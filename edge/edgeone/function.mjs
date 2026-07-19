import {
  createConfiguredTokenVerifier,
  createSowEdgeHandler,
  createStaticEnvironmentVerifier,
  readEdgeRuntimeConfiguration,
	sha256Hex,
	SnapshotRouteAbsentError,
} from "../shared/contract.mjs";
import {
  normalizeOriginCacheStatus,
	originCacheFreshnessEvidence,
  privateOriginError,
  privateOriginURL,
  validatePrivateOriginKey,
} from "../shared/private-origin.mjs";

const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

export function createEdgeOneHandler(environment, platform = globalThis) {
  const runtime = readEdgeRuntimeConfiguration(environment);
  const verifier = createStaticEnvironmentVerifier(environment);
  const verifyToken = createConfiguredTokenVerifier(environment, {
	providerTransport: "https",
	fetch: platform.fetch,
  });
  const origin = createEdgeOneOriginFetcher(environment, platform, runtime);
  const fetchOrigin = origin.fetch;
  return createSowEdgeHandler({
    verifyToken,
    verifyBasic: verifier.verifyBasic,
    fetchOrigin,
    readChannel: createChannelReader(fetchOrigin),
	readSnapshot: createSnapshotReader(fetchOrigin),
    publicBaseURL: runtime.publicBaseURL,
		betaBaseURL: runtime.betaBaseURL,
		publicPrefixes: runtime.publicPrefixes,
		publicKeys: runtime.publicKeys,
		compatibility: runtime.compatibility,
		originTransport: origin.transport,
  });
}

function createEdgeOneOriginFetcher(environment, platform, runtime) {
  switch (environment?.SOW_ORIGIN_MODE) {
    case "cos-sigv4":
      return { transport: "cos-sigv4", fetch: createCOSOriginFetcher(environment, platform) };
    case "https-bearer":
      return { transport: "https-bearer", fetch: createHTTPSBearerOriginFetcher(environment, platform, runtime) };
    default:
      throw new TypeError("SOW_ORIGIN_MODE must be cos-sigv4 or https-bearer on EdgeOne");
  }
}

function createSnapshotReader(fetchOrigin) {
	return async (snapshot) => {
		const response = await fetchOrigin({ method: "GET", keys: [`.sow/snapshots/${snapshot}.json`], headers: new Headers({ Accept: "application/json" }), originView: "stable" });
		if (response.status === 404 || response.status === 410) throw new SnapshotRouteAbsentError(response.status);
		if (response.status !== 200) throw new Error("snapshot unavailable");
		const body = await response.text();
		if (body.length > 64 * 1024) throw new Error("snapshot document too large");
		return JSON.parse(body);
	};
}

function createCOSOriginFetcher(environment, platform) {
  const fetchFunction = platform?.fetch;
  if (typeof fetchFunction !== "function") {
    throw new TypeError("EdgeOne Fetch API is required");
  }
  const cryptoAPI = platform?.crypto || globalThis.crypto;
  if (!cryptoAPI?.subtle || typeof cryptoAPI.subtle.digest !== "function" || typeof cryptoAPI.subtle.importKey !== "function" || typeof cryptoAPI.subtle.sign !== "function") {
    throw new TypeError("EdgeOne Web Crypto API is required for COS SigV4");
  }
  const configuration = readCOSConfiguration(environment);
  const now = typeof platform?.now === "function" ? platform.now : () => new Date();
  return async ({ method, keys, headers }) => {
    let response;
    for (const key of keys) {
      response = await fetchSignedCOSObject(fetchFunction, cryptoAPI, now, configuration, method, key, headers);
      if (response.status !== 404) {
        return response;
      }
    }
    return response || privateOriginError(404, "not_found");
  };
}

function createHTTPSBearerOriginFetcher(environment, platform, runtime) {
  if (typeof platform?.fetch !== "function") throw new TypeError("EdgeOne Fetch API is required");
  const bases = readHTTPSBearerBases(environment, runtime, "EdgeOne");
  const bearer = environment?.SOW_ORIGIN_BEARER;
  if (typeof bearer !== "string" || !/^[\x21-\x7e]{16,4096}$/.test(bearer)) {
    throw new TypeError("SOW_ORIGIN_BEARER platform secret is invalid");
  }
  return async ({ method, keys, headers, originView }) => {
    const base = selectHTTPSBearerBase(keys, bases, originView);
    let response;
    for (const key of keys) {
      const cleanURL = privateOriginURL(base, key);
      const cleanHeaders = new Headers(headers);
      cleanHeaders.set("Authorization", `Bearer ${bearer}`);
      const origin = await platform.fetch(new Request(cleanURL, { method, headers: cleanHeaders, redirect: "manual" }));
      if (origin.status >= 300 && origin.status < 400) return privateOriginError(502, "invalid_origin_redirect");
      response = await annotateOriginResponse(origin, "https-bearer", cleanURL, origin.headers.get("EO-Cache-Status"));
      if (response.status !== 404) return response;
    }
    return response || privateOriginError(404, "not_found");
  };
}

function readHTTPSBearerBases(environment, runtime, vendor) {
  const bases = {
    main: new URL(`${runtime.publicBaseURL}/`),
    beta: new URL(`${runtime.betaBaseURL}/`),
  };
  for (const [name, wanted] of [["SOW_ORIGIN_BASE_URL", bases.main], ["SOW_BETA_ORIGIN_BASE_URL", bases.beta]]) {
    const configured = environment?.[name];
    if (configured === undefined || configured === "") continue;
    let parsed;
    try {
      parsed = new URL(configured);
    } catch {
      throw new TypeError(`${vendor} ${name} must equal its declared public serving origin`);
    }
    if (parsed.href !== wanted.href) {
      throw new TypeError(`${vendor} ${name} must equal its declared public serving origin`);
    }
  }
  return bases;
}

function selectHTTPSBearerBase(keys, bases, originView) {
  if (!Array.isArray(keys) || keys.length === 0 || typeof keys[0] !== "string") {
    throw new TypeError("https-bearer origin keys are invalid");
  }
  if (!["beta", "latest", "stable"].includes(originView)) {
    throw new TypeError("https-bearer origin view is invalid");
  }
  const betaNamespace = keys[0].startsWith(".sow/beta/") || keys[0].startsWith("_sow/v1/mirrorlist/beta/");
  if (betaNamespace && originView !== "beta") {
    throw new TypeError("beta origin key escaped the beta request view");
  }
  return originView === "beta" ? bases.beta : bases.main;
}

function readCOSConfiguration(environment) {
  const region = environment?.SOW_COS_REGION;
  const bucket = environment?.SOW_COS_BUCKET;
  const secretID = environment?.SOW_COS_SECRET_ID;
  const secretKey = environment?.SOW_COS_SECRET_KEY;
  const sessionToken = environment?.SOW_COS_SESSION_TOKEN || "";
  if (typeof region !== "string" || !/^[a-z][a-z0-9-]{1,62}$/.test(region)) {
    throw new TypeError("SOW_COS_REGION is invalid");
  }
  if (typeof bucket !== "string" || bucket.length > 63 || !/^[a-z0-9][a-z0-9-]+-[1-9][0-9]{4,19}$/.test(bucket)) {
    throw new TypeError("SOW_COS_BUCKET must include the numeric app ID suffix");
  }
  if (typeof secretID !== "string" || !/^[A-Za-z0-9]{16,256}$/.test(secretID)) {
    throw new TypeError("SOW_COS_SECRET_ID platform secret is invalid");
  }
  if (typeof secretKey !== "string" || !/^[\x21-\x7e]{16,256}$/.test(secretKey)) {
    throw new TypeError("SOW_COS_SECRET_KEY platform secret is invalid");
  }
  if (typeof sessionToken !== "string" || sessionToken.length > 8192 || (sessionToken !== "" && !/^[\x21-\x7e]+$/.test(sessionToken))) {
    throw new TypeError("SOW_COS_SESSION_TOKEN platform secret is invalid");
  }
  const origin = new URL(`https://${bucket}.cos.${region}.myqcloud.com`);
  const expectedHost = `${bucket}.cos.${region}.myqcloud.com`;
  if (origin.protocol !== "https:" || origin.hostname !== expectedHost || origin.pathname !== "/" || origin.port || origin.username || origin.password) {
    throw new TypeError("derived COS origin is invalid");
  }
  return { region, bucket, secretID, secretKey, sessionToken, origin };
}

async function fetchSignedCOSObject(fetchFunction, cryptoAPI, now, configuration, method, key, sourceHeaders) {
  if (method !== "GET" && method !== "HEAD") throw new TypeError("COS origin only accepts GET and HEAD");
  validatePrivateOriginKey(key);
  const pathname = `/${key.split("/").map(awsURIEncode).join("/")}`;
  const url = new URL(pathname, configuration.origin);
  if (url.protocol !== "https:" || url.origin !== configuration.origin.origin || url.hostname !== configuration.origin.hostname || url.pathname !== pathname || url.search || url.hash || url.username || url.password) {
    throw new TypeError("COS object key escaped the vendor origin");
  }
  const timestamp = now();
  if (!(timestamp instanceof Date) || Number.isNaN(timestamp.valueOf())) throw new TypeError("COS signing clock is invalid");
  const amzDate = timestamp.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const headers = new Headers(sourceHeaders);
  headers.delete("Authorization");
  headers.delete("Cookie");
  headers.delete("Proxy-Authorization");
  headers.set("x-amz-content-sha256", EMPTY_SHA256);
  headers.set("x-amz-date", amzDate);
  if (configuration.sessionToken) headers.set("x-amz-security-token", configuration.sessionToken);
  const canonicalHeaderEntries = [["host", url.hostname], ["x-amz-content-sha256", EMPTY_SHA256], ["x-amz-date", amzDate]];
  if (configuration.sessionToken) canonicalHeaderEntries.push(["x-amz-security-token", configuration.sessionToken]);
  canonicalHeaderEntries.sort(([left], [right]) => left.localeCompare(right));
  const canonicalHeaders = canonicalHeaderEntries.map(([name, value]) => `${name}:${value.trim()}\n`).join("");
  const signedHeaders = canonicalHeaderEntries.map(([name]) => name).join(";");
  const canonicalRequest = `${method}\n${pathname}\n\n${canonicalHeaders}\n${signedHeaders}\n${EMPTY_SHA256}`;
  const scope = `${date}/${configuration.region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await digestHex(cryptoAPI, canonicalRequest)}`;
  const dateKey = await hmac(cryptoAPI, new TextEncoder().encode(`AWS4${configuration.secretKey}`), date);
  const regionKey = await hmac(cryptoAPI, dateKey, configuration.region);
  const serviceKey = await hmac(cryptoAPI, regionKey, "s3");
  const signingKey = await hmac(cryptoAPI, serviceKey, "aws4_request");
  const signature = bytesHex(await hmac(cryptoAPI, signingKey, stringToSign));
  headers.set("Authorization", `AWS4-HMAC-SHA256 Credential=${configuration.secretID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`);
  const response = await fetchFunction(new Request(url, { method, headers, redirect: "manual" }));
  if (response.status >= 300 && response.status < 400) {
    return privateOriginError(502, "invalid_origin_redirect");
  }
  return annotateOriginResponse(response, "cos-sigv4", url, "BYPASS");
}

async function annotateOriginResponse(response, transport, cleanURL, cacheStatus) {
  if (!(response instanceof Response)) return privateOriginError(503, "temporarily_unavailable");
  const headers = new Headers(response.headers);
  headers.set("X-SOW-Origin-Transport", transport);
	headers.set("X-SOW-Origin-Cache-Status", normalizeOriginCacheStatus(cacheStatus));
	headers.set("X-SOW-Clean-URL-SHA256", await sha256Hex(cleanURL.href));
	const freshness = originCacheFreshnessEvidence(response.headers);
	if (freshness) {
		headers.set("X-SOW-Origin-Cache-Age", String(freshness.age));
		headers.set("X-SOW-Origin-Cache-Max-Age", String(freshness.maxAge));
	}
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function awsURIEncode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

async function digestHex(cryptoAPI, value) {
  const digest = await cryptoAPI.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesHex(new Uint8Array(digest));
}

async function hmac(cryptoAPI, rawKey, value) {
  const key = await cryptoAPI.subtle.importKey("raw", rawKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await cryptoAPI.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return new Uint8Array(signature);
}

function bytesHex(value) {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function createChannelReader(fetchOrigin) {
  return async ({ view, repo, os, arch }) => {
    const response = await fetchOrigin({
      method: "GET",
      keys: [`.sow/channels/${view}/${repo}/${os}/${arch}.json`],
      headers: new Headers({ Accept: "application/json" }),
	  originView: view === "beta" ? "beta" : "stable",
    });
    if (response.status !== 200) {
      throw new Error("channel unavailable");
    }
    const body = await response.text();
    if (body.length > 64 * 1024) {
      throw new Error("channel document too large");
    }
    return JSON.parse(body);
  };
}
