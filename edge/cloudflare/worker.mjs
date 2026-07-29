import {
  createConfiguredTokenVerifier,
  createSowEdgeHandler,
  createStaticEnvironmentVerifier,
  readEdgeRuntimeConfiguration,
	sha256Hex,
	SnapshotRouteAbsentError,
} from "../shared/contract.mjs";
import {
  PRIVATE_ORIGIN_SERVICE_ORIGIN,
  normalizeOriginCacheStatus,
	originCacheFreshnessEvidence,
  privateOriginError,
  privateOriginURL,
} from "../shared/private-origin.mjs";

const CLOUDFLARE_RAY_PATTERN = /^[0-9a-f]{16,32}-[A-Z]{3}$/i;
const LOWER_SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PROVIDER_PROBE_PATTERN = /^[A-Za-z0-9_-]{22,64}$/;
const OBSERVABLE_CACHE_STATUSES = new Set(["HIT", "MISS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED"]);

export function createCloudflareHandler(environment, platform = globalThis) {
  const runtime = readEdgeRuntimeConfiguration(environment);
  const staticVerifier = createStaticEnvironmentVerifier(environment);
  const verifyToken = createConfiguredTokenVerifier(environment, { providerTransport: "service" });
  const origin = createCloudflareOriginFetcher(environment, platform, runtime);
  const fetchOrigin = origin.fetch;
  const dependencies = {
    verifyToken,
    verifyBasic: staticVerifier.verifyBasic,
    fetchOrigin,
    readChannel: createChannelReader(fetchOrigin),
	readSnapshot: createSnapshotReader(fetchOrigin),
    publicBaseURL: runtime.publicBaseURL,
		betaBaseURL: runtime.betaBaseURL,
		publicPrefixes: runtime.publicPrefixes,
		publicKeys: runtime.publicKeys,
		compatibility: runtime.compatibility,
		originTransport: origin.transport,
  };
  const handler = createSowEdgeHandler(dependencies);
  return async (request) => {
    const response = await handler(request);
    emitCloudflareProviderEvent(request, response, platform);
    return response;
  };
}

// Workers Trace Events Logpush is available on Workers Paid while zone HTTP
// request logs require Enterprise. Emit one bounded, secret-free record that a
// deployed-bundle attestation can join to the client-visible CF-Ray. The raw
// URL and credential are deliberately absent; only the clean origin digest is
// recorded.
function emitCloudflareProviderEvent(request, response, platform) {
  try {
    if (!(request instanceof Request) || !(response instanceof Response)) return;
    if (response.headers.get("X-SOW-Origin-Transport") !== "https-bearer") return;
    const probeID = request.headers.get("X-SOW-Provider-Probe") || "";
    if (!PROVIDER_PROBE_PATTERN.test(probeID)) return;
    const requestID = request.headers.get("CF-Ray") || "";
    const colo = typeof request.cf?.colo === "string" ? request.cf.colo.trim().toUpperCase() : "";
    if (!CLOUDFLARE_RAY_PATTERN.test(requestID) || requestID.slice(-3).toUpperCase() !== colo) return;
    const requestIDBase = requestID.slice(0, -4).toLowerCase();
    const cleanURLSHA256 = response.headers.get("X-SOW-Clean-URL-SHA256") || "";
    const cacheStatus = response.headers.get("X-SOW-Origin-Cache-Status") || "";
    if (!LOWER_SHA256_PATTERN.test(cleanURLSHA256) || !OBSERVABLE_CACHE_STATUSES.has(cacheStatus)) return;
    const age = boundedHeaderInteger(response.headers.get("X-SOW-Origin-Cache-Age"));
    const maxAge = boundedHeaderInteger(response.headers.get("X-SOW-Origin-Cache-Max-Age"));
    if ((age === -1) !== (maxAge === -1) || age >= 0 && (maxAge <= age || maxAge > 315360000)) return;
    const logger = platform?.console?.log;
    if (typeof logger !== "function") return;
    logger.call(platform.console, JSON.stringify({
      schema: "sow-cloudflare-edge-provider-log/v1",
      probe_id: probeID,
      request_id: requestIDBase,
      provider_request_id: `trace-${requestIDBase}`,
      colo,
      clean_url_sha256: cleanURLSHA256,
      cache_status: cacheStatus,
      cache_age_seconds: age,
      cache_max_age_seconds: maxAge,
      status: response.status,
    }));
  } catch {
    // Provider evidence must never change request behavior.
  }
}

function boundedHeaderInteger(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,8})$/.test(value)) return -1;
  return Number(value);
}

function createCloudflareOriginFetcher(environment, platform, runtime) {
  switch (environment?.SOW_ORIGIN_MODE) {
    case "r2-service":
      return { transport: "r2-service", fetch: createServiceOriginFetcher(environment) };
    case "https-bearer":
      return { transport: "https-bearer", fetch: createHTTPSBearerOriginFetcher(environment, platform, runtime) };
    default:
      throw new TypeError("SOW_ORIGIN_MODE must be r2-service or https-bearer on Cloudflare");
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

function createServiceOriginFetcher(environment) {
  if (!environment?.ORIGIN || typeof environment.ORIGIN.fetch !== "function") {
    throw new TypeError("Cloudflare ORIGIN service binding is required");
  }
  return async ({ method, keys, headers }) => {
    let response;
    for (const key of keys) {
      const cleanURL = privateOriginURL(PRIVATE_ORIGIN_SERVICE_ORIGIN, key);
      const request = new Request(cleanURL, { method, headers, redirect: "manual" });
      response = await annotateOriginResponse(await environment.ORIGIN.fetch(request), "r2-service", cleanURL, "BYPASS");
      if (response.status !== 404) {
        return response;
      }
    }
    return response || privateOriginError(404, "not_found");
  };
}

function createHTTPSBearerOriginFetcher(environment, platform, runtime) {
  if (typeof platform?.fetch !== "function") throw new TypeError("Cloudflare global Fetch API is required");
  const bases = readHTTPSBearerBases(environment, runtime, "Cloudflare");
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
      response = await annotateOriginResponse(origin, "https-bearer", cleanURL, origin.headers.get("CF-Cache-Status"));
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

export default {
  async fetch(request, environment) {
    try {
      return await createCloudflareHandler(environment)(request);
    } catch {
      return new Response("temporarily_unavailable\n", {
        status: 503,
        headers: { "Cache-Control": "private, no-store, max-age=0", "X-SOW-Edge-Contract": "sow-edge-runtime/v1" },
      });
    }
  },
};
