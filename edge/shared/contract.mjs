const TOKEN_PATTERN = /^[A-Za-z0-9_-]{22,256}$/;
const SAFE_SEGMENT = /^[A-Za-z0-9+._~^:-]+$/;
const GENERATION_PATTERN = /^[0-9]{20}$/;
const SNAPSHOT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9+._-]*-[0-9]{8}$/;
const ENVIRONMENT_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;
const PROVIDER_ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;

export const EDGE_RUNTIME_SCHEMA = "sow-edge-runtime/v2";
export const EDGE_PRO_PREFIX = "/pro/v1/{token}/";

export class SnapshotRouteAbsentError extends Error {
	constructor(status) {
		super("snapshot route is absent");
		this.name = "SnapshotRouteAbsentError";
		this.status = status === 410 ? 410 : 404;
	}
}

export function createSowEdgeHandler(dependencies) {
  validateDependencies(dependencies);
  return async function handleSowEdgeRequest(request) {
    try {
      return await handleRequest(request, dependencies);
    } catch {
      return privateError(503, "temporarily_unavailable");
    }
  };
}

async function handleRequest(request, dependencies) {
  if (!(request instanceof Request)) {
    return privateError(503, "temporarily_unavailable");
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    const response = privateError(405, "method_not_allowed");
    response.headers.set("Allow", "GET, HEAD");
    return response;
  }
  const parsed = parseStrictRequestURL(request.url);
  if (!parsed) {
    return privateError(404, "not_found");
  }

  const authorization = await authorize(parsed.segments, request, dependencies);
  if (authorization.response) {
    return authorization.response;
  }
  const { access, credentialSegment, cleanSegments } = authorization;
	const publicView = resolvePublicView(request.url, dependencies.betaBaseURL);
  if (cleanSegments.length === 0 || cleanSegments[0] === ".sow" || cleanSegments[0] === ".pool" || cleanSegments[0] === ".git") {
    return privateError(404, "not_found");
  }
	if (!isAllowedRequestPath(cleanSegments, dependencies)) {
		return privateError(404, "not_found");
	}

  if (isMirrorlist(cleanSegments)) {
	return renderMirrorlist(request, cleanSegments, access, credentialSegment, publicView, dependencies);
  }

	if (isSnapshotRoute(cleanSegments)) {
		if (access !== "pro") {
			return authError(403);
		}
		const snapshot = cleanSegments[3];
		let pointer;
		try {
			pointer = await dependencies.readSnapshot(snapshot);
		} catch (error) {
			if (error instanceof SnapshotRouteAbsentError) {
				return privateError(error.status, "not_found");
			}
			return privateError(503, "temporarily_unavailable");
		}
		const generation = normalizeGeneration(pointer?.generation);
		if (pointer?.schema !== "sow-snapshot-route/v1" || pointer?.snapshot !== snapshot || !generation) {
			return privateError(503, "temporarily_unavailable");
		}
		const route = routeSnapshot(cleanSegments, snapshot, generation);
		if (!route) {
			return privateError(404, "not_found");
		}
		return fetchRoutedOrigin(request, route, access, dependencies, "stable");
	}

	const route = routeOriginKeys(cleanSegments, access, publicView);
  if (!route) {
    return privateError(404, "not_found");
  }
  return fetchRoutedOrigin(request, route, access, dependencies, publicView);
}

async function fetchRoutedOrigin(request, route, access, dependencies, publicView) {
  const originHeaders = cleanOriginHeaders(request.headers);
  let originResponse;
  try {
    originResponse = await dependencies.fetchOrigin({
      method: request.method,
      keys: route.keys,
      headers: originHeaders,
	  originView: access === "public" ? publicView : "stable",
    });
  } catch {
    return privateError(503, "temporarily_unavailable");
  }
  if (!(originResponse instanceof Response)) {
    return privateError(503, "temporarily_unavailable");
  }
  return clientResponse(originResponse, access, request.method);
}

function isSnapshotRoute(segments) {
	return segments.length >= 5 && segments[0] === "_sow" && segments[1] === "v1" && segments[2] === "snapshots" && SNAPSHOT_PATTERN.test(segments[3]);
}

// The public edge is a closed projection of the repository configuration, not
// a generic object-store proxy. Ordinary paths must sit below one configured
// repository prefix or equal one explicitly published key. The _sow namespace
// is also closed to the protocol routes implemented below plus exact publicKeys
// (for example immutable compatibility trust packets); this prevents an
// unknown control object from becoming public merely because its key is URL
// safe. Exact keys are checked before the namespace gate, never as prefixes.
// The same boundary applies after Pro authentication so an entitlement cannot
// be used to enumerate arbitrary root objects.
function isAllowedRequestPath(segments, dependencies) {
	const cleanPath = segments.join("/");
	if (dependencies.publicKeys.includes(cleanPath)) return true;
	if (segments[0] === "_sow") {
		if (isMirrorlist(segments)) {
			return expectedMirrorlistRoot(
				segments[3], segments[4], segments[5], segments[6].slice(0, -4), dependencies.compatibility,
			) !== null;
		}
		if (isSnapshotRoute(segments)) return isAllowedSnapshotRequest(segments, dependencies.compatibility);
		const aptGeneration = routeAPTGeneration(segments, "public");
		if (aptGeneration !== null) return dependencies.compatibility.aptRoots.has(aptGeneration.legacyRoot);
		const generation = routeGeneration(segments, "public");
		if (generation === null) return false;
		const compatibilityID = dependencies.compatibility.byRoot.get(generation.legacyRoot);
		return compatibilityID === undefined
			? dependencies.compatibility.yumRoots.has(generation.legacyRoot)
			: dependencies.compatibility.active.has(compatibilityID);
	}
	return dependencies.publicPrefixes.some((prefix) => cleanPath === prefix || cleanPath.startsWith(`${prefix}/`));
}

function channelKey(view, repo, os, arch) {
	return `${view}\0${repo}\0${os}\0${arch}`;
}

function expectedMirrorlistRoot(view, repo, os, arch, compatibility) {
	const projection = compatibility.byID.get(repo);
	if (projection !== undefined) {
		return compatibility.active.has(repo) && projection.view === view && projection.os === os && projection.arch === arch
			? projection.root
			: null;
	}
	return compatibility.yumChannels.get(channelKey(view, repo, os, arch)) ?? null;
}

function isAllowedSnapshotRequest(segments, compatibility) {
	const parsed = parseSnapshotRoute(segments);
	if (parsed === null) return false;
	const snapshot = compatibility.snapshots.get(segments[3]);
	if (snapshot === undefined) return false;
	if (parsed.kind === "control") return true;
	if (parsed.kind === "apt") return snapshot.aptRoots.has(parsed.legacyRoot);
	if (parsed.kind === "yum") return snapshot.yumRoots.has(parsed.legacyRoot);
	return snapshot.assetKeys.has(parsed.assetPath) || [...snapshot.assetRoots].some((root) => parsed.assetPath === root || parsed.assetPath.startsWith(`${root}/`));
}

function routeSnapshot(segments, snapshot, generation) {
	const parsed = parseSnapshotRoute(segments);
	if (parsed === null) return null;
	if (parsed.kind === "control") {
		return { keys: [`.sow/snapshots/${snapshot}.json`] };
	}
	if (parsed.kind === "apt") {
		if (parsed.payloadKind === "pool") {
			return { keys: [`.sow/gated/${parsed.legacyPath}`, parsed.legacyPath] };
		}
		return { keys: [`.sow/gated/generations/${generation}/apt/${parsed.legacyPath}`] };
	}
	if (parsed.kind === "yum") {
		if (parsed.payloadKind === "repodata") {
			return { keys: [`.sow/gated/generations/${generation}/yum/${parsed.legacyRoot}/${parsed.payload}`] };
		}
		return { keys: [`.sow/gated/snapshots/${snapshot}/yum/${parsed.legacyRoot}/${parsed.payload}`] };
	}
	return { keys: [`.sow/gated/snapshots/${snapshot}/asset/${parsed.assetPath}`] };
}

function parseSnapshotRoute(segments) {
	if (segments[4] === "_route.json" && segments.length === 5) return { kind: "control" };
	const kind = segments[4];
	const repositorySegments = segments.slice(5);
	if (repositorySegments.length === 0 || repositorySegments.some((segment) => !SAFE_SEGMENT.test(segment))) return null;
	if (kind === "apt") {
		const payloadIndex = repositorySegments.findIndex((segment) => segment === "dists" || segment === "pool");
		if (payloadIndex < 1 || repositorySegments.length < payloadIndex + 3) return null;
		return {
			kind,
			legacyRoot: repositorySegments.slice(0, payloadIndex).join("/"),
			legacyPath: repositorySegments.join("/"),
			payloadKind: repositorySegments[payloadIndex],
		};
	}
	if (kind === "yum") {
		const payloadIndex = repositorySegments.findIndex((segment) => segment === "repodata" || segment === "Packages");
		if (payloadIndex < 2) return null;
		const payloadSegments = repositorySegments.slice(payloadIndex);
		if (payloadSegments[0] === "repodata") {
			if (payloadSegments.length !== 2) return null;
		} else if (payloadSegments.length !== 3 || !/^[a-z0-9_]$/.test(payloadSegments[1]) || !/^[A-Za-z0-9][A-Za-z0-9+._~^-]*\.rpm$/.test(payloadSegments[2])) {
			return null;
		}
		return {
			kind,
			legacyRoot: repositorySegments.slice(0, payloadIndex).join("/"),
			payload: payloadSegments.join("/"),
			payloadKind: payloadSegments[0],
		};
	}
	if (kind === "assets") return { kind, assetPath: repositorySegments.join("/") };
	return null;
}

async function authorize(segments, request, dependencies) {
  if (segments[0] !== "pro") {
    return { access: "public", credentialSegment: "", cleanSegments: segments };
  }
  if (segments.length < 4 || segments[1] !== "v1") {
    return { response: privateError(404, "not_found") };
  }
  const credentialSegment = segments[2];
  const cleanSegments = segments.slice(3);
  let verification;
  try {
    if (credentialSegment === "basic") {
      const basic = parseBasicAuthorization(request.headers.get("Authorization"));
      if (!basic || typeof dependencies.verifyBasic !== "function") {
        return { response: authError(401) };
      }
      verification = await dependencies.verifyBasic(basic, authorizationContext(request, cleanSegments));
    } else {
      if (!TOKEN_PATTERN.test(credentialSegment)) {
        return { response: authError(401) };
      }
      verification = await dependencies.verifyToken(credentialSegment, authorizationContext(request, cleanSegments));
    }
  } catch {
    return { response: privateError(503, "temporarily_unavailable") };
  }
  switch (verification?.status) {
    case "ok":
      return { access: "pro", credentialSegment, cleanSegments };
    case "forbidden":
      return { response: authError(403) };
    case "unavailable":
      return { response: privateError(503, "temporarily_unavailable") };
    default:
      return { response: authError(401) };
  }
}

function authorizationContext(request, cleanSegments) {
  const url = new URL(request.url);
  return {
    audience: url.hostname.toLowerCase(),
    path: `/${cleanSegments.join("/")}`,
  };
}

function parseStrictRequestURL(rawURL) {
  if (typeof rawURL !== "string" || rawURL.length > 8192) {
    return null;
  }
  const match = rawURL.match(/^https:\/\/[^/?#]+([^?#]*)(\?[^#]*)?(#.*)?$/);
  if (!match || match[2] || match[3]) {
    return null;
  }
  const rawPath = match[1] || "/";
  if (!rawPath.startsWith("/") || rawPath.includes("//") ||
      (rawPath.length > 1 && rawPath.endsWith("/")) ||
      rawPath.includes("\\") || rawPath.includes("\0")) {
    return null;
  }
  const segments = [];
  const rawSegments = rawPath === "/" ? [] : rawPath.slice(1).split("/");
  for (const rawSegment of rawSegments) {
    const segment = decodeCanonicalPathSegment(rawSegment);
    if (segment === null) {
      return null;
    }
    segments.push(segment);
  }
  return { segments };
}

// WHATWG URL serializers and RFC 3986 normalizers must encode caret in a path
// as %5E, while RPM versions may legitimately contain caret. Accept exactly
// that one canonical wire representation and immediately recover the object-key
// byte. Re-encoding the decoded segment proves there is only one spelling:
// lowercase hex, encoded unreserved bytes, encoded separators, double encoding,
// a trailing empty segment, and a raw caret are all rejected rather than
// becoming cache-key aliases.
function decodeCanonicalPathSegment(rawSegment) {
  const decoded = rawSegment.replace(/%5E/g, "^");
  if (decoded.includes("%") || decoded.replace(/\^/g, "%5E") !== rawSegment ||
      decoded === "." || decoded === ".." || !SAFE_SEGMENT.test(decoded)) {
    return null;
  }
  return decoded;
}

// Serialize a clean object-key path for a client-facing URL without widening
// the accepted alphabet. Caret is the only literal key byte in SAFE_SEGMENT
// that the WHATWG path serializer must percent-encode; every other byte stays
// byte-identical. Returning null keeps derived URLs fail-closed if an internal
// caller ever supplies a non-canonical segment.
function encodeCanonicalClientPath(segments, trailingSlash = false) {
  if (!Array.isArray(segments) || segments.length === 0 ||
      segments.some((segment) => typeof segment !== "string" || segment === "." ||
        segment === ".." || !SAFE_SEGMENT.test(segment))) {
    return null;
  }
  const path = `/${segments.map((segment) => segment.replace(/\^/g, "%5E")).join("/")}`;
  return trailingSlash ? `${path}/` : path;
}

function isMirrorlist(segments) {
  return segments.length === 7 && segments[0] === "_sow" && segments[1] === "v1" && segments[2] === "mirrorlist" && segments[6].endsWith(".txt");
}

async function renderMirrorlist(request, segments, access, credentialSegment, publicView, dependencies) {
  const view = segments[3];
  const repo = segments[4];
  const os = segments[5];
  const arch = segments[6].slice(0, -4);
  if (![view, repo, os, arch].every((value) => value && SAFE_SEGMENT.test(value))) {
    return privateError(404, "not_found");
  }
	const expectedLegacyRoot = expectedMirrorlistRoot(view, repo, os, arch, dependencies.compatibility);
	if (expectedLegacyRoot === null) {
		return privateError(404, "not_found");
	}
  if (access === "public" && view !== "latest" && view !== "beta") {
	return authError(403);
  }
	if (access === "public" && view !== publicView) {
	return privateError(404, "not_found");
	}
	if (access === "public") {
		// OSS mirrorlists are ordinary published objects. The edge must not read a
		// control pointer or synthesize their body; direct CDN/Nginx hosting keeps
		// working when edge compute is disabled.
		return fetchRoutedOrigin(request, { keys: [segments.join("/")] }, access, dependencies, publicView);
	}
  let channel;
  try {
    channel = await dependencies.readChannel({ view, repo, os, arch, access });
  } catch {
    return privateError(503, "temporarily_unavailable");
  }
  const generation = normalizeGeneration(channel?.generation);
  const legacyRoot = normalizeLegacyRoot(channel?.legacy_root);
  if (!generation || !legacyRoot || legacyRoot !== expectedLegacyRoot) {
    return privateError(503, "temporarily_unavailable");
  }
  const requestOrigin = new URL(request.url).origin;
	const baseOrigin = access === "public" && publicView === "beta"
		? new URL(dependencies.betaBaseURL).origin
		: (dependencies.publicBaseURL || requestOrigin);
  const routeSegments = [];
  if (access === "pro") {
    routeSegments.push("pro", "v1", credentialSegment);
  }
  routeSegments.push("_sow", "v1", "g", generation, ...legacyRoot.split("/"));
  const clientPath = encodeCanonicalClientPath(routeSegments, true);
  if (clientPath === null) {
    return privateError(503, "temporarily_unavailable");
  }
  const clientURL = new URL(clientPath, baseOrigin);
  if (clientURL.origin !== baseOrigin || clientURL.pathname !== clientPath || clientURL.search || clientURL.hash) {
    return privateError(503, "temporarily_unavailable");
  }
  const body = `${clientURL.href}\n`;
  const headers = new Headers({
    "Content-Type": "text/plain; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "X-SOW-Edge-Contract": EDGE_RUNTIME_SCHEMA,
  });
  if (dependencies.originTransport) headers.set("X-SOW-Origin-Transport", dependencies.originTransport);
  if (access === "pro") {
    headers.set("Cache-Control", "private, no-store, max-age=0");
  } else {
    headers.set("Cache-Control", "public, max-age=30, must-revalidate");
  }
  return new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
}

function routeOriginKeys(segments, access, publicView) {
	if (segments[0] === "_sow" && segments[1] === "v1" && segments[2] === "a") {
		return routeAPTGeneration(segments, access);
	}
  if (segments[0] === "_sow" && segments[1] === "v1" && segments[2] === "g") {
	return routeGeneration(segments, access);
  }
  const cleanPath = segments.join("/");
  if (access === "public") {
	if (publicView === "beta") {
	  const keys = [`.sow/beta/${cleanPath}`];
	  // The publisher intentionally stores only immutable APT/YUM package
	  // payloads at their shared legacy key. Every other beta object is
	  // view-specific: falling through to the latest key would resurrect a
	  // deleted beta asset or index from another public view.
	  if (isSharedImmutablePackagePayload(segments)) keys.push(cleanPath);
	  return { keys };
	}
	return { keys: [cleanPath] };
  }
  return {
    keys: [`.sow/gated/${cleanPath}`, cleanPath],
  };
}

function isSharedImmutablePackagePayload(segments) {
	if (segments[0] === "apt") {
		const poolIndex = segments.lastIndexOf("pool");
		if (poolIndex < 1 || segments.length !== poolIndex + 5) return false;
		const [component, prefix, source, filename] = segments.slice(poolIndex + 1);
		if (!/^[a-z0-9][a-z0-9+.-]*$/.test(component) || !/^[a-z0-9][a-z0-9+.-]*$/.test(source)) return false;
		const expectedPrefix = source.startsWith("lib") ? source.slice(0, Math.min(4, source.length)) : source.slice(0, 1);
		return prefix === expectedPrefix && /^[A-Za-z0-9][A-Za-z0-9+._:~-]*\.deb$/.test(filename);
	}
	if (segments[0] === "yum") {
		const packagesIndex = segments.lastIndexOf("Packages");
		if (packagesIndex < 1 || segments.length !== packagesIndex + 3) return false;
		const [bucket, filename] = segments.slice(packagesIndex + 1);
		return /^[a-z0-9_]$/.test(bucket) && /^[A-Za-z0-9][A-Za-z0-9+._~^-]*\.rpm$/.test(filename);
	}
	return false;
}

function routeAPTGeneration(segments, access) {
	if (segments.length < 7 || segments[0] !== "_sow" || segments[1] !== "v1" || segments[2] !== "a" || !GENERATION_PATTERN.test(segments[3])) {
		return null;
	}
	const generation = segments[3];
	const legacySegments = segments.slice(4);
	const payloadIndex = legacySegments.indexOf("dists");
	if (payloadIndex < 1 || legacySegments.length < payloadIndex + 3 || legacySegments.some((segment) => !SAFE_SEGMENT.test(segment))) {
		return null;
	}
	const legacyRoot = legacySegments.slice(0, payloadIndex).join("/");
	const legacyPath = legacySegments.join("/");
	const generationPath = `generations/${generation}/apt/${legacyPath}`;
	const key = access === "public" ? `.sow/${generationPath}` : `.sow/gated/${generationPath}`;
	return { keys: [key], legacyRoot };
}

function resolvePublicView(requestURL, betaBaseURL) {
	if (typeof betaBaseURL !== "string" || betaBaseURL === "") {
		return "latest";
	}
	try {
		const request = new URL(requestURL);
		const beta = new URL(betaBaseURL);
		if (beta.protocol === "https:" && beta.pathname === "/" && !beta.search && !beta.hash && request.origin === beta.origin) {
			return "beta";
		}
	} catch {
		return "latest";
	}
	return "latest";
}

function routeGeneration(segments, access) {
  if (segments.length < 7 || !GENERATION_PATTERN.test(segments[3])) {
    return null;
  }
  const payloadIndex = segments.findIndex((segment, index) => index >= 5 && (segment === "repodata" || segment === "Packages"));
  if (payloadIndex < 6) {
    return null;
  }
  const generation = segments[3];
  const legacyRootSegments = segments.slice(4, payloadIndex);
  const payloadSegments = segments.slice(payloadIndex);
  if (legacyRootSegments.length < 2 || payloadSegments.length < 2) {
    return null;
  }
  const legacyRoot = legacyRootSegments.join("/");
  const payload = payloadSegments.join("/");
  if (payloadSegments[0] === "repodata") {
	if (payloadSegments.length !== 2) return null;
	const generationPath = `generations/${generation}/yum/${legacyRoot}/${payload}`;
    return access === "public"
	      ? { keys: [`.sow/${generationPath}`], legacyRoot }
	      : { keys: [`.sow/gated/${generationPath}`], legacyRoot };
  }
	if (payloadSegments.length !== 3 || !/^[a-z0-9_]$/.test(payloadSegments[1]) || !/^[A-Za-z0-9][A-Za-z0-9+._~^-]*\.rpm$/.test(payloadSegments[2])) {
		return null;
	}
  const packagePath = `${legacyRoot}/${payload}`;
  return access === "public"
	    ? { keys: [packagePath], legacyRoot }
	    : { keys: [`.sow/gated/${packagePath}`, packagePath], legacyRoot };
}

function normalizeGeneration(value) {
  const text = typeof value === "number" ? String(value) : value;
  if (typeof text !== "string" || !/^[0-9]{1,20}$/.test(text)) {
    return null;
  }
  const normalized = text.replace(/^0+(?=\d)/, "").padStart(20, "0");
  return GENERATION_PATTERN.test(normalized) ? normalized : null;
}

function normalizeLegacyRoot(value) {
  if (typeof value !== "string" || value.startsWith("/") || value.endsWith("/") || value.includes("//") || value.includes("%") || value.includes("\\")) {
    return null;
  }
  const segments = value.split("/");
  if (segments.length < 2 || segments.some((segment) => !SAFE_SEGMENT.test(segment) || segment === "." || segment === "..")) {
    return null;
  }
  return segments.join("/");
}

function cleanOriginHeaders(headers) {
  const result = new Headers();
  for (const name of ["Range", "If-Range", "If-Match", "If-Unmodified-Since", "If-None-Match", "If-Modified-Since", "Accept-Encoding"]) {
    const value = headers.get(name);
    if (value !== null) {
      result.set(name, value);
    }
  }
  return result;
}

function clientResponse(response, access, method) {
  const headers = sanitizedResponseHeaders(response.headers);
  headers.set("X-SOW-Edge-Contract", EDGE_RUNTIME_SCHEMA);
  if (access === "pro") {
    headers.set("Cache-Control", "private, no-store, max-age=0");
  }
  const body = method === "HEAD" ? null : response.body;
  return new Response(body, { status: response.status, statusText: response.statusText, headers });
}

function sanitizedResponseHeaders(source) {
  const headers = new Headers(source);
  headers.delete("Set-Cookie");
  headers.delete("Server");
  headers.delete("Authorization");
  headers.delete("Proxy-Authorization");
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-amz-") || name.toLowerCase().startsWith("x-cos-")) {
      headers.delete(name);
    }
  }
  headers.set("X-Content-Type-Options", "nosniff");
  return headers;
}

function parseBasicAuthorization(value) {
  if (typeof value !== "string" || !value.startsWith("Basic ")) {
    return null;
  }
  try {
    const decoded = atob(value.slice(6));
    const separator = decoded.indexOf(":");
    if (separator <= 0 || decoded.length > 1024) {
      return null;
    }
    if ([...decoded].some((character) => character.charCodeAt(0) > 0x7f || character === "\0")) {
      return null;
    }
    return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1), encoded: decoded };
  } catch {
    return null;
  }
}

function authError(status) {
  const response = privateError(status, status === 403 ? "forbidden" : "unauthorized");
  if (status === 401) {
    response.headers.set("WWW-Authenticate", 'Basic realm="Pigsty Pro", charset="UTF-8"');
  }
  return response;
}

function privateError(status, code) {
  return new Response(`${code}\n`, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "private, no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
      "X-SOW-Edge-Contract": EDGE_RUNTIME_SCHEMA,
    },
  });
}

function validateDependencies(dependencies) {
  if (!dependencies || typeof dependencies.verifyToken !== "function" || typeof dependencies.fetchOrigin !== "function" || typeof dependencies.readChannel !== "function") {
    throw new TypeError("incomplete SOW edge dependencies");
  }
	dependencies.publicPrefixes = validateRouteAllowlist("publicPrefixes", dependencies.publicPrefixes, false);
	dependencies.publicKeys = validateRouteAllowlist("publicKeys", dependencies.publicKeys, true);
	dependencies.compatibility = validateCompatibilityAdmission(dependencies.compatibility ?? {
		apt_roots: [], yum_repos: [], yum_roots: [], yum_channels: [], asset_roots: [], asset_keys: [], projections: [], snapshots: [], raw: [], active: [],
	}, dependencies.publicPrefixes, dependencies.publicKeys);
  if (dependencies.publicBaseURL) {
    const parsed = new URL(dependencies.publicBaseURL);
    if (parsed.protocol !== "https:" || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      throw new TypeError("publicBaseURL must be an HTTPS origin");
    }
    dependencies.publicBaseURL = parsed.origin;
  }
  if (dependencies.originTransport !== undefined && !["r2-service", "cos-sigv4", "https-bearer"].includes(dependencies.originTransport)) {
    throw new TypeError("originTransport is not a closed deployment mode");
  }
}

function validateCompatibilityAdmission(value, publicPrefixes, publicKeys) {
	if (!value || !Array.isArray(value.apt_roots) || !Array.isArray(value.yum_repos) || !Array.isArray(value.yum_roots) ||
		!Array.isArray(value.yum_channels) || !Array.isArray(value.asset_roots) || !Array.isArray(value.asset_keys) ||
		!Array.isArray(value.projections) || !Array.isArray(value.snapshots) || !Array.isArray(value.raw) || !Array.isArray(value.active)) {
		throw new TypeError("compatibility admission is incomplete");
	}
	const parseSortedIDs = (name, values) => {
		const result = new Set();
		let prior = "";
		for (const item of values) {
			if (typeof item !== "string" || item <= prior) throw new TypeError(`${name} must be unique and sorted`);
			if (!SAFE_SEGMENT.test(item)) throw new TypeError(`${name} contains an invalid ID`);
			result.add(item);
			prior = item;
		}
		return result;
	};
	const parseSortedRoutes = (name, values, exact) => new Set(validateRouteAllowlist(name, values, exact));
	const aptRoots = parseSortedRoutes("ordinary APT roots", value.apt_roots, false);
	const yumRepos = parseSortedIDs("ordinary YUM repository IDs", value.yum_repos);
	const yumRoots = parseSortedRoutes("ordinary YUM roots", value.yum_roots, false);
	const assetRoots = parseSortedRoutes("ordinary asset roots", value.asset_roots, false);
	const assetKeys = parseSortedRoutes("ordinary asset exact keys", value.asset_keys, true);
	const yumChannels = new Map();
	let previousChannel = "";
	for (const channel of value.yum_channels) {
		if (!channel || Object.keys(channel).sort().join(",") !== "arch,os,repo,root,view" ||
			!["beta", "latest", "stable"].includes(channel.view) || !yumRepos.has(channel.repo) ||
			![channel.repo, channel.os, channel.arch].every((item) => typeof item === "string" && SAFE_SEGMENT.test(item)) ||
			typeof channel.root !== "string" || !yumRoots.has(channel.root)) {
			throw new TypeError("ordinary YUM channels contain an invalid coordinate");
		}
		const key = channelKey(channel.view, channel.repo, channel.os, channel.arch);
		if (key <= previousChannel) throw new TypeError("ordinary YUM channels must be unique and sorted");
		yumChannels.set(key, channel.root);
		previousChannel = key;
	}
	const byID = new Map();
	const byRoot = new Map();
	let previous = "";
	for (const projection of value.projections) {
		if (!projection || Object.keys(projection).sort().join(",") !== "arch,id,os,root,view" ||
			typeof projection.id !== "string" || !PROVIDER_ID_PATTERN.test(projection.id) || typeof projection.root !== "string" ||
			projection.view !== "latest" || projection.os !== "cross-el" || typeof projection.arch !== "string" || !SAFE_SEGMENT.test(projection.arch) ||
			projection.id <= previous) {
			throw new TypeError("compatibility projections must be unique and sorted");
		}
		validateRouteAllowlist("compatibility root", [projection.root], false);
		if (byRoot.has(projection.root)) throw new TypeError("compatibility roots must be unique");
		byID.set(projection.id, projection);
		byRoot.set(projection.root, projection.id);
		previous = projection.id;
	}
	const parseIDs = (name, ids) => {
		const result = new Set();
		let prior = "";
		for (const id of ids) {
			if (typeof id !== "string" || id <= prior || !byID.has(id)) throw new TypeError(`${name} compatibility IDs must be configured, unique, and sorted`);
			result.add(id);
			prior = id;
		}
		return result;
	};
	const raw = parseIDs("raw", value.raw);
	const active = parseIDs("active", value.active);
	for (const id of active) {
		if (!raw.has(id)) throw new TypeError("active compatibility ID lacks a raw bridge");
		for (const name of ["repository.pgp", "packages.pgp"]) {
			if (!publicKeys.includes(`_sow/v1/trust/yum-compat/${id}/${name}`)) throw new TypeError("active compatibility trust keys are incomplete");
		}
	}
	for (const id of raw) {
		if (!publicPrefixes.includes(byID.get(id).root)) throw new TypeError("raw compatibility root is absent from public prefixes");
	}
	for (const id of byID.keys()) {
		if (active.has(id)) continue;
		for (const name of ["repository.pgp", "packages.pgp"]) {
			if (publicKeys.includes(`_sow/v1/trust/yum-compat/${id}/${name}`)) throw new TypeError("inactive compatibility trust key is public");
		}
	}
	const snapshots = new Map();
	let previousSnapshot = "";
	for (const snapshot of value.snapshots) {
		if (!snapshot || Object.keys(snapshot).sort().join(",") !== "apt_roots,asset_keys,asset_roots,id,yum_roots" ||
			typeof snapshot.id !== "string" || !SNAPSHOT_PATTERN.test(snapshot.id) || snapshot.id <= previousSnapshot) {
			throw new TypeError("snapshot route admissions must be complete, unique, and sorted");
		}
		snapshots.set(snapshot.id, {
			aptRoots: parseSortedRoutes(`snapshot ${snapshot.id} APT roots`, snapshot.apt_roots, false),
			yumRoots: parseSortedRoutes(`snapshot ${snapshot.id} YUM roots`, snapshot.yum_roots, false),
			assetRoots: parseSortedRoutes(`snapshot ${snapshot.id} asset roots`, snapshot.asset_roots, false),
			assetKeys: parseSortedRoutes(`snapshot ${snapshot.id} asset keys`, snapshot.asset_keys, true),
		});
		previousSnapshot = snapshot.id;
	}
	const prefixOwns = (root) => publicPrefixes.some((prefix) => root === prefix || root.startsWith(`${prefix}/`));
	for (const root of [...aptRoots, ...yumRoots, ...assetRoots]) {
		if (!prefixOwns(root)) throw new TypeError("route inventory root is absent from public prefixes");
	}
	for (const key of assetKeys) {
		if (!publicKeys.includes(key)) throw new TypeError("asset exact key is absent from public keys");
	}
	return { aptRoots, byID, byRoot, raw, active, yumRepos, yumRoots, yumChannels, assetRoots, assetKeys, snapshots };
}

function validateRouteAllowlist(name, values, exact) {
	if (!Array.isArray(values) || values.length > 10000) {
		throw new TypeError(`${name} must be a route allowlist`);
	}
	let previous = "";
	const result = [];
	for (const value of values) {
		if (typeof value !== "string" || value.length > 2048 || value.startsWith("/") || value.endsWith("/") || value.includes("//") || value.includes("%") || value.includes("\\")) {
			throw new TypeError(`${name} contains an invalid route path`);
		}
		const segments = value.split("/");
		const reservedRoot = [".sow", ".pool", ".git", "_sow"].includes(segments[0]);
		if (segments.some((segment) => segment === "." || segment === ".." || !SAFE_SEGMENT.test(segment)) ||
			(reservedRoot && !(exact && isExactPublicControlKey(segments)))) {
			throw new TypeError(`${name} contains a reserved or non-canonical route path`);
		}
		if (previous !== "" && value <= previous) {
			throw new TypeError(`${name} must be strictly sorted and unique`);
		}
		if (!exact && result.some((prefix) => value.startsWith(`${prefix}/`))) {
			throw new TypeError(`${name} contains overlapping route prefixes`);
		}
		previous = value;
		result.push(value);
	}
	return result;
}

// Public control objects are a closed exact-key contract. Keeping this grammar
// beside allowlist validation means a generated deployment cannot use
// SOW_PUBLIC_KEYS to expose an arbitrary _sow object even if request routing
// later performs an exact string comparison.
function isExactPublicControlKey(segments) {
	return segments.length === 6 &&
		segments[0] === "_sow" && segments[1] === "v1" &&
		segments[2] === "trust" && segments[3] === "yum-compat" &&
		PROVIDER_ID_PATTERN.test(segments[4]) &&
		(segments[5] === "repository.pgp" || segments[5] === "packages.pgp");
}

export async function sha256Hex(value) {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function constantTimeHexEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index % Math.max(left.length, 1)) || 0) ^ (right.charCodeAt(index % Math.max(right.length, 1)) || 0);
  }
  return difference === 0;
}

export function createStaticEnvironmentVerifier(environment) {
  const tokenEntitlements = parseEntitlements(environment?.SOW_TOKEN_ENTITLEMENTS, true);
  const basicEntitlements = parseEntitlements(environment?.SOW_BASIC_ENTITLEMENTS, true);
  if (tokenEntitlements === null) {
	throw new TypeError("SOW_TOKEN_ENTITLEMENTS must contain a strict entitlement JSON array");
  }
  if (basicEntitlements === null) {
	throw new TypeError("SOW_BASIC_ENTITLEMENTS must contain a strict entitlement JSON array");
  }
  return {
    async verifyToken(token, context) {
      const digest = await sha256Hex(token);
      return verifyEntitlement(tokenEntitlements, digest, context);
    },
    async verifyBasic(credentials, context) {
      const digest = await sha256Hex(credentials.encoded);
      return verifyEntitlement(basicEntitlements, digest, context);
    },
  };
}

// readEdgeRuntimeConfiguration consumes the exact non-secret variable mapping
// emitted by Go's config.EdgeDeployment. A stale or partially configured edge
// deployment fails at adapter construction instead of silently selecting a
// permissive verifier fallback.
export function readEdgeRuntimeConfiguration(environment) {
  if (environment?.SOW_EDGE_SCHEMA !== EDGE_RUNTIME_SCHEMA) {
	throw new TypeError(`SOW_EDGE_SCHEMA must be ${EDGE_RUNTIME_SCHEMA}`);
  }
  if (environment?.SOW_PRO_PREFIX !== EDGE_PRO_PREFIX) {
	throw new TypeError(`SOW_PRO_PREFIX must be ${EDGE_PRO_PREFIX}`);
  }
  const publicBaseURL = normalizeHTTPSOrigin("SOW_PUBLIC_BASE_URL", environment?.SOW_PUBLIC_BASE_URL);
  const betaBaseURL = normalizeHTTPSOrigin("SOW_BETA_BASE_URL", environment?.SOW_BETA_BASE_URL);
  if (publicBaseURL === betaBaseURL) {
	throw new TypeError("SOW_BETA_BASE_URL must be distinct from SOW_PUBLIC_BASE_URL");
  }
  const tokenVerifier = parseTokenVerifierReference(environment?.SOW_TOKEN_VERIFIER);
	const publicPrefixes = parseRuntimeRouteAllowlist("SOW_PUBLIC_PREFIXES", environment?.SOW_PUBLIC_PREFIXES, false);
	const publicKeys = parseRuntimeRouteAllowlist("SOW_PUBLIC_KEYS", environment?.SOW_PUBLIC_KEYS, true);
	const compatibility = parseRuntimeCompatibilityAdmission(environment?.SOW_COMPATIBILITY_ADMISSION);
  return { publicBaseURL, betaBaseURL, tokenVerifier, publicPrefixes, publicKeys, compatibility };
}

function parseRuntimeCompatibilityAdmission(value) {
	if (typeof value !== "string" || value.length > 1024 * 1024) throw new TypeError("SOW_COMPATIBILITY_ADMISSION must be canonical JSON");
	let decoded;
	try {
		decoded = JSON.parse(value);
	} catch {
		throw new TypeError("SOW_COMPATIBILITY_ADMISSION must be canonical JSON");
	}
	if (JSON.stringify(decoded) !== value) throw new TypeError("SOW_COMPATIBILITY_ADMISSION must use canonical compact JSON");
	return decoded;
}

function parseRuntimeRouteAllowlist(name, value, exact) {
	if (typeof value !== "string" || value.length > 1024 * 1024) {
		throw new TypeError(`${name} must be a canonical JSON route allowlist`);
	}
	let decoded;
	try {
		decoded = JSON.parse(value);
	} catch {
		throw new TypeError(`${name} must be a canonical JSON route allowlist`);
	}
	const validated = validateRouteAllowlist(name, decoded, exact);
	if (JSON.stringify(validated) !== value) {
		throw new TypeError(`${name} must use canonical compact JSON`);
	}
	return validated;
}

// createConfiguredTokenVerifier implements the same digest-only verifier
// protocol for both vendor adapters. Cloudflare selects a service binding;
// EdgeOne selects an HTTPS endpoint authenticated with a platform secret.
// env:// remains a deterministic secret-bound entitlement implementation for
// small deployments and contract tests.
export function createConfiguredTokenVerifier(environment, options = {}) {
  const runtime = readEdgeRuntimeConfiguration(environment);
  const reference = runtime.tokenVerifier;
  if (reference.kind === "env") {
	const entitlements = parseEntitlements(environment?.[reference.name], false);
	if (entitlements === null) {
	  throw new TypeError(`${reference.name} must contain a strict entitlement JSON array`);
	}
	return async (token, context) => {
	  const digest = await sha256Hex(token);
	  return verifyEntitlement(entitlements, digest, context);
	};
  }

  if (options.providerTransport === "service") {
	const binding = environment?.TOKEN_VERIFIER;
	if (!binding || typeof binding.fetch !== "function") {
	  throw new TypeError("provider:// token verification requires the TOKEN_VERIFIER service binding");
	}
	return (token, context) => verifyWithProvider(
	  (request) => binding.fetch(request),
	  `https://sow-token-verifier.invalid/v1/providers/${reference.name}/verify`,
	  "",
	  reference.name,
	  token,
	  context,
	);
  }
  if (options.providerTransport === "https") {
	const endpoint = normalizeVerifierEndpoint(environment?.SOW_TOKEN_VERIFIER_URL);
	const bearer = environment?.SOW_TOKEN_VERIFIER_BEARER;
	if (typeof bearer !== "string" || bearer.length < 16 || bearer.length > 4096 || /[\0\r\n]/.test(bearer)) {
	  throw new TypeError("provider:// token verification requires SOW_TOKEN_VERIFIER_BEARER as a platform secret");
	}
	if (typeof options.fetch !== "function") {
	  throw new TypeError("provider:// HTTPS verification requires the runtime Fetch API");
	}
	return (token, context) => verifyWithProvider(options.fetch, endpoint, bearer, reference.name, token, context);
  }
  throw new TypeError("provider:// token verifier transport is not configured for this runtime");
}

function parseTokenVerifierReference(value) {
  if (typeof value !== "string" || value.length > 256) {
	throw new TypeError("SOW_TOKEN_VERIFIER must be an env:// or provider:// reference");
  }
  if (value.startsWith("env://")) {
	const name = value.slice("env://".length);
	if (name.length > 128 || !ENVIRONMENT_NAME_PATTERN.test(name)) {
	  throw new TypeError("SOW_TOKEN_VERIFIER has an invalid env binding name");
	}
	return { kind: "env", name };
  }
  if (value.startsWith("provider://")) {
	const name = value.slice("provider://".length);
	if (name.length > 128 || !PROVIDER_ID_PATTERN.test(name)) {
	  throw new TypeError("SOW_TOKEN_VERIFIER has an invalid provider ID");
	}
	return { kind: "provider", name };
  }
  throw new TypeError("SOW_TOKEN_VERIFIER must be an env:// or provider:// reference");
}

function normalizeHTTPSOrigin(name, value) {
  let parsed;
  try {
	parsed = new URL(value || "");
  } catch {
	throw new TypeError(`${name} must be a clean HTTPS origin`);
  }
  if (parsed.protocol !== "https:" || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.username || parsed.password || parsed.port) {
	throw new TypeError(`${name} must be a clean HTTPS origin`);
  }
  return parsed.origin;
}

function normalizeVerifierEndpoint(value) {
  let parsed;
  try {
	parsed = new URL(value || "");
  } catch {
	throw new TypeError("SOW_TOKEN_VERIFIER_URL must be a clean HTTPS endpoint");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.port || parsed.pathname === "/") {
	throw new TypeError("SOW_TOKEN_VERIFIER_URL must be a clean HTTPS endpoint");
  }
  return parsed.toString();
}

async function verifyWithProvider(fetchFunction, endpoint, bearer, provider, token, context) {
  const digest = await sha256Hex(token);
  const headers = new Headers({
	"Content-Type": "application/json",
	"Cache-Control": "no-store",
  });
  if (bearer !== "") headers.set("Authorization", `Bearer ${bearer}`);
  const request = new Request(endpoint, {
	method: "POST",
	headers,
	body: JSON.stringify({
	  schema: "sow-token-verifier-request/v1",
	  provider,
	  token_sha256: digest,
	  audience: context?.audience,
	  path: context?.path,
	}),
	redirect: "manual",
  });
  let response;
  try {
	response = await fetchFunction(request);
  } catch {
	return { status: "unavailable" };
  }
  if (!(response instanceof Response)) return { status: "unavailable" };
  if (response.status === 200) return { status: "ok" };
  if (response.status === 403) return { status: "forbidden" };
  if (response.status === 401 || response.status === 404) return { status: "invalid" };
  return { status: "unavailable" };
}

function verifyEntitlement(entitlements, digest, context) {
  let matched;
  for (const entitlement of entitlements) {
    if (constantTimeHexEqual(entitlement.sha256, digest)) {
      matched = entitlement;
    }
  }
  if (!matched || !context || typeof context.audience !== "string" || typeof context.path !== "string") {
    return { status: "invalid" };
  }
  const expiry = canonicalUTCExpiryMillis(matched.expires_at);
  if (expiry === null || Date.now() >= expiry) {
    return { status: "invalid" };
  }
  if (!matched.audiences.includes(context.audience) || !matched.path_prefixes.some((prefix) => pathHasPrefix(context.path, prefix))) {
    return { status: "forbidden" };
  }
  return { status: "ok" };
}

function pathHasPrefix(value, prefix) {
  return prefix === "/" || value === prefix || value.startsWith(`${prefix}/`);
}

function parseEntitlements(value, allowMissing) {
  if ((value === undefined || value === null || value === "") && allowMissing) {
	return [];
  }
  if (typeof value !== "string" || value.length > 1024 * 1024) {
    return null;
  }
  let decoded;
  try {
    decoded = JSON.parse(value);
  } catch {
    return null;
  }
  if (!Array.isArray(decoded) || decoded.length > 10000) {
    return null;
  }
  for (const item of decoded) {
    if (!item || typeof item !== "object" || !/^[0-9a-f]{64}$/.test(item.sha256 || "")) {
	  return null;
    }
	if (canonicalUTCExpiryMillis(item.expires_at) === null) {
	  return null;
	}
    if (!Array.isArray(item.audiences) || item.audiences.length === 0 || item.audiences.some((audience) => typeof audience !== "string" || !/^[a-z0-9.-]+$/.test(audience))) {
	  return null;
    }
    if (!Array.isArray(item.path_prefixes) || item.path_prefixes.length === 0 || item.path_prefixes.some((prefix) => typeof prefix !== "string" || !/^\/(?:[A-Za-z0-9+._~^:-]+(?:\/[A-Za-z0-9+._~^:-]+)*)?$/.test(prefix))) {
	  return null;
    }
	if (Object.keys(item).some((key) => !["sha256", "expires_at", "audiences", "path_prefixes"].includes(key))) {
	  return null;
	}
  }
	decoded.sort((left, right) => left.sha256 < right.sha256 ? -1 : left.sha256 > right.sha256 ? 1 : 0);
	for (let index = 1; index < decoded.length; index += 1) {
		if (decoded[index - 1].sha256 === decoded[index].sha256) {
			// One credential has exactly one authority record. Rejecting duplicate
			// digests prevents JSON input order from choosing the winning audience,
			// path scope, or expiry while retaining constant-time lookup below.
			return null;
		}
	}
  return decoded;
}

// Keep credential expiry interpretation byte-identical across vendor runtimes.
// Date.parse accepts timezone-less, offset, rollover, and implementation-shaped
// inputs; a Cloudflare UTC runtime and an EdgeOne regional runtime could then
// disagree about whether the same credential is live. The entitlement wire
// contract therefore admits exactly UTC RFC3339 whole seconds and rejects
// calendar values that the Date implementation would normalize.
function canonicalUTCExpiryMillis(value) {
	if (typeof value !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value)) {
		return null;
	}
	const parsed = Date.parse(value);
	if (!Number.isFinite(parsed)) return null;
	const roundTrip = new Date(parsed).toISOString();
	return roundTrip === `${value.slice(0, -1)}.000Z` ? parsed : null;
}
