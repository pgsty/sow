const PRIVATE_ORIGIN_SEGMENT = /^[A-Za-z0-9+._~^:-]+$/;

export const PRIVATE_ORIGIN_SERVICE_ORIGIN = "https://sow-private-origin.invalid";

export function validatePrivateOriginKey(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 8192 || value.startsWith("/") || value.endsWith("/") || value.includes("\\") || value.includes("%") || value.includes("?") || value.includes("#") || value.includes("\0")) {
    throw new TypeError("origin object key is unsafe");
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === ".." || !PRIVATE_ORIGIN_SEGMENT.test(segment))) {
    throw new TypeError("origin object key is unsafe");
  }
  return value;
}

export function privateOriginURL(origin, key) {
  const base = origin instanceof URL ? new URL(origin.href) : new URL(origin || "");
  if (base.protocol !== "https:" || base.username || base.password || base.pathname !== "/" || base.search || base.hash || base.port) {
    throw new TypeError("private origin must be a clean HTTPS origin");
  }
  validatePrivateOriginKey(key);
  // The leading slash is security-significant. Scheme-shaped keys must remain
  // pathnames and can never replace the credential-bearing origin.
  const pathname = `/${key.split("/").map(encodePrivateOriginSegment).join("/")}`;
  const result = new URL(pathname, base);
  if (result.protocol !== "https:" || result.origin !== base.origin || result.username || result.password || result.pathname !== pathname || result.search || result.hash) {
    throw new TypeError("origin object key escaped the private origin");
  }
  return result;
}

export function decodePrivateOriginPath(pathname) {
  if (typeof pathname !== "string" || !pathname.startsWith("/") || pathname.length > 8193 || pathname.includes("//")) {
    throw new TypeError("private origin pathname is unsafe");
  }
  let key;
  try {
    key = pathname.slice(1).split("/").map((segment) => decodeURIComponent(segment)).join("/");
  } catch {
    throw new TypeError("private origin pathname is unsafe");
  }
  validatePrivateOriginKey(key);
  return key;
}

function encodePrivateOriginSegment(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function privateOriginError(status, code, headers = undefined) {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "text/plain; charset=utf-8");
  responseHeaders.set("Cache-Control", "private, no-store, max-age=0");
  responseHeaders.set("X-Content-Type-Options", "nosniff");
  return new Response(`${code}\n`, { status, headers: responseHeaders });
}

export function normalizeOriginCacheStatus(value) {
  if (typeof value !== "string") return "UNKNOWN";
  const normalized = value.trim().toUpperCase();
  for (const status of ["HIT", "MISS", "BYPASS", "DYNAMIC", "EXPIRED", "STALE", "UPDATING", "REVALIDATED"]) {
    if (normalized === status || normalized.includes(status)) return status;
  }
	return "UNKNOWN";
}

export function originCacheFreshnessEvidence(headers) {
  if (!(headers instanceof Headers)) return null;
  const age = parseBoundedCacheSeconds(headers.get("Age"));
  if (age === null) return null;
  let shared = null;
  let ordinary = null;
  for (const rawDirective of (headers.get("Cache-Control") || "").split(",")) {
    const directive = rawDirective.trim().toLowerCase();
    const match = /^(s-maxage|max-age)=([0-9]{1,9})$/.exec(directive);
    if (!match) continue;
    const seconds = parseBoundedCacheSeconds(match[2]);
    if (seconds === null) continue;
    if (match[1] === "s-maxage") shared = seconds;
    if (match[1] === "max-age") ordinary = seconds;
  }
  const maxAge = shared ?? ordinary;
  if (maxAge === null || maxAge <= age) return null;
  return { age, maxAge };
}

function parseBoundedCacheSeconds(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,8})$/.test(value)) return null;
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds < 0 || seconds > 315360000) return null;
  return seconds;
}
