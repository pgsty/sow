import {
  PRIVATE_ORIGIN_SERVICE_ORIGIN,
  decodePrivateOriginPath,
  privateOriginError,
  privateOriginURL,
  validatePrivateOriginKey,
} from "../shared/private-origin.mjs";

const FORBIDDEN_REQUEST_HEADERS = ["Authorization", "Cookie", "Proxy-Authorization"];

export function createCloudflareR2OriginHandler(environment) {
  const bucket = environment?.REPOSITORY;
  if (!bucket || typeof bucket.get !== "function" || typeof bucket.head !== "function") {
    throw new TypeError("Cloudflare REPOSITORY R2 binding is required");
  }
  return async function handleR2Origin(request) {
    const parsed = parseServiceRequest(request);
    if (parsed.response) return parsed.response;
    try {
      const conditional = hasConditionalHeaders(request.headers);
      const object = parsed.method === "HEAD" && !conditional
        ? await bucket.head(parsed.key)
        : await bucket.get(parsed.key, { range: request.headers, onlyIf: request.headers });
      if (!object) return privateOriginError(404, "not_found");
      return r2ObjectResponse(object, parsed.method, request.headers, conditional);
    } catch {
      return privateOriginError(503, "temporarily_unavailable");
    }
  };
}

function parseServiceRequest(request) {
  if (!(request instanceof Request) || typeof request.url !== "string" || request.url.length > 8192) {
    return { response: privateOriginError(404, "not_found") };
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return { response: privateOriginError(405, "method_not_allowed", { Allow: "GET, HEAD" }) };
  }
  if (FORBIDDEN_REQUEST_HEADERS.some((name) => request.headers.has(name))) {
    return { response: privateOriginError(404, "not_found") };
  }
  let url;
  try {
    url = new URL(request.url);
  } catch {
    return { response: privateOriginError(404, "not_found") };
  }
  if (url.origin !== PRIVATE_ORIGIN_SERVICE_ORIGIN || url.username || url.password || url.search || url.hash || !url.pathname.startsWith("/")) {
    return { response: privateOriginError(404, "not_found") };
  }
  let key;
  try {
    key = decodePrivateOriginPath(url.pathname);
    validatePrivateOriginKey(key);
    if (privateOriginURL(PRIVATE_ORIGIN_SERVICE_ORIGIN, key).href !== request.url) {
      throw new TypeError("non-canonical service URL");
    }
  } catch {
    return { response: privateOriginError(404, "not_found") };
  }
  return { method: request.method, key };
}

function r2ObjectResponse(object, method, requestHeaders, conditional) {
  const headers = new Headers();
  if (typeof object.writeHttpMetadata === "function") object.writeHttpMetadata(headers);
  headers.delete("Set-Cookie");
  headers.delete("Server");
  if (typeof object.httpEtag === "string" && object.httpEtag !== "") {
    headers.set("ETag", object.httpEtag);
  } else if (typeof object.etag === "string" && object.etag !== "") {
    headers.set("ETag", `"${object.etag.replace(/^"|"$/g, "")}"`);
  }
  const range = normalizeR2Range(object.range, object.size);
  const length = range ? range.length : object.size;
  if (Number.isSafeInteger(length) && length >= 0) headers.set("Content-Length", String(length));
  if (object.uploaded instanceof Date && !Number.isNaN(object.uploaded.valueOf())) headers.set("Last-Modified", object.uploaded.toUTCString());
  headers.set("Accept-Ranges", "bytes");
  headers.set("X-Content-Type-Options", "nosniff");
  if (conditional && object.body === undefined) {
    const status = failedConditionStatus(object, requestHeaders);
    headers.delete("Content-Length");
    headers.set("Cache-Control", "private, no-store, max-age=0");
    return new Response(null, { status, headers });
  }
  if (method === "GET" && object.body === undefined) return privateOriginError(503, "temporarily_unavailable");
  if (range) headers.set("Content-Range", `bytes ${range.offset}-${range.offset + range.length - 1}/${object.size}`);
  return new Response(method === "HEAD" ? null : object.body, { status: range && method === "GET" ? 206 : 200, headers });
}

function normalizeR2Range(value, size) {
  if (!value || !Number.isSafeInteger(value.offset) || value.offset < 0 || !Number.isSafeInteger(value.length) || value.length <= 0 || !Number.isSafeInteger(size) || size < value.offset + value.length) {
    return null;
  }
  return { offset: value.offset, length: value.length };
}

function hasConditionalHeaders(headers) {
  return ["If-Match", "If-Unmodified-Since", "If-None-Match", "If-Modified-Since"].some((name) => headers.has(name));
}

// R2 evaluates the Headers passed through onlyIf and returns metadata without a
// body on any failed condition. Classify that bodyless result with RFC 9110's
// precondition order so a failed positive condition cannot be mislabeled 304
// merely because a later cache validator is also present.
function failedConditionStatus(object, headers) {
  const etag = objectHTTPETag(object);
  const ifMatch = headers.get("If-Match");
  if (ifMatch !== null) {
    if (!entityTagMatches(ifMatch, etag, false)) return 412;
  } else {
    const ifUnmodifiedSince = parseHTTPDate(headers.get("If-Unmodified-Since"));
    if (ifUnmodifiedSince !== null && object.uploaded instanceof Date && object.uploaded.valueOf() > ifUnmodifiedSince) return 412;
  }
  const ifNoneMatch = headers.get("If-None-Match");
  if (ifNoneMatch !== null) {
    if (entityTagMatches(ifNoneMatch, etag, true)) return 304;
  } else {
    const ifModifiedSince = parseHTTPDate(headers.get("If-Modified-Since"));
    if (ifModifiedSince !== null && object.uploaded instanceof Date && object.uploaded.valueOf() <= ifModifiedSince) return 304;
  }
  // R2 rejected a condition that could not be safely classified from returned
  // metadata (including malformed or provider-new syntax). Fail as a positive
  // precondition instead of exposing a false cache hit.
  return 412;
}

function objectHTTPETag(object) {
  if (typeof object.httpEtag === "string" && object.httpEtag !== "") return object.httpEtag;
  if (typeof object.etag === "string" && object.etag !== "") return `"${object.etag.replace(/^"|"$/g, "")}"`;
  return "";
}

function entityTagMatches(value, current, weak) {
  if (typeof value !== "string" || current === "") return false;
  for (const candidate of value.split(",").map((item) => item.trim())) {
    if (candidate === "*") return true;
    if (weak) {
      if (candidate.replace(/^W\//, "") === current.replace(/^W\//, "")) return true;
    } else if (!candidate.startsWith("W/") && candidate === current) {
      return true;
    }
  }
  return false;
}

function parseHTTPDate(value) {
  if (value === null) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export default {
  async fetch(request, environment) {
    try {
      return await createCloudflareR2OriginHandler(environment)(request);
    } catch {
      return privateOriginError(503, "temporarily_unavailable");
    }
  },
};
