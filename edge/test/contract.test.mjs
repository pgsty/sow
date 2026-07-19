import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

import { createSowEdgeHandler, sha256Hex } from "../shared/contract.mjs";
import { createCloudflareR2OriginHandler } from "../cloudflare/origin.mjs";
import { createCloudflareHandler } from "../cloudflare/worker.mjs";
import { createEdgeOneHandler } from "../edgeone/function.mjs";

const tokenA = "A".repeat(22);
const tokenB = "B".repeat(22);
const invalidToken = "C".repeat(22);
const basicValue = "pigsty:correct-horse-battery-staple";
const runtimeFixture = JSON.parse(readFileSync(new URL("../testdata/runtime-contract.json", import.meta.url), "utf8"));
const deploymentFixtures = JSON.parse(readFileSync(new URL("../testdata/deployment-contracts.json", import.meta.url), "utf8"));
const runtimeRouteAdmission = JSON.parse(runtimeFixture.runtime_variables.SOW_COMPATIBILITY_ADMISSION);

function routeAdmission(overrides = {}) {
	return { ...runtimeRouteAdmission, ...overrides };
}

function runtimeVariables(tokenVerifier = "env://SOW_TOKEN_ENTITLEMENTS") {
  return {
	...runtimeFixture.runtime_variables,
		SOW_TOKEN_VERIFIER: tokenVerifier,
		SOW_PUBLIC_BASE_URL: "https://repo.example",
		SOW_BETA_BASE_URL: "https://beta.example/",
		SOW_PUBLIC_PREFIXES: '["apt/infra","pkg","yum"]',
		SOW_PUBLIC_KEYS: '["keys/test-package-trust.asc"]',
		SOW_ORIGIN_MODE: "r2-service",
  };
}

function cosRuntimeVariables() {
  return {
		SOW_ORIGIN_MODE: "cos-sigv4",
    SOW_COS_REGION: "ap-guangzhou",
    SOW_COS_BUCKET: "sow-contract-1250000000",
    SOW_COS_SECRET_ID: "AKIDEXAMPLE0123456789012345",
    SOW_COS_SECRET_KEY: "cos-secret-key-for-contract-tests-only",
  };
}

function deterministicEdgeOnePlatform(fetch, extra = {}) {
  return {
    crypto: webcrypto,
    now: () => new Date("2026-07-12T03:04:05Z"),
    fetch,
    ...extra,
  };
}

class MemoryCache {
  constructor() {
    this.values = new Map();
    this.keys = [];
  }

  async match(request) {
    this.keys.push(request.url);
    const response = this.values.get(request.url);
    return response ? response.clone() : undefined;
  }

  async put(request, response) {
    this.keys.push(request.url);
    this.values.set(request.url, response.clone());
  }
}

class FakeR2Bucket {
  constructor(objects = new Map()) {
    this.objects = objects;
    this.calls = [];
    this.failure = null;
  }

  async head(key) {
    this.calls.push({ method: "HEAD", key });
    if (this.failure) throw this.failure;
    const value = this.objects.get(key);
    return value ? fakeR2Object(value) : null;
  }

  async get(key, options = {}) {
    this.calls.push({ method: "GET", key, options });
    if (this.failure) throw this.failure;
    const value = this.objects.get(key);
    if (!value) return null;
    const object = fakeR2Object(value);
		if (fakeR2ConditionFails(object, options.onlyIf)) {
			delete object.body;
			return object;
		}
    const headers = options.range;
    const range = headers?.get("Range")?.match(/^bytes=(\d+)-(\d+)$/);
    if (range) {
      const offset = Number(range[1]);
      const end = Math.min(Number(range[2]), value.body.length - 1);
      object.range = { offset, length: end - offset + 1 };
      object.body = value.body.slice(offset, end + 1);
    }
    return object;
  }
}

function fakeR2ConditionFails(object, headers) {
	if (!headers) return false;
	const tagListMatches = (value, weak) => typeof value === "string" && value.split(",").map((item) => item.trim()).some((item) => item === "*" || (weak ? item.replace(/^W\//, "") === object.httpEtag : !item.startsWith("W/") && item === object.httpEtag));
	const ifMatch = headers.get("If-Match");
	if (ifMatch !== null) {
		if (!tagListMatches(ifMatch, false)) return true;
	} else {
		const boundary = Date.parse(headers.get("If-Unmodified-Since") || "");
		if (Number.isFinite(boundary) && object.uploaded.valueOf() > boundary) return true;
	}
	const ifNoneMatch = headers.get("If-None-Match");
	if (ifNoneMatch !== null) {
		if (tagListMatches(ifNoneMatch, true)) return true;
	} else {
		const boundary = Date.parse(headers.get("If-Modified-Since") || "");
		if (Number.isFinite(boundary) && object.uploaded.valueOf() <= boundary) return true;
	}
	return false;
}

function fakeR2Object(value) {
  return {
    body: value.body,
    size: value.body.length,
    httpEtag: value.etag || '"r2-fixture"',
    uploaded: value.uploaded || new Date("2026-07-12T00:00:00Z"),
    writeHttpMetadata(headers) {
      headers.set("Content-Type", value.contentType || "application/octet-stream");
      if (value.cacheControl) headers.set("Cache-Control", value.cacheControl);
    },
  };
}

test("Cloudflare service-only R2 origin provides GET, HEAD, range, conditional, and private errors", async () => {
  const key = ".sow/gated/yum/infra/Packages/p/pkg.rpm";
  const body = new TextEncoder().encode("0123456789");
  const bucket = new FakeR2Bucket(new Map([[key, { body, cacheControl: "public, max-age=60" }]]));
  const handler = createCloudflareR2OriginHandler({ REPOSITORY: bucket });

  const get = await handler(new Request(`https://sow-private-origin.invalid/${key}`));
  assert.equal(get.status, 200);
  assert.equal(await get.text(), "0123456789");
  assert.equal(get.headers.get("ETag"), '"r2-fixture"');
  assert.equal(get.headers.get("Accept-Ranges"), "bytes");
  assert.equal(get.headers.get("Cache-Control"), "public, max-age=60");

  const head = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { method: "HEAD" }));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
  assert.equal(head.headers.get("Content-Length"), "10");

  const ranged = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { headers: { Range: "bytes=2-5" } }));
  assert.equal(ranged.status, 206);
  assert.equal(await ranged.text(), "2345");
  assert.equal(ranged.headers.get("Content-Range"), "bytes 2-5/10");
  assert.equal(ranged.headers.get("Content-Length"), "4");
  const rangeCall = bucket.calls.at(-1);
  assert.equal(rangeCall.options.range.get("Range"), "bytes=2-5");
  assert.equal(rangeCall.options.onlyIf.get("Range"), "bytes=2-5");

  const conditional = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { headers: { "If-None-Match": '"r2-fixture"' } }));
  assert.equal(conditional.status, 304);
  assert.equal(conditional.headers.get("Cache-Control"), "private, no-store, max-age=0");
  const conditionalHead = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { method: "HEAD", headers: { "If-None-Match": '"r2-fixture"' } }));
  assert.equal(conditionalHead.status, 304);
	assert.equal(bucket.calls.at(-1).method, "GET", "conditional HEAD must use R2 get(...onlyIf), not unconditional head()");
	assert.equal(bucket.calls.at(-1).options.onlyIf.get("If-None-Match"), '"r2-fixture"');

	const match = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { headers: { "If-Match": '"r2-fixture"' } }));
	assert.equal(match.status, 200);
	const failedMatch = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { headers: { "If-Match": '"other"' } }));
	assert.equal(failedMatch.status, 412);
	assert.equal(failedMatch.headers.get("Cache-Control"), "private, no-store, max-age=0");
	const failedMatchHead = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { method: "HEAD", headers: { "If-Match": '"other"' } }));
	assert.equal(failedMatchHead.status, 412);
	const failedTime = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { headers: { "If-Unmodified-Since": "Sat, 11 Jul 2026 23:59:59 GMT" } }));
	assert.equal(failedTime.status, 412);
	const validTimeHead = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { method: "HEAD", headers: { "If-Unmodified-Since": "Mon, 13 Jul 2026 00:00:00 GMT" } }));
	assert.equal(validTimeHead.status, 200);
	const notModifiedTime = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { method: "HEAD", headers: { "If-Modified-Since": "Mon, 13 Jul 2026 00:00:00 GMT" } }));
	assert.equal(notModifiedTime.status, 304);
	const positivePrecedence = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { headers: { "If-Match": '"other"', "If-None-Match": '"r2-fixture"' } }));
	assert.equal(positivePrecedence.status, 412, "failed If-Match must precede matching If-None-Match");
	const negativeAfterMatch = await handler(new Request(`https://sow-private-origin.invalid/${key}`, { headers: { "If-Match": '"r2-fixture"', "If-None-Match": '"r2-fixture"' } }));
	assert.equal(negativeAfterMatch.status, 304);

  const specialKey = "http:attacker.example/pkg^name.rpm";
  bucket.objects.set(specialKey, { body: new TextEncoder().encode("special") });
  const special = await handler(new Request("https://sow-private-origin.invalid/http%3Aattacker.example/pkg%5Ename.rpm"));
  assert.equal(special.status, 200);
  assert.equal(await special.text(), "special");
  assert.equal(bucket.calls.at(-1).key, specialKey);

  const beforeRejects = bucket.calls.length;
  for (const request of [
    new Request(`https://public.example/${key}`),
    new Request("https://sow-private-origin.invalid/unsafe%2Fsecret"),
    new Request(`https://sow-private-origin.invalid/${key}?list=1`),
    new Request(`https://sow-private-origin.invalid/${key}`, { method: "POST" }),
    new Request(`https://sow-private-origin.invalid/${key}`, { headers: { Authorization: "Bearer must-not-arrive" } }),
  ]) {
    const response = await handler(request);
    assert.ok(response.status === 404 || response.status === 405);
    assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0");
  }
  assert.equal(bucket.calls.length, beforeRejects);
  const missing = await handler(new Request("https://sow-private-origin.invalid/missing"));
  assert.equal(missing.status, 404);
  assert.equal(missing.headers.get("Cache-Control"), "private, no-store, max-age=0");
  bucket.failure = new Error("R2 unavailable");
  const unavailable = await handler(new Request(`https://sow-private-origin.invalid/${key}`));
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.headers.get("Cache-Control"), "private, no-store, max-age=0");
});

test("Cloudflare auth Worker uses the deployable R2 origin for gated-to-public fallback and HEAD", async () => {
  const publicKey = "yum/infra/x86_64/Packages/p/pkg.rpm";
  const bucket = new FakeR2Bucket(new Map([[publicKey, { body: new TextEncoder().encode("rpm-body") }]]));
  const origin = createCloudflareR2OriginHandler({ REPOSITORY: bucket });
  const environment = {
    ...runtimeVariables(),
    SOW_TOKEN_ENTITLEMENTS: JSON.stringify([entitlement(await sha256Hex(tokenA))]),
    SOW_BASIC_ENTITLEMENTS: "[]",
    ORIGIN: { fetch: origin },
  };
  const handler = createCloudflareHandler(environment);
  const response = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/${publicKey}`));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "rpm-body");
  assert.equal(response.headers.get("X-SOW-Origin-Transport"), "r2-service");
  assert.equal(response.headers.get("X-SOW-Origin-Cache-Status"), "BYPASS");
  assert.deepEqual(bucket.calls.map((call) => call.key), [`.sow/gated/${publicKey}`, publicKey]);
  assert.equal(bucket.calls.some((call) => call.key.includes(tokenA)), false);

  const ranged = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/${publicKey}`, { headers: { Range: "bytes=0-2" } }));
  assert.equal(ranged.status, 206);
  assert.equal(await ranged.text(), "rpm");
  assert.equal(ranged.headers.get("Content-Range"), "bytes 0-2/8");

  const head = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/${publicKey}`, { method: "HEAD" }));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
  assert.equal(bucket.calls.at(-1).method, "HEAD");
});

test("deployment inventories keep the R2 origin service-only and secrets names-only", () => {
  const originConfig = readFileSync(new URL("../cloudflare/wrangler.origin.toml.example", import.meta.url), "utf8");
  assert.match(originConfig, /workers_dev\s*=\s*false/);
  assert.match(originConfig, /preview_urls\s*=\s*false/);
  assert.match(originConfig, /main\s*=\s*"\.\.\/dist\/cloudflare-origin-worker\.mjs"/);
  assert.match(originConfig, /binding\s*=\s*"REPOSITORY"/);
  assert.doesNotMatch(originConfig, /^routes?\s*=/m);
  const cachePOC = readFileSync(new URL("../cloudflare/wrangler.cache-poc.toml.example", import.meta.url), "utf8");
  assert.match(cachePOC, /SOW_ORIGIN_MODE\s*=\s*"https-bearer"/);
  assert.match(cachePOC, /compatibility_flags\s*=\s*\["global_fetch_private_origin"\]/);
  assert.match(cachePOC, /SOW_ORIGIN_BASE_URL\s*=\s*"https:\/\/repo\.example"/);
  assert.match(cachePOC, /SOW_BETA_ORIGIN_BASE_URL\s*=\s*"https:\/\/beta\.example"/);
  assert.doesNotMatch(cachePOC, /binding\s*=\s*"REPOSITORY"/);
  const edgeOne = JSON.parse(readFileSync(new URL("../edgeone/bindings.example.json", import.meta.url), "utf8"));
  assert.deepEqual(edgeOne.required_secret_names.sort(), ["SOW_COS_SECRET_ID", "SOW_COS_SECRET_KEY", "SOW_TOKEN_VERIFIER_BEARER"].sort());
  assert.equal(edgeOne.variables.SOW_COS_REGION, "ap-guangzhou");
  assert.match(edgeOne.variables.SOW_COS_BUCKET, /-1250000000$/);
  assert.equal(JSON.stringify(edgeOne).includes("cos-secret-key-for-contract-tests-only"), false);
  const basic = readFileSync(new URL("../basic/nginx.conf.example", import.meta.url), "utf8");
  assert.match(basic, /does NOT cache these private,no-store responses/);
  assert.match(basic, /anonymous request could reuse an object/);
  assert.doesNotMatch(basic, /caches only 200 responses after origin authentication/);
});

test("deployment examples keep root-exact assets out of public prefix allowlists", () => {
	const expectedPrefixes = ["apt", "pkg/pig", "yum"];
	const expectedKeys = ["keys/pigsty.asc", "pkg"];
	const readTOMLAllowlist = (document, name) => {
		const match = document.match(new RegExp(`^${name}\\s*=\\s*'([^']+)'$`, "m"));
		assert.ok(match, `${name} is absent from Cloudflare example`);
		return JSON.parse(match[1]);
	};
	for (const relative of ["../cloudflare/wrangler.toml.example", "../cloudflare/wrangler.cache-poc.toml.example"]) {
		const document = readFileSync(new URL(relative, import.meta.url), "utf8");
		const prefixes = readTOMLAllowlist(document, "SOW_PUBLIC_PREFIXES");
		const keys = readTOMLAllowlist(document, "SOW_PUBLIC_KEYS");
		assert.deepEqual(prefixes, expectedPrefixes, relative);
		assert.deepEqual(keys, expectedKeys, relative);
		assert.equal(prefixes.includes("pkg"), false, `${relative} widened exact key pkg into a prefix`);
		assert.match(document, /sow materialize latest --edge-contract cf/, relative);
	}
	const edgeOne = JSON.parse(readFileSync(new URL("../edgeone/bindings.example.json", import.meta.url), "utf8"));
	const edgeOnePrefixes = JSON.parse(edgeOne.variables.SOW_PUBLIC_PREFIXES);
	const edgeOneKeys = JSON.parse(edgeOne.variables.SOW_PUBLIC_KEYS);
	assert.deepEqual(edgeOnePrefixes, expectedPrefixes);
	assert.deepEqual(edgeOneKeys, expectedKeys);
	assert.equal(edgeOnePrefixes.includes("pkg"), false, "EdgeOne example widened exact key pkg into a prefix");
	assert.match(edgeOne.comment, /sow materialize latest --edge-contract cos/);
	const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
	assert.match(readme, /SOW_PUBLIC_PREFIXES=\["apt","pkg\/pig","yum"\]/);
	assert.match(readme, /SOW_PUBLIC_KEYS=\["keys\/pigsty\.asc","pkg"\]/);
	assert.match(readme, /sow materialize latest --edge-contract TARGET/);
});

test("the exact Go deployment contracts construct both shipped JavaScript adapters", () => {
	const cloudflare = deploymentFixtures.cloudflare;
	const cloudflareEnvironment = {
		...cloudflare.variables,
		ORIGIN: { async fetch() { return new Response("not found\n", { status: 404 }); } },
		TOKEN_VERIFIER: { async fetch() { return new Response("{}", { status: 401 }); } },
	};
	assert.deepEqual(Object.keys(cloudflareEnvironment).filter((name) => typeof cloudflareEnvironment[name] === "object").sort(), cloudflare.service_bindings.slice().sort());
	assert.equal(typeof createCloudflareHandler(cloudflareEnvironment), "function");

	const edgeone = deploymentFixtures.edgeone;
	const requiredValues = {
		SOW_TOKEN_VERIFIER_URL: "https://entitlements.example/v1/verify",
		SOW_COS_SECRET_ID: "AKIDEXAMPLE0123456789012345",
		SOW_COS_SECRET_KEY: "cos-secret-key-for-contract-tests-only",
		SOW_TOKEN_VERIFIER_BEARER: "edge-verifier-secret",
	};
	const edgeoneEnvironment = { ...edgeone.variables };
	for (const name of [...edgeone.required_variables, ...edgeone.required_secrets]) edgeoneEnvironment[name] = requiredValues[name];
	assert.equal(typeof createEdgeOneHandler(edgeoneEnvironment, deterministicEdgeOnePlatform(async () => new Response("not found\n", { status: 404 }))), "function");
});

test("all generated deployment bundles load without source-tree imports", async () => {
  const authBundle = await import("../dist/cloudflare-worker.mjs");
  const originBundle = await import("../dist/cloudflare-origin-worker.mjs");
  assert.equal(typeof authBundle.createCloudflareHandler, "function");
  assert.equal(typeof originBundle.createCloudflareR2OriginHandler, "function");
  const priorListener = globalThis.addEventListener;
  let listener;
  globalThis.addEventListener = (name, candidate) => {
    assert.equal(name, "fetch");
    listener = candidate;
  };
  try {
    await import(`../dist/edgeone.js?bundle-smoke=${Date.now()}`);
  } finally {
    if (priorListener === undefined) delete globalThis.addEventListener;
    else globalThis.addEventListener = priorListener;
  }
  assert.equal(typeof listener, "function");
  for (const relative of ["../dist/cloudflare-worker.mjs", "../dist/cloudflare-origin-worker.mjs", "../dist/edgeone.js"]) {
    const body = readFileSync(new URL(relative, import.meta.url), "utf8");
    assert.doesNotMatch(body, /^import\s/m, relative);
  }
});

async function vendorFixtures(runtimeOverrides = {}, originResponder = originResponseFor, entitlementOverrides = {}) {
  const tokenEntitlements = JSON.stringify([
    entitlement(await sha256Hex(tokenA), entitlementOverrides),
    entitlement(await sha256Hex(tokenB), entitlementOverrides),
  ]);
  const basicEntitlements = JSON.stringify([entitlement(await sha256Hex(basicValue), entitlementOverrides)]);
  return [
    makeCloudflareFixture(tokenEntitlements, basicEntitlements, runtimeOverrides, originResponder),
    makeEdgeOneFixture(tokenEntitlements, basicEntitlements, runtimeOverrides, originResponder),
  ];
}

function entitlement(sha256, overrides = {}) {
  return {
    sha256,
    expires_at: "2099-01-01T00:00:00Z",
    audiences: ["repo.example"],
    path_prefixes: ["/"],
    ...overrides,
  };
}

function originResponseFor(path) {
	const deletedBetaObjects = new Set([
		".sow/beta/apt/infra/dists/bookworm/Release",
		".sow/beta/pkg/removed-tool",
		".sow/beta/pkg/Packages/p/package-shaped-asset.rpm",
		".sow/beta/yum/infra/x86_64/repodata/repomd.xml",
	]);
	if (deletedBetaObjects.has(path)) {
		return new Response("not found\n", { status: 404 });
	}
	if (path === "_sow/v1/mirrorlist/latest/infra/el9/x86_64.txt") {
		return new Response("https://repo.example/_sow/v1/g/00000000000000000042/yum/infra/x86_64/\n", { status: 200, headers: { "Content-Type": "text/plain" } });
	}
	if (path === "_sow/v1/mirrorlist/beta/infra/el9/x86_64.txt") {
		return new Response("https://beta.example/_sow/v1/g/00000000000000000042/yum/infra/x86_64/\n", { status: 200, headers: { "Content-Type": "text/plain" } });
	}
	if (path === ".sow/snapshots/jammy-20260712.json") {
		return new Response(JSON.stringify({ schema: "sow-snapshot-route/v1", snapshot: "jammy-20260712", generation: "42" }), { status: 200, headers: { "Content-Type": "application/json" } });
	}
	if (path === ".sow/snapshots/jammy-20260701.json") {
		return new Response("not found\n", { status: 404 });
	}
	if (path === ".sow/snapshots/jammy-20260601.json") {
		return new Response("gone\n", { status: 410 });
	}
  if (path.startsWith(".sow/channels/")) {
    return new Response(JSON.stringify({ generation: "42", legacy_root: "yum/infra/x86_64" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
	if (path.startsWith(".sow/beta/") && (path.includes("/Packages/") || path.includes("/pool/"))) {
		return new Response("not found\n", { status: 404 });
	}
  return new Response(`origin:${path}`, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream", ETag: '"fixture"', "X-Amz-Request-Id": "must-strip" },
  });
}

function makeCloudflareFixture(tokenEntitlements, basicEntitlements, runtimeOverrides = {}, originResponder = originResponseFor) {
  const calls = [];
  const cache = new MemoryCache();
  const environment = {
	...runtimeVariables(),
	...runtimeOverrides,
    SOW_TOKEN_ENTITLEMENTS: tokenEntitlements,
    SOW_BASIC_ENTITLEMENTS: basicEntitlements,
    ORIGIN: {
      async fetch(request) {
        const path = decodeURIComponent(new URL(request.url).pathname.slice(1));
        calls.push({ url: request.url, authorization: request.headers.get("Authorization"), ifMatch: request.headers.get("If-Match"), ifUnmodifiedSince: request.headers.get("If-Unmodified-Since") });
        return originResponder(path);
      },
    },
  };
  return {
    name: "cloudflare",
    calls,
    cache,
    handler: createCloudflareHandler(environment, { caches: { default: cache } }),
  };
}

function makeEdgeOneFixture(tokenEntitlements, basicEntitlements, runtimeOverrides = {}, originResponder = originResponseFor) {
  const calls = [];
  const cache = new MemoryCache();
	const environment = {
		...runtimeVariables(),
		...cosRuntimeVariables(),
		...runtimeOverrides,
    SOW_TOKEN_ENTITLEMENTS: tokenEntitlements,
    SOW_BASIC_ENTITLEMENTS: basicEntitlements,
  };
  const platform = deterministicEdgeOnePlatform(async (request) => {
      const path = decodeURIComponent(new URL(request.url).pathname.slice(1));
      calls.push({ url: request.url, authorization: request.headers.get("Authorization"), method: request.method, ifMatch: request.headers.get("If-Match"), ifUnmodifiedSince: request.headers.get("If-Unmodified-Since") });
      return originResponder(path);
    }, {
    caches: { default: cache },
  });
  return {
    name: "edgeone",
    calls,
    cache,
    handler: createEdgeOneHandler(environment, platform),
  };
}

test("Cloudflare and EdgeOne strip credentials onto the same clean origin URL without Cache API", async () => {
  for (const fixture of await vendorFixtures()) {
    const path = "/yum/infra/x86_64/Packages/p/pkg.rpm";
    const first = await fixture.handler(new Request(`https://repo.example/pro/v1/${tokenA}${path}`));
    assert.equal(first.status, 200, fixture.name);
    assert.match(await first.text(), /^origin:/, fixture.name);
    assert.equal(first.headers.get("Cache-Control"), "private, no-store, max-age=0", fixture.name);
    assert.equal(first.headers.has("X-Amz-Request-Id"), false, fixture.name);
    const callsAfterFirst = fixture.calls.length;

    const second = await fixture.handler(new Request(`https://repo.example/pro/v1/${tokenB}${path}`));
    assert.equal(second.status, 200, fixture.name);
    assert.equal(fixture.calls.length, callsAfterFirst + 1, `${fixture.name} unexpectedly used a manual Cache API`);
    assert.equal(fixture.calls.at(-1).url, fixture.calls.at(-2).url, `${fixture.name} tokens did not converge on one clean origin URL`);
    assert.equal(fixture.cache.keys.length, 0, `${fixture.name} touched the forbidden Cache API`);
    for (const call of fixture.calls) {
      assert.equal(call.url.includes(tokenA) || call.url.includes(tokenB), false, `${fixture.name} origin URL leaked token`);
      assert.notEqual(call.authorization, `Bearer ${tokenA}`, fixture.name);
      assert.notEqual(call.authorization, `Bearer ${tokenB}`, fixture.name);
    }
  }
});

test("both vendors route RPM caret bytes through one canonical URL spelling", async () => {
	const admission = routeAdmission({ asset_roots: ["pkg", "pkg^next"] });
	const runtime = {
		SOW_PUBLIC_PREFIXES: '["apt/infra","pkg","pkg^next","yum"]',
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(admission),
	};
	for (const fixture of await vendorFixtures(runtime)) {
		const literal = new Request("https://repo.example/pkg^next/tool-1.0^git.rpm");
		assert.equal(literal.url, "https://repo.example/pkg%5Enext/tool-1.0%5Egit.rpm", fixture.name);
		const response = await fixture.handler(literal);
		assert.equal(response.status, 200, fixture.name);
		assert.equal(await response.text(), "origin:pkg^next/tool-1.0^git.rpm", fixture.name);
		assert.equal(
			decodeURIComponent(new URL(fixture.calls.at(-1).url).pathname.slice(1)),
			"pkg^next/tool-1.0^git.rpm",
			fixture.name,
		);
		const gated = await fixture.handler(new Request(
			`https://repo.example/pro/v1/${tokenA}/pkg^next/tool-1.0^git.rpm`,
		));
		assert.equal(gated.status, 200, fixture.name);
		assert.equal(await gated.text(), "origin:.sow/gated/pkg^next/tool-1.0^git.rpm", fixture.name);
		assert.equal(
			decodeURIComponent(new URL(fixture.calls.at(-1).url).pathname.slice(1)),
			".sow/gated/pkg^next/tool-1.0^git.rpm",
			fixture.name,
		);

		for (const alias of [
			"pkg%5enext/tool.rpm",
			"pkg%255Enext/tool.rpm",
			"pkg%41next/tool.rpm",
			"pkg%2Fnext/tool.rpm",
			"pkg%5Enext/tool.rpm/",
		]) {
			const before = fixture.calls.length;
			const denied = await fixture.handler(new Request(`https://repo.example/${alias}`));
			assert.equal(denied.status, 404, `${fixture.name}/${alias}`);
			assert.equal(fixture.calls.length, before, `${fixture.name}/${alias} reached origin`);
		}
		const rawCaret = new Request("https://repo.example/pkg%5Enext/tool.rpm");
		Object.defineProperty(rawCaret, "url", { value: "https://repo.example/pkg^next/tool.rpm" });
		const beforeRawCaret = fixture.calls.length;
		const deniedRawCaret = await fixture.handler(rawCaret);
		assert.equal(deniedRawCaret.status, 404, `${fixture.name}/raw-caret`);
		assert.equal(fixture.calls.length, beforeRawCaret, `${fixture.name}/raw-caret reached origin`);
	}
});

test("WHATWG-normalized aliases re-enter final route and entitlement gates", async () => {
	const canonicalPath = "yum/infra/x86_64/Packages/p/pkg.rpm";
	const canonicalURL = `https://repo.example/${canonicalPath}`;
	const aliases = [
		"https://repo.example/pkg/%2e%2e/yum/infra/x86_64/Packages/p/pkg.rpm",
		String.raw`https://repo.example/pkg\..\yum\infra\x86_64\Packages\p\pkg.rpm`,
	];
	for (const fixture of await vendorFixtures()) {
		for (const alias of aliases) {
			const request = new Request(alias);
			assert.equal(request.url, canonicalURL, `${fixture.name}/${alias}`);
			const response = await fixture.handler(request);
			assert.equal(response.status, 200, `${fixture.name}/${alias}`);
			assert.equal(await response.text(), `origin:${canonicalPath}`, `${fixture.name}/${alias}`);
		}

		const deniedRequest = new Request("https://repo.example/pkg/%2e%2e/private/secret");
		assert.equal(deniedRequest.url, "https://repo.example/private/secret", fixture.name);
		const before = fixture.calls.length;
		const denied = await fixture.handler(deniedRequest);
		assert.equal(denied.status, 404, fixture.name);
		assert.equal(fixture.calls.length, before, `${fixture.name} normalized path bypassed the route allowlist`);
	}

	const scoped = { path_prefixes: ["/pkg"] };
	for (const fixture of await vendorFixtures({}, originResponseFor, scoped)) {
		const request = new Request(
			`https://repo.example/pro/v1/${tokenA}/pkg/%2e%2e/${canonicalPath}`,
		);
		assert.equal(request.url, `https://repo.example/pro/v1/${tokenA}/${canonicalPath}`, fixture.name);
		const before = fixture.calls.length;
		const denied = await fixture.handler(request);
		assert.equal(denied.status, 403, fixture.name);
		assert.equal(fixture.calls.length, before, `${fixture.name} normalized path bypassed entitlement scope`);
	}
});

test("both vendors deny undeclared root objects and unknown _sow routes before origin", async () => {
	for (const fixture of await vendorFixtures()) {
		for (const path of ["/sow.yaml", "/unknown-root/object", "/_sow/v1/private.json"]) {
			const before = fixture.calls.length;
			const anonymous = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(anonymous.status, 404, `${fixture.name} anonymous ${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name} touched origin for ${path}`);

			const entitled = await fixture.handler(new Request(`https://repo.example/pro/v1/${tokenA}${path}`));
			assert.equal(entitled.status, 404, `${fixture.name} pro ${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name} touched origin for Pro ${path}`);
		}
	}
});

test("root-exact asset-only deployments allow canonical empty prefixes without widening", async () => {
	const runtime = {
		SOW_PUBLIC_PREFIXES: "[]",
		SOW_PUBLIC_KEYS: '["get"]',
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({
			apt_roots: [], yum_repos: [], yum_roots: [], yum_channels: [], asset_roots: [], asset_keys: ["get"], snapshots: [],
		})),
	};
	for (const fixture of await vendorFixtures(runtime)) {
		for (const method of ["GET", "HEAD"]) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request("https://repo.example/get", { method }));
			assert.equal(response.status, 200, `${fixture.name}/${method}`);
			assert.equal(fixture.calls.length, before + 1, `${fixture.name}/${method} missed exact origin key`);
			if (method === "HEAD") assert.equal(await response.text(), "", fixture.name);
		}
		for (const path of ["/get/child", "/anything"]) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(response.status, 404, `${fixture.name}${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name}${path} reached origin`);
		}
	}
});

test("APT generation and snapshot payload routes reject unconfigured sibling ownership before origin", async () => {
	for (const fixture of await vendorFixtures()) {
		const paths = [
			"/_sow/v1/a/00000000000000000042/apt/sibling/dists/bookworm/InRelease",
			`/pro/v1/${tokenA}/_sow/v1/snapshots/jammy-20260712/apt/apt/sibling/dists/bookworm/InRelease`,
			`/pro/v1/${tokenA}/_sow/v1/snapshots/jammy-20260712/yum/yum/sibling/x86_64/repodata/repomd.xml`,
			`/pro/v1/${tokenA}/_sow/v1/snapshots/jammy-20260712/assets/sibling/tool.tar.gz`,
		];
		for (const path of paths) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(response.status, 404, `${fixture.name}${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name}${path} reached origin or snapshot pointer`);
		}
	}
});

test("per-snapshot inventory retains an EOL root without admitting it to a sibling snapshot", async () => {
	const eol = {
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({
			snapshots: [{ id: "jammy-20260712", apt_roots: [], yum_roots: [], asset_roots: ["archive/eol"], asset_keys: [] }],
		})),
	};
	for (const fixture of await vendorFixtures(eol)) {
		const retained = await fixture.handler(new Request(
			`https://repo.example/pro/v1/${tokenA}/_sow/v1/snapshots/jammy-20260712/assets/archive/eol/tool.tgz`,
		));
		assert.equal(retained.status, 200, fixture.name);
		assert.equal(await retained.text(), "origin:.sow/gated/snapshots/jammy-20260712/asset/archive/eol/tool.tgz", fixture.name);
		for (const path of [
			`/pro/v1/${tokenA}/_sow/v1/snapshots/jammy-20260712/assets/archive/sibling/tool.tgz`,
			`/pro/v1/${tokenA}/_sow/v1/snapshots/other-20260712/assets/archive/eol/tool.tgz`,
		]) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(response.status, 404, `${fixture.name}${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name}${path} reached origin`);
		}
	}
});

test("snapshot control routes require an exact admitted snapshot ID before reading origin", async () => {
	for (const fixture of await vendorFixtures()) {
		const admitted = "jammy-20260712";
		const beforeAdmitted = fixture.calls.length;
		const response = await fixture.handler(new Request(
			`https://repo.example/pro/v1/${tokenA}/_sow/v1/snapshots/${admitted}/_route.json`,
		));
		assert.equal(response.status, 200, `${fixture.name}/${admitted}`);
		assert.equal(JSON.parse(await response.text()).snapshot, admitted, `${fixture.name}/${admitted}`);
		assert.deepEqual(
			fixture.calls.slice(beforeAdmitted).map((call) => decodeURIComponent(new URL(call.url).pathname.slice(1))),
			[`.sow/snapshots/${admitted}.json`, `.sow/snapshots/${admitted}.json`],
			`${fixture.name}/${admitted}`,
		);

		for (const denied of ["sibling-20260712", "unknown-20260712"]) {
			const beforeDenied = fixture.calls.length;
			const rejected = await fixture.handler(new Request(
				`https://repo.example/pro/v1/${tokenA}/_sow/v1/snapshots/${denied}/_route.json`,
			));
			assert.equal(rejected.status, 404, `${fixture.name}/${denied}`);
			assert.equal(fixture.calls.length, beforeDenied, `${fixture.name}/${denied} read snapshot or origin`);
		}
	}
});

test("both vendors serve only exact target-owned compatibility trust keys for GET and HEAD", async () => {
	const admission = {
		SOW_PUBLIC_PREFIXES: '["apt/infra","pkg","yum/infra/x86_64"]',
		SOW_PUBLIC_KEYS: '["_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp","_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp","keys/test-package-trust.asc"]',
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({
			yum_repos: [], yum_roots: [], yum_channels: [],
			projections: [{ id: "infra-legacy-x86-64", root: "yum/infra/x86_64", view: "latest", os: "cross-el", arch: "x86_64" }],
			raw: ["infra-legacy-x86-64"], active: ["infra-legacy-x86-64"],
		})),
	};
	const exact = [
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp",
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp",
	];
	const denied = [
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp.bak",
		"/_sow/v1/trust/yum-compat/infra-legacy-aarch64/repository.pgp",
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64",
	];
	for (const fixture of await vendorFixtures(admission)) {
		for (const path of exact) {
			for (const method of ["GET", "HEAD"]) {
				const before = fixture.calls.length;
				const response = await fixture.handler(new Request(`https://repo.example${path}`, { method }));
				assert.equal(response.status, 200, `${fixture.name} ${method} ${path}`);
				assert.equal(fixture.calls.length, before + 1, `${fixture.name} did not fetch exact trust key`);
				assert.equal(decodeURIComponent(new URL(fixture.calls.at(-1).url).pathname), path, `${fixture.name} routed a different trust key`);
				if (method === "HEAD") assert.equal(await response.text(), "", `${fixture.name} returned a HEAD body`);
			}
		}
		for (const path of denied) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(response.status, 404, `${fixture.name} exposed ${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name} touched origin for denied trust path`);
		}
	}
});

test("both vendors preserve positive HTTP preconditions on credential-free origin requests", async () => {
	for (const fixture of await vendorFixtures()) {
		const path = "/yum/infra/x86_64/Packages/p/pkg.rpm";
		const response = await fixture.handler(new Request(`https://repo.example/pro/v1/${tokenA}${path}`, {
			headers: { "If-Match": '"package-etag"', "If-Unmodified-Since": "Mon, 13 Jul 2026 00:00:00 GMT" },
		}));
		assert.equal(response.status, 200, fixture.name);
		const call = fixture.calls.at(-1);
		assert.equal(call.ifMatch, '"package-etag"', fixture.name);
		assert.equal(call.ifUnmodifiedSince, "Mon, 13 Jul 2026 00:00:00 GMT", fixture.name);
		assert.equal(call.url.includes(tokenA), false, fixture.name);
	}
});

test("both vendors retain an explicit same-host https-bearer topology interface for the external cache PoC", async () => {
  const tokenEntitlements = JSON.stringify([entitlement(await sha256Hex(tokenA)), entitlement(await sha256Hex(tokenB))]);
  for (const vendor of ["cloudflare", "edgeone"]) {
    const calls = [];
    const seen = new Map();
    const originFetch = async (request) => {
      const url = new URL(request.url);
      const key = decodeURIComponent(url.pathname.slice(1));
      const count = seen.get(request.url) || 0;
      seen.set(request.url, count + 1);
      calls.push({ url: request.url, authorization: request.headers.get("Authorization") });
      if (key.startsWith(".sow/gated/")) return new Response("not found\n", { status: 404 });
      const cacheHeader = count === 0 ? "MISS" : "HIT";
		return new Response(`origin:${key}`, { headers: {
			[vendor === "cloudflare" ? "CF-Cache-Status" : "EO-Cache-Status"]: cacheHeader,
			Age: "12", "Cache-Control": "public, max-age=300",
		} });
    };
    const environment = {
      ...runtimeVariables(),
      SOW_ORIGIN_MODE: "https-bearer",
      SOW_ORIGIN_BASE_URL: "https://repo.example",
      SOW_BETA_ORIGIN_BASE_URL: "https://beta.example",
      SOW_ORIGIN_BEARER: "origin-service-contract-secret",
      SOW_TOKEN_ENTITLEMENTS: tokenEntitlements,
      SOW_BASIC_ENTITLEMENTS: "[]",
    };
    const handler = vendor === "cloudflare"
      ? createCloudflareHandler(environment, { fetch: originFetch })
      : createEdgeOneHandler(environment, deterministicEdgeOnePlatform(originFetch));
    const path = "yum/infra/x86_64/Packages/p/pkg.rpm";
    const first = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/${path}`));
    const firstDigest = first.headers.get("X-SOW-Clean-URL-SHA256");
    assert.equal(first.status, 200, vendor);
    assert.equal(first.headers.get("X-SOW-Origin-Transport"), "https-bearer", vendor);
    assert.equal(first.headers.get("X-SOW-Origin-Cache-Status"), "MISS", vendor);
    const second = await handler(new Request(`https://repo.example/pro/v1/${tokenB}/${path}`));
    assert.equal(second.status, 200, vendor);
		assert.equal(second.headers.get("X-SOW-Origin-Cache-Status"), "HIT", vendor);
		assert.equal(second.headers.get("X-SOW-Origin-Cache-Age"), "12", vendor);
		assert.equal(second.headers.get("X-SOW-Origin-Cache-Max-Age"), "300", vendor);
    assert.equal(second.headers.get("X-SOW-Clean-URL-SHA256"), firstDigest, vendor);
    assert.equal(calls.at(-1).url, calls.at(-3).url, `${vendor} token paths did not converge on the public fallback key`);
    for (const call of calls) {
      assert.equal(new URL(call.url).origin, "https://repo.example", vendor);
      assert.equal(call.url.includes(tokenA) || call.url.includes(tokenB), false, vendor);
      assert.equal(call.authorization, "Bearer origin-service-contract-secret", vendor);
    }
  }
});

test("https-bearer keeps an entire beta fallback group on the beta host for both vendors", async () => {
  for (const vendor of ["cloudflare", "edgeone"]) {
    const calls = [];
    const originFetch = async (request) => {
      calls.push(request.url);
      const key = decodeURIComponent(new URL(request.url).pathname.slice(1));
      if (key.startsWith(".sow/beta/")) return new Response("not found\n", { status: 404 });
      return new Response(`origin:${key}`, { headers: { [vendor === "cloudflare" ? "CF-Cache-Status" : "EO-Cache-Status"]: "MISS" } });
    };
    const environment = {
      ...runtimeVariables(),
      SOW_ORIGIN_MODE: "https-bearer",
      SOW_ORIGIN_BASE_URL: "https://repo.example",
      SOW_BETA_ORIGIN_BASE_URL: "https://beta.example",
      SOW_ORIGIN_BEARER: "origin-service-contract-secret",
      SOW_TOKEN_ENTITLEMENTS: "[]",
      SOW_BASIC_ENTITLEMENTS: "[]",
    };
    const handler = vendor === "cloudflare"
      ? createCloudflareHandler(environment, { fetch: originFetch })
      : createEdgeOneHandler(environment, deterministicEdgeOnePlatform(originFetch));
    const path = "yum/infra/x86_64/Packages/p/pkg.rpm";
    const response = await handler(new Request(`https://beta.example/${path}`));
    assert.equal(response.status, 200, vendor);
    assert.equal(await response.text(), `origin:${path}`, vendor);
    assert.deepEqual(calls.map((rawURL) => new URL(rawURL).origin), ["https://beta.example", "https://beta.example"], vendor);
    assert.deepEqual(calls.map((rawURL) => decodeURIComponent(new URL(rawURL).pathname.slice(1))), [`.sow/beta/${path}`, path], vendor);

	  calls.splice(0);
	  const generation = "00000000000000000042";
	  const aptGeneration = await handler(new Request(`https://beta.example/_sow/v1/a/${generation}/apt/infra/dists/jammy/InRelease`));
	  assert.equal(aptGeneration.status, 200, vendor);
	  assert.deepEqual(calls.map((rawURL) => new URL(rawURL).origin), ["https://beta.example"], `${vendor}/beta-generation`);
	  assert.equal(decodeURIComponent(new URL(calls[0]).pathname.slice(1)), `.sow/generations/${generation}/apt/apt/infra/dists/jammy/InRelease`, vendor);

	  calls.splice(0);
	  const mirrorlist = await handler(new Request("https://beta.example/_sow/v1/mirrorlist/beta/infra/el9/x86_64.txt"));
	  assert.equal(mirrorlist.status, 200, vendor);
	  assert.deepEqual(calls.map((rawURL) => new URL(rawURL).origin), ["https://beta.example"], `${vendor}/beta-mirrorlist`);
	  assert.equal(decodeURIComponent(new URL(calls[0]).pathname.slice(1)), "_sow/v1/mirrorlist/beta/infra/el9/x86_64.txt", vendor);

    for (const [name, value] of [["SOW_ORIGIN_BASE_URL", "https://attacker.example"], ["SOW_BETA_ORIGIN_BASE_URL", "https://attacker.example"]]) {
      const invalid = { ...environment, [name]: value };
      assert.throws(
        () => vendor === "cloudflare" ? createCloudflareHandler(invalid, { fetch: originFetch }) : createEdgeOneHandler(invalid, deterministicEdgeOnePlatform(originFetch)),
        /must equal its declared public serving origin/,
        `${vendor}/${name}`,
      );
    }
  }
});

test("EdgeOne keeps scheme-shaped anonymous, token, and Basic keys on the private HTTPS origin", async () => {
  const tokenEntitlements = JSON.stringify([entitlement(await sha256Hex(tokenA))]);
  const basicEntitlements = JSON.stringify([entitlement(await sha256Hex(basicValue))]);
	const environment = {
		...runtimeVariables(),
		...cosRuntimeVariables(),
		SOW_PUBLIC_PREFIXES: '["file:etc","ftp:attacker.example","http:attacker.example","https:attacker.example"]',
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({
			apt_roots: [], yum_repos: [], yum_roots: [], yum_channels: [], asset_roots: [], asset_keys: [], snapshots: [],
		})),
    SOW_TOKEN_ENTITLEMENTS: tokenEntitlements,
    SOW_BASIC_ENTITLEMENTS: basicEntitlements,
  };
  const calls = [];
  const handler = createEdgeOneHandler(environment, deterministicEdgeOnePlatform(async (request) => {
      calls.push({
        url: request.url,
        authorization: request.headers.get("Authorization"),
      });
      return new Response("not found\n", { status: 404 });
    }));
  const basic = btoa(basicValue);
  const schemeShapedKeys = ["http:attacker.example", "https:attacker.example", "ftp:attacker.example", "file:etc"];
  for (const key of schemeShapedKeys) {
    const requests = [
      new Request(`https://repo.example/${key}`),
      new Request(`https://repo.example/pro/v1/${tokenA}/${key}`),
      new Request(`https://repo.example/pro/v1/basic/${key}`, { headers: { Authorization: `Basic ${basic}` } }),
    ];
    for (const request of requests) {
      const response = await handler(request);
      assert.equal(response.status, 404, request.url);
    }
  }
  assert.ok(calls.length > schemeShapedKeys.length, "Pro fallbacks were not exercised");
  for (const call of calls) {
    const url = new URL(call.url);
    assert.equal(url.protocol, "https:", call.url);
    assert.equal(url.origin, "https://sow-contract-1250000000.cos.ap-guangzhou.myqcloud.com", call.url);
		assert.match(call.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE0123456789012345\//, call.url);
		assert.equal(call.authorization.includes("cos-secret-key-for-contract-tests-only"), false, call.url);
    assert.equal(call.url.includes(tokenA), false, call.url);
    assert.notEqual(call.authorization, `Basic ${basic}`, call.url);
  }
});

test("EdgeOne signs Range and HEAD only for the derived COS host and rejects redirects without leaking origin authorization", async () => {
  const environment = {
    ...runtimeVariables(),
    ...cosRuntimeVariables(),
    SOW_COS_SESSION_TOKEN: "temporary-session-token-for-contract-test",
    SOW_TOKEN_ENTITLEMENTS: JSON.stringify([entitlement(await sha256Hex(tokenA))]),
    SOW_BASIC_ENTITLEMENTS: "[]",
  };
  const calls = [];
  let redirect = false;
  const handler = createEdgeOneHandler(environment, deterministicEdgeOnePlatform(async (request) => {
    calls.push(request);
    if (redirect) {
      return new Response(null, { status: 307, headers: { Location: "https://attacker.example/collect" } });
    }
    if (decodeURIComponent(new URL(request.url).pathname).startsWith("/.sow/gated/")) {
      return new Response("not found\n", { status: 404 });
    }
    const reflectedAuthorization = request.headers.get("Authorization");
    return new Response(request.method === "HEAD" ? null : "partial-object", {
      status: request.headers.has("Range") ? 206 : 200,
      headers: {
        Authorization: reflectedAuthorization,
        "X-Cos-Session-Token": request.headers.get("x-amz-security-token"),
        "Content-Range": "bytes 5-10/11",
      },
    });
  }));
  const path = "yum/infra/x86_64/Packages/p/pkg.rpm";
  const ranged = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/${path}`, { headers: { Range: "bytes=5-10" } }));
  assert.equal(ranged.status, 206);
  assert.equal(await ranged.text(), "partial-object");
  assert.equal(ranged.headers.get("X-SOW-Origin-Transport"), "cos-sigv4");
  assert.equal(ranged.headers.get("X-SOW-Origin-Cache-Status"), "BYPASS");
  assert.equal(ranged.headers.has("Authorization"), false);
  assert.equal(ranged.headers.has("X-Cos-Session-Token"), false);
  const signedRange = calls.at(-1);
  assert.equal(signedRange.url, `https://sow-contract-1250000000.cos.ap-guangzhou.myqcloud.com/${path}`);
  assert.equal(calls.at(-2).url, `https://sow-contract-1250000000.cos.ap-guangzhou.myqcloud.com/.sow/gated/${path}`);
  assert.equal(signedRange.headers.get("Range"), "bytes=5-10");
  assert.match(signedRange.headers.get("Authorization"), /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE0123456789012345\/20260712\/ap-guangzhou\/s3\/aws4_request,/);
  assert.match(signedRange.headers.get("Authorization"), /Signature=5fb42681582002c92007c674a4d94b5c6f906f6b846dcf22cf6c792c496c2635$/);
  assert.equal(signedRange.headers.get("Authorization").includes("cos-secret-key-for-contract-tests-only"), false);
  assert.equal(signedRange.headers.get("x-amz-security-token"), "temporary-session-token-for-contract-test");
  assert.equal([...signedRange.headers.values()].some((value) => value.includes(tokenA)), false);

  const head = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/${path}`, { method: "HEAD" }));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
  assert.equal(calls.at(-1).method, "HEAD");

  redirect = true;
  const beforeRedirect = calls.length;
  const redirected = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/${path}`));
  assert.equal(redirected.status, 502);
  assert.equal(redirected.headers.get("Cache-Control"), "private, no-store, max-age=0");
  assert.equal(redirected.headers.has("Location"), false);
  assert.equal(calls.length, beforeRedirect + 1, "manual redirect followed a non-COS Location");
  assert.equal(new URL(calls.at(-1).url).hostname.endsWith(".cos.ap-guangzhou.myqcloud.com"), true);

  let origins = 0;
  for (const invalid of [
    { ...environment, SOW_COS_REGION: "ap-guangzhou.attacker.example" },
    { ...environment, SOW_COS_BUCKET: "bucket.attacker.example-1250000000" },
    { ...environment, SOW_COS_SECRET_KEY: "short" },
  ]) {
    assert.throws(() => createEdgeOneHandler(invalid, deterministicEdgeOnePlatform(async () => { origins += 1; return new Response("unexpected"); })), /COS|SECRET/);
  }
  assert.equal(origins, 0);
});

test("beta host is a distinct metadata view while package bodies remain shared", async () => {
	for (const fixture of await vendorFixtures()) {
		const metadata = await fixture.handler(new Request("https://beta.example/apt/infra/dists/bookworm/InRelease"));
		assert.equal(metadata.status, 200, fixture.name);
		assert.equal(await metadata.text(), "origin:.sow/beta/apt/infra/dists/bookworm/InRelease", fixture.name);

		const pkg = await fixture.handler(new Request("https://beta.example/yum/infra/x86_64/Packages/p/pkg.rpm"));
		assert.equal(pkg.status, 200, fixture.name);
		assert.equal(await pkg.text(), "origin:yum/infra/x86_64/Packages/p/pkg.rpm", fixture.name);
		const deb = await fixture.handler(new Request("https://beta.example/apt/infra/pool/main/p/pkg/pkg.deb"));
		assert.equal(deb.status, 200, fixture.name);
		assert.equal(await deb.text(), "origin:apt/infra/pool/main/p/pkg/pkg.deb", fixture.name);

		const latest = await fixture.handler(new Request("https://repo.example/apt/infra/dists/bookworm/InRelease"));
		assert.equal(await latest.text(), "origin:apt/infra/dists/bookworm/InRelease", fixture.name);
		const wrongMirror = await fixture.handler(new Request("https://repo.example/_sow/v1/mirrorlist/beta/infra/el9/x86_64.txt"));
		assert.equal(wrongMirror.status, 404, fixture.name);
	}
});

test("beta removals never fall through to latest asset or repository metadata", async () => {
	const paths = [
		"apt/infra/dists/bookworm/Release",
		"yum/infra/x86_64/repodata/repomd.xml",
		"pkg/removed-tool",
		"pkg/Packages/p/package-shaped-asset.rpm",
	];
	for (const fixture of await vendorFixtures()) {
		for (const path of paths) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(`https://beta.example/${path}`));
			assert.equal(response.status, 404, `${fixture.name}/${path}`);
			const routed = fixture.calls.slice(before).map((call) => new URL(call.url).pathname.slice(1));
			assert.deepEqual(routed, [`.sow/beta/${path}`], `${fixture.name}/${path} escaped the beta namespace`);
		}
	}
});

test("both vendors authenticate before origin and return identical status classes", async () => {
  for (const fixture of await vendorFixtures()) {
    const before = fixture.calls.length;
    const invalid = await fixture.handler(new Request(`https://repo.example/pro/v1/${invalidToken}/yum/infra/file`));
    assert.equal(invalid.status, 401, fixture.name);
    assert.equal(invalid.headers.get("Cache-Control"), "private, no-store, max-age=0", fixture.name);
    assert.equal((await invalid.text()).includes(invalidToken), false, fixture.name);
    assert.equal(fixture.calls.length, before, `${fixture.name} touched origin before authentication`);

    const malformed = await fixture.handler(new Request("https://repo.example/pro/v1/short/yum/infra/file"));
    assert.equal(malformed.status, 401, fixture.name);
    const method = await fixture.handler(new Request("https://repo.example/yum/infra/file", { method: "POST" }));
    assert.equal(method.status, 405, fixture.name);
    const control = await fixture.handler(new Request("https://repo.example/.sow/manifest.json"));
    assert.equal(control.status, 404, fixture.name);
    const encoded = await fixture.handler(new Request("https://repo.example/yum/%2e%2e/.sow/manifest.json"));
    assert.equal(encoded.status, 404, fixture.name);
    const query = await fixture.handler(new Request("https://repo.example/yum/file?token=forbidden"));
    assert.equal(query.status, 404, fixture.name);
  }
});

test("both vendors expose the exact anonymous pre-upload confidentiality denial", async () => {
  for (const fixture of await vendorFixtures()) {
    const before = fixture.calls.length;
    const response = await fixture.handler(new Request(
      "https://repo.example/.sow/gated/.sow-confidentiality-preflight",
      { headers: { Cookie: "ambient-session=must-not-authorize" } },
    ));
    assert.equal(response.status, 404, fixture.name);
    assert.equal(response.headers.get("X-SOW-Edge-Contract"), "sow-edge-runtime/v2", fixture.name);
    assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0", fixture.name);
    assert.equal(response.headers.get("Content-Type"), "text/plain; charset=utf-8", fixture.name);
    assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff", fixture.name);
    assert.equal(response.headers.get("WWW-Authenticate"), null, fixture.name);
    assert.equal(response.headers.get("X-SOW-Origin-Transport"), null, fixture.name);
    assert.equal(await response.text(), "not_found\n", fixture.name);
    assert.equal(fixture.calls.length, before, `${fixture.name} touched origin for the confidentiality canary`);
  }
});

test("dynamic mirrorlists inject only the authorized credential and pin one generation", async () => {
  for (const fixture of await vendorFixtures()) {
    const request = new Request(`https://repo.example/pro/v1/${tokenA}/_sow/v1/mirrorlist/stable/infra/el9/x86_64.txt`);
    const response = await fixture.handler(request);
    assert.equal(response.status, 200, fixture.name);
    assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0", fixture.name);
    assert.equal(
      await response.text(),
      `https://repo.example/pro/v1/${tokenA}/_sow/v1/g/00000000000000000042/yum/infra/x86_64/\n`,
      fixture.name,
    );
    const publicResponse = await fixture.handler(new Request("https://repo.example/_sow/v1/mirrorlist/latest/infra/el9/x86_64.txt"));
    assert.equal(publicResponse.status, 200, fixture.name);
    assert.equal(
      await publicResponse.text(),
      "https://repo.example/_sow/v1/g/00000000000000000042/yum/infra/x86_64/\n",
      fixture.name,
    );
	assert.equal(fixture.calls.at(-1).url.endsWith("/_sow/v1/mirrorlist/latest/infra/el9/x86_64.txt"), true, `${fixture.name} did not fetch the static latest mirrorlist`);
	const betaResponse = await fixture.handler(new Request("https://beta.example/_sow/v1/mirrorlist/beta/infra/el9/x86_64.txt"));
	assert.equal(betaResponse.status, 200, fixture.name);
	assert.equal(
	  await betaResponse.text(),
	  "https://beta.example/_sow/v1/g/00000000000000000042/yum/infra/x86_64/\n",
	  fixture.name,
	);
	assert.equal(fixture.calls.at(-1).url.endsWith("/_sow/v1/mirrorlist/beta/infra/el9/x86_64.txt"), true, `${fixture.name} did not fetch the static beta mirrorlist`);
    for (const call of fixture.calls) {
      assert.equal(call.url.includes(tokenA), false, `${fixture.name} mirrorlist lookup leaked token`);
    }
  }
});

test("dynamic mirrorlists serialize caret roots canonically for token and Basic on both vendors", async () => {
  const legacyRoot = "yum/infra^next/x86_64";
  const runtime = {
    SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({
      yum_roots: [legacyRoot],
      yum_channels: runtimeRouteAdmission.yum_channels.map((channel) => ({
        ...channel,
        root: legacyRoot,
      })),
    })),
  };
  const originResponder = (path) => path.startsWith(".sow/channels/")
    ? new Response(JSON.stringify({ generation: "42", legacy_root: legacyRoot }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
    : originResponseFor(path);
  const credentials = [
    { name: "token", prefix: `https://repo.example/pro/v1/${tokenA}`, headers: undefined },
    { name: "basic", prefix: "https://repo.example/pro/v1/basic", headers: { Authorization: `Basic ${btoa(basicValue)}` } },
  ];

  for (const fixture of await vendorFixtures(runtime, originResponder)) {
    for (const credential of credentials) {
      const response = await fixture.handler(new Request(
        `${credential.prefix}/_sow/v1/mirrorlist/stable/infra/el9/x86_64.txt`,
        { headers: credential.headers },
      ));
      assert.equal(response.status, 200, `${fixture.name}/${credential.name}`);
      const body = await response.text();
      assert.equal(
        body,
        `${credential.prefix}/_sow/v1/g/00000000000000000042/yum/infra%5Enext/x86_64/\n`,
        `${fixture.name}/${credential.name}`,
      );
      assert.equal(body.includes("^"), false, `${fixture.name}/${credential.name} emitted a raw caret`);
      assert.equal(new URL(body.trim()).pathname.includes("%5E"), true, `${fixture.name}/${credential.name}`);
    }
  }
});

test("dynamic ordinary and compatibility mirrorlists reject cross-root channel drift", async () => {
	const id = "infra-legacy-x86-64";
	const root = "yum/infra/x86_64";
	const runtime = {
		SOW_PUBLIC_PREFIXES: JSON.stringify(["apt/infra", "pkg", root]),
		SOW_PUBLIC_KEYS: JSON.stringify([
			`_sow/v1/trust/yum-compat/${id}/packages.pgp`,
			`_sow/v1/trust/yum-compat/${id}/repository.pgp`,
			"keys/test-package-trust.asc",
		]),
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({
			projections: [{ id, root, view: "latest", os: "cross-el", arch: "x86_64" }],
			raw: [id],
			active: [id],
		})),
	};
	const driftedOrigin = (path) => path.startsWith(".sow/channels/")
		? new Response(JSON.stringify({ generation: "42", legacy_root: "yum/sibling/x86_64" }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		})
		: originResponseFor(path);
	for (const fixture of await vendorFixtures(runtime, driftedOrigin)) {
		for (const coordinate of ["stable/infra/el9/x86_64", `latest/${id}/cross-el/x86_64`]) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(
				`https://repo.example/pro/v1/${tokenA}/_sow/v1/mirrorlist/${coordinate}.txt`,
			));
			assert.equal(response.status, 503, `${fixture.name}/${coordinate}`);
			assert.doesNotMatch(await response.text(), /yum\/sibling/, `${fixture.name}/${coordinate}`);
			const calls = fixture.calls.slice(before).map((call) => decodeURIComponent(new URL(call.url).pathname.slice(1)));
			assert.equal(calls.length, 1, `${fixture.name}/${coordinate} followed a drifted root`);
			assert.match(calls[0], /^\.sow\/channels\//, `${fixture.name}/${coordinate}`);
		}
	}
});

test("generation routing pins repodata while sharing package bodies", async () => {
  for (const fixture of await vendorFixtures()) {
    const generation = "00000000000000000042";
    const metadata = await fixture.handler(new Request(`https://repo.example/_sow/v1/g/${generation}/yum/infra/x86_64/repodata/repomd.xml`));
    assert.equal(metadata.status, 200, fixture.name);
    assert.equal(
      await metadata.text(),
	  `origin:.sow/generations/${generation}/yum/yum/infra/x86_64/repodata/repomd.xml`,
      fixture.name,
    );
	const betaMetadata = await fixture.handler(new Request(`https://beta.example/_sow/v1/g/${generation}/yum/infra/x86_64/repodata/repomd.xml`));
	assert.equal(
		await betaMetadata.text(),
		`origin:.sow/generations/${generation}/yum/yum/infra/x86_64/repodata/repomd.xml`,
		fixture.name,
	);
    const pkg = await fixture.handler(new Request(`https://repo.example/pro/v1/${tokenA}/_sow/v1/g/${generation}/yum/infra/x86_64/Packages/p/pkg.rpm`));
    assert.equal(pkg.status, 200, fixture.name);
    assert.equal(await pkg.text(), "origin:.sow/gated/yum/infra/x86_64/Packages/p/pkg.rpm", fixture.name);
	for (const suffix of ["pkg.rpm", "Packages/p/pkg.rpm/hidden", "Packages/pp/pkg.rpm", "repodata/nested/hidden.xml.gz"]) {
		const before = fixture.calls.length;
		const denied = await fixture.handler(new Request(`https://repo.example/_sow/v1/g/${generation}/yum/infra/x86_64/${suffix}`));
		assert.equal(denied.status, 404, `${fixture.name}/${suffix}`);
		assert.equal(fixture.calls.length, before, `${fixture.name}/${suffix} reached origin`);
	}
  }
});

test("compatibility raw and active admission are state-separated on both vendors", async () => {
	const id = "infra-legacy-x86-64";
	const root = "yum/infra/x86_64";
	const projection = { id, root, view: "latest", os: "cross-el", arch: "x86_64" };
	const prefixes = JSON.stringify(["apt/infra", "pkg", root]);
	const base = {
		SOW_PUBLIC_PREFIXES: prefixes,
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({ yum_repos: [], yum_roots: [], yum_channels: [], projections: [projection], raw: [id], active: [] })),
	};
	for (const fixture of await vendorFixtures(base)) {
		const raw = await fixture.handler(new Request(`https://repo.example/${root}/legacy.rpm`));
		assert.equal(raw.status, 200, `${fixture.name}/raw`);
		for (const path of [
			`/_sow/v1/g/00000000000000000042/${root}/repodata/repomd.xml`,
			`/_sow/v1/mirrorlist/latest/${id}/cross-el/x86_64.txt`,
			`/_sow/v1/trust/yum-compat/${id}/packages.pgp`,
		]) {
			const before = fixture.calls.length;
			const denied = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(denied.status, 404, `${fixture.name}/inactive/${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name}/inactive reached origin`);
		}
	}
	const active = {
		...base,
		SOW_PUBLIC_KEYS: JSON.stringify([
			`_sow/v1/trust/yum-compat/${id}/packages.pgp`,
			`_sow/v1/trust/yum-compat/${id}/repository.pgp`,
			"keys/test-package-trust.asc",
		]),
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({ yum_repos: [], yum_roots: [], yum_channels: [], projections: [projection], raw: [id], active: [id] })),
	};
	for (const fixture of await vendorFixtures(active)) {
		for (const path of [
			`/_sow/v1/g/00000000000000000042/${root}/repodata/repomd.xml`,
			`/_sow/v1/mirrorlist/latest/${id}/cross-el/x86_64.txt`,
			`/_sow/v1/trust/yum-compat/${id}/packages.pgp`,
		]) {
			const response = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(response.status, 200, `${fixture.name}/active/${path}`);
		}
		for (const path of [
			`/_sow/v1/mirrorlist/beta/${id}/cross-el/x86_64.txt`,
			`/_sow/v1/mirrorlist/latest/${id}/el9/x86_64.txt`,
			`/_sow/v1/mirrorlist/latest/${id}/cross-el/aarch64.txt`,
		]) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(response.status, 404, `${fixture.name}/wrong-coordinate/${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name}/wrong-coordinate reached origin`);
		}
		const dynamic = await fixture.handler(new Request(
			`https://repo.example/pro/v1/${tokenA}/_sow/v1/mirrorlist/latest/${id}/cross-el/x86_64.txt`,
		));
		assert.equal(dynamic.status, 200, `${fixture.name}/dynamic`);
		assert.equal(
			await dynamic.text(),
			`https://repo.example/pro/v1/${tokenA}/_sow/v1/g/00000000000000000042/${root}/\n`,
			`${fixture.name}/dynamic`,
		);
	}
});

test("ordinary mirrorlists require an exact configured view, OS, and architecture before origin", async () => {
	for (const fixture of await vendorFixtures()) {
		for (const path of [
			`/pro/v1/${tokenA}/_sow/v1/mirrorlist/preview/infra/el9/x86_64.txt`,
			`/pro/v1/${tokenA}/_sow/v1/mirrorlist/stable/infra/el10/x86_64.txt`,
			`/pro/v1/${tokenA}/_sow/v1/mirrorlist/stable/infra/el9/aarch64.txt`,
			`/pro/v1/${tokenA}/_sow/v1/mirrorlist/stable/unknown/el9/x86_64.txt`,
		]) {
			const before = fixture.calls.length;
			const response = await fixture.handler(new Request(`https://repo.example${path}`));
			assert.equal(response.status, 404, `${fixture.name}${path}`);
			assert.equal(fixture.calls.length, before, `${fixture.name}${path} reached channel origin`);
		}
	}
});

test("a resolved mirrorlist keeps the signed YUM pair on one immutable generation across a channel flip", async () => {
	let activeGeneration = 42;
	const originKeys = [];
	const handler = createSowEdgeHandler({
		verifyToken: async () => ({ status: "ok" }),
		verifyBasic: async () => ({ status: "ok" }),
		readChannel: async () => ({ generation: activeGeneration, legacy_root: "yum/infra/x86_64" }),
		fetchOrigin: async ({ keys }) => {
			originKeys.push(keys[0]);
			return new Response(`origin:${keys[0]}`);
		},
		publicBaseURL: "https://repo.example",
		betaBaseURL: "https://beta.example",
		publicPrefixes: ["apt/infra", "pkg", "yum"],
		publicKeys: ["keys/test-package-trust.asc"],
		compatibility: routeAdmission(),
	});

	const mirrorRequest = new Request(`https://repo.example/pro/v1/${tokenA}/_sow/v1/mirrorlist/stable/infra/el9/x86_64.txt`);
	const oldMirror = await handler(mirrorRequest);
	const oldBase = (await oldMirror.text()).trim();
	assert.equal(oldBase, `https://repo.example/pro/v1/${tokenA}/_sow/v1/g/00000000000000000042/yum/infra/x86_64/`);

	activeGeneration = 43;
	for (const name of ["repomd.xml", "repomd.xml.asc"]) {
		const response = await handler(new Request(`${oldBase}repodata/${name}`));
		assert.equal(
			await response.text(),
			`origin:.sow/gated/generations/00000000000000000042/yum/yum/infra/x86_64/repodata/${name}`,
			name,
		);
	}
	const newMirror = await handler(mirrorRequest);
	assert.match(await newMirror.text(), /_sow\/v1\/g\/00000000000000000043\//);
	assert.equal(originKeys.some((key) => key.includes("00000000000000000043") && key.includes("repomd")), false);
});

test("APT generation evidence is addressable only through its clean generation route", async () => {
	for (const fixture of await vendorFixtures()) {
		const generation = "00000000000000000042";
		const publicAPT = await fixture.handler(new Request(`https://repo.example/_sow/v1/a/${generation}/apt/infra/dists/bookworm/InRelease`));
		assert.equal(await publicAPT.text(), `origin:.sow/generations/${generation}/apt/apt/infra/dists/bookworm/InRelease`, fixture.name);
		const betaAPT = await fixture.handler(new Request(`https://beta.example/_sow/v1/a/${generation}/apt/infra/dists/bookworm/InRelease`));
		assert.equal(await betaAPT.text(), `origin:.sow/generations/${generation}/apt/apt/infra/dists/bookworm/InRelease`, fixture.name);
		const encoded = btoa(basicValue);
		const proAPT = await fixture.handler(new Request(`https://repo.example/pro/v1/basic/_sow/v1/a/${generation}/apt/infra/dists/bookworm/InRelease`, {
			headers: { Authorization: `Basic ${encoded}` },
		}));
		assert.equal(await proAPT.text(), `origin:.sow/gated/generations/${generation}/apt/apt/infra/dists/bookworm/InRelease`, fixture.name);
	}
});

test("snapshot routes pin signed APT/YUM metadata and keep package hrefs credential-relative", async () => {
	for (const fixture of await vendorFixtures()) {
		const prefix = `https://repo.example/pro/v1/${tokenA}/_sow/v1/snapshots/jammy-20260712`;
		const apt = await fixture.handler(new Request(`${prefix}/apt/apt/infra/dists/jammy-20260712/InRelease`));
		assert.equal(await apt.text(), "origin:.sow/gated/generations/00000000000000000042/apt/apt/infra/dists/jammy-20260712/InRelease", fixture.name);
		const aptPool = await fixture.handler(new Request(`${prefix}/apt/apt/infra/pool/main/p/pkg.deb`));
		assert.equal(await aptPool.text(), "origin:.sow/gated/apt/infra/pool/main/p/pkg.deb", fixture.name);
		const yum = await fixture.handler(new Request(`${prefix}/yum/yum/infra/x86_64/repodata/repomd.xml`));
		assert.equal(await yum.text(), "origin:.sow/gated/generations/00000000000000000042/yum/yum/infra/x86_64/repodata/repomd.xml", fixture.name);
		const rpm = await fixture.handler(new Request(`${prefix}/yum/yum/infra/x86_64/Packages/p/pkg.rpm`));
		assert.equal(await rpm.text(), "origin:.sow/gated/snapshots/jammy-20260712/yum/yum/infra/x86_64/Packages/p/pkg.rpm", fixture.name);
		assert.equal(apt.headers.get("Cache-Control"), "private, no-store, max-age=0", fixture.name);
		for (const call of fixture.calls) assert.equal(call.url.includes(tokenA), false, `${fixture.name} leaked token to origin`);
	}
});

test("asset snapshot routes accept root-exact and nested safe keys through token and Basic on both vendors", async () => {
	const credentials = [
		{ name: "token", prefix: `https://repo.example/pro/v1/${tokenA}`, headers: undefined },
		{ name: "basic", prefix: "https://repo.example/pro/v1/basic", headers: { Authorization: `Basic ${btoa(basicValue)}` } },
	];
	for (const fixture of await vendorFixtures()) {
		for (const credential of credentials) {
			for (const assetPath of ["pkg", "pkg/pig/cli.tar.gz"]) {
				const before = fixture.calls.length;
				const response = await fixture.handler(new Request(
					`${credential.prefix}/_sow/v1/snapshots/jammy-20260712/assets/${assetPath}`,
					{ headers: credential.headers },
				));
				assert.equal(response.status, 200, `${fixture.name}/${credential.name}/${assetPath}`);
				assert.equal(
					await response.text(),
					`origin:.sow/gated/snapshots/jammy-20260712/asset/${assetPath}`,
					`${fixture.name}/${credential.name}/${assetPath}`,
				);
				assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0", fixture.name);
				const routed = fixture.calls.slice(before);
				assert.deepEqual(
					routed.map((call) => decodeURIComponent(new URL(call.url).pathname.slice(1))),
					[
						".sow/snapshots/jammy-20260712.json",
						`.sow/gated/snapshots/jammy-20260712/asset/${assetPath}`,
					],
					`${fixture.name}/${credential.name}/${assetPath}`,
				);
				for (const call of routed) {
					assert.equal(call.url.includes(tokenA), false, `${fixture.name} leaked token`);
					assert.notEqual(call.authorization, `Basic ${btoa(basicValue)}`, `${fixture.name} leaked Basic authorization`);
					assert.equal(call.authorization?.includes(basicValue) ?? false, false, `${fixture.name} leaked Basic credentials`);
				}
			}
		}
	}
});

test("snapshot routes reject empty, malformed, and unsafe assets without relaxing APT/YUM shape gates", async () => {
	const suffixes = [
		"assets",
		"assets/pkg//nested",
		"assets/pkg%2Fnested",
		"assets/%2e%2e/secret",
		"assets/bad!name",
		"apt/apt/infra",
		"yum/yum/repodata/repomd.xml",
	];
	for (const fixture of await vendorFixtures()) {
		for (const credential of [
			{ name: "token", prefix: `https://repo.example/pro/v1/${tokenA}`, headers: undefined },
			{ name: "basic", prefix: "https://repo.example/pro/v1/basic", headers: { Authorization: `Basic ${btoa(basicValue)}` } },
		]) {
			for (const suffix of suffixes) {
				const before = fixture.calls.length;
				const response = await fixture.handler(new Request(
					`${credential.prefix}/_sow/v1/snapshots/jammy-20260712/${suffix}`,
					{ headers: credential.headers },
				));
				assert.equal(response.status, 404, `${fixture.name}/${credential.name}/${suffix}`);
				assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0", fixture.name);
				for (const call of fixture.calls.slice(before)) {
					const key = decodeURIComponent(new URL(call.url).pathname.slice(1));
					assert.equal(key.startsWith(".sow/gated/snapshots/"), false, `${fixture.name}/${suffix} reached a snapshot payload`);
					assert.equal(call.url.includes(tokenA), false, `${fixture.name} leaked token`);
					assert.notEqual(call.authorization, `Basic ${btoa(basicValue)}`, `${fixture.name} leaked Basic authorization`);
					assert.equal(call.authorization?.includes(basicValue) ?? false, false, `${fixture.name} leaked Basic credentials`);
				}
			}
		}
	}
});

test("deleted snapshot pointers terminate as 404 or 410 instead of availability errors", async () => {
	const admittedDeletedSnapshots = {
		SOW_COMPATIBILITY_ADMISSION: JSON.stringify(routeAdmission({
			snapshots: [
				{ id: "jammy-20260601", apt_roots: [], yum_roots: [], asset_roots: [], asset_keys: [] },
				{ id: "jammy-20260701", apt_roots: [], yum_roots: [], asset_roots: [], asset_keys: [] },
				...runtimeRouteAdmission.snapshots,
			],
		})),
	};
	for (const fixture of await vendorFixtures(admittedDeletedSnapshots)) {
		for (const [snapshot, status] of [["jammy-20260701", 404], ["jammy-20260601", 410]]) {
			const response = await fixture.handler(new Request(`https://repo.example/pro/v1/${tokenA}/_sow/v1/snapshots/${snapshot}/_route.json`));
			assert.equal(response.status, status, `${fixture.name}/${snapshot}`);
			assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0", `${fixture.name}/${snapshot}`);
		}
	}
});

test("Basic Auth is the only credential fallback and is stripped before origin", async () => {
  for (const fixture of await vendorFixtures()) {
    const encoded = btoa(basicValue);
    const response = await fixture.handler(new Request("https://repo.example/pro/v1/basic/yum/infra/private.rpm", {
      headers: { Authorization: `Basic ${encoded}` },
    }));
    assert.equal(response.status, 200, fixture.name);
    const last = fixture.calls.at(-1);
    assert.notEqual(last.authorization, `Basic ${encoded}`, fixture.name);
    const denied = await fixture.handler(new Request("https://repo.example/pro/v1/basic/yum/infra/private.rpm", {
      headers: { Authorization: `Basic ${btoa("pigsty:wrong")}` },
    }));
    assert.equal(denied.status, 401, fixture.name);
  }
});

test("shared verifier maps insufficient scope and outages without origin access", async () => {
  for (const [status, expected] of [["forbidden", 403], ["unavailable", 503]]) {
    let origins = 0;
    const handler = createSowEdgeHandler({
      verifyToken: async () => ({ status }),
      verifyBasic: async () => ({ status }),
      fetchOrigin: async () => {
        origins += 1;
        return new Response("unexpected");
      },
      readChannel: async () => ({ generation: 1, legacy_root: "yum/repo/x86_64" }),
		publicPrefixes: ["yum"],
		publicKeys: [],
    });
    const response = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/private`));
    assert.equal(response.status, expected);
    assert.equal(origins, 0);
  }
});

test("production static verifiers enforce expiry, audience, and path scope on both vendors", async () => {
  const digest = await sha256Hex(tokenA);
  for (const vendor of ["cloudflare", "edgeone"]) {
    const makeFixture = vendor === "cloudflare" ? makeCloudflareFixture : makeEdgeOneFixture;
    const scoped = makeFixture(JSON.stringify([entitlement(digest, { path_prefixes: ["/yum/allowed"] })]), "[]");
    const forbidden = await scoped.handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/private/pkg.rpm`));
    assert.equal(forbidden.status, 403, vendor);
    assert.equal(scoped.calls.length, 0, `${vendor} touched origin for an under-scoped token`);

    const wrongAudience = makeFixture(JSON.stringify([entitlement(digest, { audiences: ["customer.example"] })]), "[]");
    assert.equal((await wrongAudience.handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/allowed/pkg.rpm`))).status, 403, vendor);
    assert.equal(wrongAudience.calls.length, 0, `${vendor} touched origin for a wrong audience`);

    const expired = makeFixture(JSON.stringify([entitlement(digest, { expires_at: "2000-01-01T00:00:00Z" })]), "[]");
    assert.equal((await expired.handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/allowed/pkg.rpm`))).status, 401, vendor);
    assert.equal(expired.calls.length, 0, `${vendor} touched origin for an expired token`);
  }
});

test("provider:// uses isomorphic digest requests through Cloudflare service and EdgeOne HTTPS bindings", async () => {
	const observed = [];
	const cloudflareEnvironment = {
		...runtimeVariables(runtimeFixture.token_verifier),
		TOKEN_VERIFIER: {
			async fetch(request) {
				observed.push({ vendor: "cloudflare", request });
				return new Response("{}", { status: 200 });
			},
		},
		ORIGIN: {
			async fetch(request) {
				return originResponseFor(new URL(request.url).pathname.slice(1));
			},
		},
	};
	const cloudflare = createCloudflareHandler(cloudflareEnvironment);

	const edgeEnvironment = {
		...runtimeVariables(runtimeFixture.token_verifier),
		...cosRuntimeVariables(),
		SOW_TOKEN_VERIFIER_URL: "https://entitlements.example/v1/verify",
		SOW_TOKEN_VERIFIER_BEARER: "edge-verifier-secret",
	};
	const edge = createEdgeOneHandler(edgeEnvironment, deterministicEdgeOnePlatform(async (request) => {
			if (new URL(request.url).hostname === "entitlements.example") {
				observed.push({ vendor: "edgeone", request });
				return new Response("{}", { status: 200 });
			}
			return originResponseFor(decodeURIComponent(new URL(request.url).pathname.slice(1)));
		}));

	for (const [vendor, handler] of [["cloudflare", cloudflare], ["edgeone", edge]]) {
		const response = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/private`));
		assert.equal(response.status, 200, vendor);
		const item = observed.find((candidate) => candidate.vendor === vendor);
		assert.ok(item, vendor);
		const verifierBody = await item.request.text();
			assert.equal(item.request.url.includes(tokenA), false, vendor);
			assert.equal([...item.request.headers.values()].some((value) => value.includes(tokenA)), false, vendor);
			assert.equal([...item.request.headers.values()].some((value) => value.includes("AKIDEXAMPLE0123456789012345") || value.includes("cos-secret-key-for-contract-tests-only")), false, `${vendor} sent COS credentials to verifier host`);
		assert.equal(verifierBody.includes(tokenA), false, vendor);
		const decoded = JSON.parse(verifierBody);
		assert.deepEqual(decoded, {
			schema: "sow-token-verifier-request/v1",
			provider: "pigsty-entitlements",
			token_sha256: await sha256Hex(tokenA),
			audience: "repo.example",
			path: "/yum/private",
		}, vendor);
	}
});

test("provider denial and outage map identically and never reach either origin", async () => {
	for (const [providerStatus, clientStatus] of [[403, 403], [500, 503]]) {
		for (const vendor of ["cloudflare", "edgeone"]) {
			let origins = 0;
			const environment = {
				...runtimeVariables(runtimeFixture.token_verifier),
				...cosRuntimeVariables(),
				TOKEN_VERIFIER: { async fetch() { return new Response("{}", { status: providerStatus }); } },
				ORIGIN: { async fetch() { origins += 1; return new Response("unexpected"); } },
				SOW_TOKEN_VERIFIER_URL: "https://entitlements.example/v1/verify",
				SOW_TOKEN_VERIFIER_BEARER: "edge-verifier-secret",
				SOW_ORIGIN_MODE: vendor === "cloudflare" ? "r2-service" : "cos-sigv4",
			};
			const handler = vendor === "cloudflare"
				? createCloudflareHandler(environment)
				: createEdgeOneHandler(environment, deterministicEdgeOnePlatform(async (request) => {
						if (new URL(request.url).hostname === "entitlements.example") return new Response("{}", { status: providerStatus });
						origins += 1;
						return new Response("unexpected");
					}));
			const response = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/private`));
			assert.equal(response.status, clientStatus, `${vendor}/${providerStatus}`);
			assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0", vendor);
			assert.equal(origins, 0, vendor);
		}
	}
});

test("runtime verifier configuration fails closed before either adapter can touch origin", async () => {
	for (const vendor of ["cloudflare", "edgeone"]) {
		let origins = 0;
		const environment = {
			...runtimeVariables(runtimeFixture.token_verifier),
			...cosRuntimeVariables(),
			ORIGIN: { async fetch() { origins += 1; return new Response("unexpected"); } },
		};
		const construct = vendor === "cloudflare"
			? () => createCloudflareHandler(environment)
			: () => createEdgeOneHandler(environment, deterministicEdgeOnePlatform(async () => { origins += 1; return new Response("unexpected"); }));
		assert.throws(construct, /TOKEN_VERIFIER|SOW_TOKEN_VERIFIER/, vendor);
		assert.equal(origins, 0, vendor);

		const invalidReference = { ...environment, SOW_TOKEN_VERIFIER: "provider://Pigsty/unsafe" };
		const constructInvalid = vendor === "cloudflare"
			? () => createCloudflareHandler(invalidReference)
			: () => createEdgeOneHandler(invalidReference, deterministicEdgeOnePlatform(async () => { origins += 1; return new Response("unexpected"); }));
		assert.throws(constructInvalid, /provider ID/, vendor);
		assert.equal(origins, 0, vendor);
	}
});

test("malformed env:// entitlement secrets fail deployment instead of becoming an empty allowlist", () => {
	for (const vendor of ["cloudflare", "edgeone"]) {
		const environment = {
			...runtimeVariables(),
			...cosRuntimeVariables(),
			SOW_TOKEN_ENTITLEMENTS: '[{"sha256":"bad"}]',
			ORIGIN: { async fetch() { return new Response("unexpected"); } },
		};
		const construct = vendor === "cloudflare"
			? () => createCloudflareHandler(environment)
			: () => createEdgeOneHandler(environment, deterministicEdgeOnePlatform(async () => new Response("unexpected")));
		assert.throws(construct, /strict entitlement JSON/, vendor);
	}
});

test("entitlement expiry is canonical UTC and malformed Basic documents fail deployment", async () => {
	const digest = await sha256Hex(tokenA);
	const basicDigest = await sha256Hex(basicValue);
	const invalidExpiries = [
		"2099-01-01T00:00:00",
		"2099-01-01T08:00:00+08:00",
		"2099-01-01T00:00:00.000Z",
		"2099-02-29T00:00:00Z",
		"2099-01-01T24:00:00Z",
	];
	for (const vendor of ["cloudflare", "edgeone"]) {
		const makeFixture = vendor === "cloudflare" ? makeCloudflareFixture : makeEdgeOneFixture;
		const canonical = makeFixture(JSON.stringify([entitlement(digest, { expires_at: "2096-02-29T23:59:59Z" })]), "[]");
		const canonicalResponse = await canonical.handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/private/pkg.rpm`));
		assert.equal(canonicalResponse.status, 200, `${vendor}/canonical-leap-day`);
		assert.equal(canonical.calls.length, 1, `${vendor}/canonical-leap-day origin count`);

		for (const expires_at of invalidExpiries) {
			let origins = 0;
			const environment = {
				...runtimeVariables(),
				...cosRuntimeVariables(),
				SOW_TOKEN_ENTITLEMENTS: JSON.stringify([entitlement(digest, { expires_at })]),
				SOW_BASIC_ENTITLEMENTS: "[]",
				ORIGIN: { async fetch() { origins += 1; return new Response("unexpected"); } },
			};
			const construct = vendor === "cloudflare"
				? () => createCloudflareHandler(environment)
				: () => createEdgeOneHandler(environment, deterministicEdgeOnePlatform(async () => { origins += 1; return new Response("unexpected"); }));
			assert.throws(construct, /strict entitlement JSON/, `${vendor}/${expires_at}`);
			assert.equal(origins, 0, `${vendor}/${expires_at} touched origin`);
		}

		for (const basicDocument of [
			"{",
			JSON.stringify([entitlement(basicDigest, { expires_at: "2099-01-01T00:00:00" })]),
		]) {
			let origins = 0;
			const malformedBasic = {
				...runtimeVariables(),
				...cosRuntimeVariables(),
				SOW_TOKEN_ENTITLEMENTS: JSON.stringify([entitlement(digest)]),
				SOW_BASIC_ENTITLEMENTS: basicDocument,
				ORIGIN: { async fetch() { origins += 1; return new Response("unexpected"); } },
			};
			const constructBasic = vendor === "cloudflare"
				? () => createCloudflareHandler(malformedBasic)
				: () => createEdgeOneHandler(malformedBasic, deterministicEdgeOnePlatform(async () => { origins += 1; return new Response("unexpected"); }));
			assert.throws(constructBasic, /SOW_BASIC_ENTITLEMENTS.*strict entitlement JSON/, `${vendor}/${basicDocument}`);
			assert.equal(origins, 0, `${vendor}/${basicDocument} touched origin`);
		}

		let providerCalls = 0;
		let providerOrigins = 0;
		const malformedDormantStatic = {
			...runtimeVariables("provider://pigsty-entitlements"),
			...cosRuntimeVariables(),
			SOW_TOKEN_ENTITLEMENTS: "{",
			SOW_BASIC_ENTITLEMENTS: "[]",
			TOKEN_VERIFIER: { async fetch() { providerCalls += 1; return new Response("{}", { status: 200 }); } },
			SOW_TOKEN_VERIFIER_URL: "https://entitlements.example/v1/verify",
			SOW_TOKEN_VERIFIER_BEARER: "edge-verifier-secret",
			ORIGIN: { async fetch() { providerOrigins += 1; return new Response("unexpected"); } },
		};
		const constructProvider = vendor === "cloudflare"
			? () => createCloudflareHandler(malformedDormantStatic)
			: () => createEdgeOneHandler(malformedDormantStatic, deterministicEdgeOnePlatform(async (request) => {
				if (new URL(request.url).hostname === "entitlements.example") providerCalls += 1;
				else providerOrigins += 1;
				return new Response("{}", { status: 200 });
			}));
		assert.throws(constructProvider, /SOW_TOKEN_ENTITLEMENTS.*strict entitlement JSON/, `${vendor}/provider-dormant-static`);
		assert.equal(providerCalls, 0, `${vendor}/provider-dormant-static touched provider`);
		assert.equal(providerOrigins, 0, `${vendor}/provider-dormant-static touched origin`);
	}
});

test("duplicate entitlement digests fail closed independent of document order", async () => {
	const digest = await sha256Hex(tokenA);
	const duplicates = [
		entitlement(digest, { path_prefixes: ["/yum/infra"] }),
		entitlement(digest, { path_prefixes: ["/apt/infra"] }),
	];
	for (const entries of [duplicates, duplicates.slice().reverse()]) {
		for (const vendor of ["cloudflare", "edgeone"]) {
			const environment = {
				...runtimeVariables(),
				...cosRuntimeVariables(),
				SOW_TOKEN_ENTITLEMENTS: JSON.stringify(entries),
				ORIGIN: { async fetch() { return new Response("unexpected"); } },
			};
			const construct = vendor === "cloudflare"
				? () => createCloudflareHandler(environment)
				: () => createEdgeOneHandler(environment, deterministicEdgeOnePlatform(async () => new Response("unexpected")));
			assert.throws(construct, /strict entitlement JSON/, `${vendor}/${entries[0].path_prefixes[0]}`);
		}
	}
});

test("shared contract ignores the forbidden manual Cache API", async () => {
	let origins = 0;
	let cacheCalls = 0;
	const handler = createSowEdgeHandler({
		verifyToken: async () => ({ status: "ok" }),
		verifyBasic: async () => ({ status: "ok" }),
		fetchOrigin: async ({ keys }) => {
			origins += 1;
			return new Response(keys[0]);
		},
		readChannel: async () => ({ generation: 1, legacy_root: "yum/repo/x86_64" }),
		publicPrefixes: ["yum"],
		publicKeys: [],
		cache: {
			async match() { cacheCalls += 1; throw new Error("cache down"); },
			async put() { cacheCalls += 1; throw new Error("cache down"); },
		},
	});
	const response = await handler(new Request(`https://repo.example/pro/v1/${tokenA}/yum/private`));
	assert.equal(response.status, 200);
	assert.equal(origins, 1);
	assert.equal(cacheCalls, 0);
});
