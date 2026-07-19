import { createHash } from "node:crypto";
import { appendFileSync, lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { resolve, sep } from "node:path";

import { createCloudflareHandler } from "../../edge/dist/cloudflare-worker.mjs";

const required = (name) => {
	const value = process.env[name];
	if (typeof value !== "string" || value === "") throw new TypeError(`${name} is required`);
	return value;
};

const root = realpathSync(required("SOW_EDGE_CLIENT_ROOT"));
const contract = JSON.parse(readFileSync(required("SOW_EDGE_CLIENT_CONTRACT"), "utf8"));
const token = required("SOW_EDGE_CLIENT_TOKEN");
const portFile = required("SOW_EDGE_CLIENT_PORT_FILE");
const evidenceFile = required("SOW_EDGE_CLIENT_EVIDENCE_FILE");
if (!/^[A-Za-z0-9_-]{22,256}$/.test(token) || contract?.runtime !== "cloudflare" || contract?.schema !== "sow-edge-runtime/v2") {
	throw new TypeError("edge client fixture identity is invalid");
}
const tokenSHA = createHash("sha256").update(token).digest("hex");

const record = (value) => appendFileSync(evidenceFile, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });

const cleanClientPath = (raw) => {
	const parsed = new URL(raw, "https://host.docker.internal");
	const segments = parsed.pathname.split("/").filter(Boolean);
	if (segments[0] === "pro" && segments[1] === "v1" && segments.length >= 4) {
		return { credentialSHA256: createHash("sha256").update(segments[2]).digest("hex"), cleanPath: `/${segments.slice(3).join("/")}` };
	}
	return { credentialSHA256: "", cleanPath: parsed.pathname };
};

const origin = {
	async fetch(request) {
		const parsed = new URL(request.url);
		if (parsed.origin !== "https://sow-private-origin.invalid" || parsed.search || parsed.hash) {
			return new Response("not_found\n", { status: 404 });
		}
		let key;
		try {
			key = decodeURIComponent(parsed.pathname.slice(1));
		} catch {
			return new Response("not_found\n", { status: 404 });
		}
		if (key === "" || key.startsWith("/") || key.split("/").some((part) => part === "" || part === "." || part === "..")) {
			return new Response("not_found\n", { status: 404 });
		}
		const filename = resolve(root, key);
		if (filename !== root && !filename.startsWith(root + sep)) return new Response("not_found\n", { status: 404 });
		let info;
		try {
			info = lstatSync(filename);
		} catch {
			return new Response("not_found\n", { status: 404 });
		}
		if (!info.isFile() || info.isSymbolicLink()) return new Response("not_found\n", { status: 404 });
		const whole = readFileSync(filename);
		let body = whole;
		let status = 200;
		const headers = new Headers({
			"Accept-Ranges": "bytes",
			"Cache-Control": "public, max-age=60",
			"Content-Type": key.endsWith(".xml") || key.endsWith(".xml.gz") || key.endsWith(".xml.zst") ? "application/octet-stream" : "application/octet-stream",
			ETag: `"${createHash("sha256").update(whole).digest("hex")}"`,
		});
		const match = request.headers.get("Range")?.match(/^bytes=(\d+)-(\d*)$/);
		if (match) {
			const start = Number(match[1]);
			const end = match[2] === "" ? whole.length - 1 : Math.min(Number(match[2]), whole.length - 1);
			if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || start >= whole.length) {
				return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${whole.length}` } });
			}
			body = whole.subarray(start, end + 1);
			status = 206;
			headers.set("Content-Range", `bytes ${start}-${end}/${whole.length}`);
		}
		headers.set("Content-Length", String(body.length));
		record({ schema: "sow-edge-client-origin/v1", method: request.method, key, status });
		return new Response(request.method === "HEAD" ? null : body, { status, headers });
	},
};

const environment = {
	...contract.variables,
	SOW_COMPAT_TOKEN_ENTITLEMENTS: JSON.stringify([{
		sha256: tokenSHA,
		expires_at: "2099-01-01T00:00:00Z",
		audiences: ["host.docker.internal"],
		path_prefixes: ["/"],
	}]),
	SOW_BASIC_ENTITLEMENTS: "[]",
	ORIGIN: origin,
};
const handler = createCloudflareHandler(environment);

const server = createServer(async (incoming, outgoing) => {
	try {
		const observed = cleanClientPath(incoming.url || "/");
		record({ schema: "sow-edge-client-request/v1", method: incoming.method, clean_path: observed.cleanPath, credential_sha256: observed.credentialSHA256 });
		const headers = new Headers();
		for (const [name, value] of Object.entries(incoming.headers)) {
			if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(", ") : value);
		}
		const request = new Request(`https://host.docker.internal${incoming.url || "/"}`, {
			method: incoming.method,
			headers,
			redirect: "manual",
		});
		const response = await handler(request);
		outgoing.statusCode = response.status;
		for (const [name, value] of response.headers) outgoing.setHeader(name, value);
		if (incoming.method === "HEAD" || response.body === null) {
			outgoing.end();
			return;
		}
		for await (const chunk of response.body) outgoing.write(chunk);
		outgoing.end();
	} catch {
		outgoing.writeHead(503, { "Cache-Control": "private, no-store, max-age=0" });
		outgoing.end("temporarily_unavailable\n");
	}
});

server.listen(0, "0.0.0.0", () => {
	const address = server.address();
	writeFileSync(portFile, `${address.port}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
});
for (const signal of ["SIGINT", "SIGTERM"]) {
	process.on(signal, () => server.close(() => process.exit(0)));
}
