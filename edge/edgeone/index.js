import { createEdgeOneHandler } from "./function.mjs";

addEventListener("fetch", (event) => {
	event.respondWith((async () => {
		try {
			return await createEdgeOneHandler(env)(event.request);
		} catch {
			return new Response("temporarily_unavailable\n", {
				status: 503,
				headers: { "Cache-Control": "private, no-store, max-age=0", "X-SOW-Edge-Contract": "sow-edge-runtime/v1" },
			});
		}
	})());
});
