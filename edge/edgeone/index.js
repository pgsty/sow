import { edgeRuntimeFailureResponse } from "../shared/contract.mjs";
import { createEdgeOneHandler } from "./function.mjs";

addEventListener("fetch", (event) => {
	event.respondWith((async () => {
		try {
			return await createEdgeOneHandler(env)(event.request);
		} catch {
			return edgeRuntimeFailureResponse();
		}
	})());
});
