/**
 * Registry process entrypoint — the mock FMCSA L&I authority, as its own
 * process with its own key and clock.
 *
 *   REGISTRY_ID        identifier the venue and verifiers pin the key under (default fmcsa-li-mock)
 *   REGISTRY_DATA_DIR  own state dir (key)
 *   REGISTRY_STORE     path to the records JSON (default src/identity/fixtures/registry.json)
 *   REGISTRY_PORT      listen port (127.0.0.1)
 *   SIM_MODE=1         enables /admin/* (mutations + fault injection for the simulator ONLY)
 */
import { startServer, type HttpRoute } from "../protocol/rpc";
import { RegistryService } from "./service";
import type { RegistryRecord } from "../protocol/registry";

const svc = new RegistryService(process.env.REGISTRY_ID ?? "fmcsa-li-mock", process.env.REGISTRY_DATA_DIR ?? ".data/registry", process.env.REGISTRY_STORE ?? "src/identity/fixtures/registry.json");
const port = Number(process.env.REGISTRY_PORT ?? 4400);
const simMode = process.env.SIM_MODE === "1";
const ok = (body: unknown) => ({ status: 200, body });
const usdotOf = (req: { url?: string }) => new URL(req.url ?? "/", "http://localhost").searchParams.get("usdot") ?? "";

const routes: Record<string, HttpRoute> = {
  "GET /health": async () => ok({ ok: true, ...svc.status() }),
  "GET /.well-known/registry.json": async () => ok(svc.wellKnown()),
  /** The registry's signed word about one entity, as of now. */
  "GET /attest": async (req) => (svc.unavailable ? { status: 503, body: { error: "registry unavailable" } } : ok(svc.attest(usdotOf(req)))),
  "GET /records": async () => (svc.unavailable ? { status: 503, body: { error: "registry unavailable" } } : ok(svc.records())),
  /** STUB out-of-band channel (proof-of-control token, vetting flags). */
  "GET /stub/out-of-band": async (req) => (svc.unavailable ? { status: 503, body: { error: "registry unavailable" } } : ok(svc.outOfBand(usdotOf(req)) ?? null)),
};
if (simMode) {
  Object.assign(routes, {
    /** An insurer files a cancellation; FMCSA revokes an authority. Nobody tells the venue. */
    "POST /admin/update": async (_r, b) => {
      const { usdot, patch } = b as { usdot: string; patch: Partial<RegistryRecord> };
      svc.store.update(usdot, patch);
      return ok({ ok: true, recordHash: svc.store.snapshotHash(usdot) });
    },
    "POST /admin/fault": async (_r, b) => {
      svc.unavailable = !!(b as { unavailable?: boolean }).unavailable;
      return ok({ unavailable: svc.unavailable });
    },
  } satisfies Record<string, HttpRoute>);
}

startServer(port, { rpcPath: "/rpc", rpc: async () => { throw new Error("no rpc methods"); }, routes }).then(() => {
  console.log(`[registry] ${svc.registryId} serving ${svc.store.all().length} records (kid ${svc.kp.kid.slice(0, 12)}…) on http://127.0.0.1:${port}${simMode ? " [SIM_MODE]" : ""}`);
});
