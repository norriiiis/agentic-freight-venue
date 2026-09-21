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
import type { RegistryRecord, RegulatorKey } from "../protocol/registry";
import { FilerRefusal } from "./store";

/** A refusal is an outcome, not a crash: the registry says why, with a reason code, and stays up. */
const refusable = (f: () => unknown) => {
  try {
    return { status: 200, body: f() };
  } catch (e) {
    if (e instanceof FilerRefusal) return { status: 200, body: { ok: false, reasonCode: e.reasonCode, refusedBy: "registry.onboarding", evidence: e.evidence } };
    throw e;
  }
};

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
  /** The registry's signed word about a registered filer (an insurer), as of now. */
  "GET /attest-filer": async (req) => (svc.unavailable ? { status: 503, body: { error: "registry unavailable" } } : ok(svc.attestFiler(new URL(req.url ?? "/", "http://localhost").searchParams.get("insurerId") ?? ""))),
  "GET /filers": async () => (svc.unavailable ? { status: 503, body: { error: "registry unavailable" } } : ok(svc.store.allFilers())),
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
    /** The upstream pins a regulator (operator configuration at the registry — the law's binding, not a protocol's). */
    "POST /admin/regulators": async (_r, b) => { svc.store.pinRegulator(b as RegulatorKey); return ok({ ok: true, regulators: svc.store.allRegulators().map((r) => r.regulatorId) }); },
    /** The upstream onboards a filer on its regulator's word; the filer rotates (regulator) or revokes (itself or regulator) a key. */
    "POST /admin/filers": async (_r, b) => refusable(() => { const f = b as Parameters<typeof svc.store.registerFiler>[0]; svc.store.registerFiler(f); return { ok: true, filer: svc.store.filer(f.insurerId) }; }),
    "POST /admin/filers/rotate": async (_r, b) => refusable(() => { const f = b as Parameters<typeof svc.store.rotateFilerKey>[0]; svc.store.rotateFilerKey(f); return { ok: true, filer: svc.store.filer(f.insurerId) }; }),
    "POST /admin/filers/revoke": async (_r, b) => refusable(() => { const f = b as Parameters<typeof svc.store.revokeFilerKey>[0]; svc.store.revokeFilerKey(f); return { ok: true, filer: svc.store.filer(f.insurerId) }; }),
    "POST /admin/fault": async (_r, b) => {
      const f = b as { unavailable?: boolean; freeze?: boolean; claimsCurrent?: boolean };
      if (f.unavailable !== undefined) svc.unavailable = !!f.unavailable;
      if (f.freeze !== undefined) svc.freeze(!!f.freeze, !!f.claimsCurrent);
      return ok({ unavailable: svc.unavailable, frozen: svc.isFrozen, claimsCurrent: svc.claimsCurrent });
    },
  } satisfies Record<string, HttpRoute>);
}

startServer(port, { rpcPath: "/rpc", rpc: async () => { throw new Error("no rpc methods"); }, routes }).then(() => {
  console.log(`[registry] ${svc.registryId} serving ${svc.store.all().length} records (kid ${svc.kp.kid.slice(0, 12)}…) on http://127.0.0.1:${port}${simMode ? " [SIM_MODE]" : ""}`);
});
