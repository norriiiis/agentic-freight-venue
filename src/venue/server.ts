/**
 * Venue process entrypoint. Configuration comes only from environment; the
 * venue never receives or reads either agent's data directory.
 *
 *   VENUE_DATA_DIR       own state dir
 *   VENUE_REGISTRY_PATH  path to the mock FMCSA registry JSON
 *   VENUE_PORT           listen port (127.0.0.1)
 *   VENUE_ID             venue identifier
 *   VENUE_MAX_ROUNDS     protocol bound on negotiation rounds
 *   SIM_MODE=1           enables /admin/* (fault injection + introspection for the simulator ONLY)
 */
import { startServer, type HttpRoute } from "../protocol/rpc";
import { VenueService } from "./service";

const config = {
  venueId: process.env.VENUE_ID ?? "venue-local",
  dataDir: process.env.VENUE_DATA_DIR ?? ".data/venue",
  registryPath: process.env.VENUE_REGISTRY_PATH ?? "src/identity/fixtures/registry.json",
  port: Number(process.env.VENUE_PORT ?? 4100),
  maxRounds: Number(process.env.VENUE_MAX_ROUNDS ?? 8),
  messageMaxAgeMs: Number(process.env.VENUE_MSG_MAX_AGE_MS ?? 5 * 60_000),
  underwriting: process.env.VENUE_UW_PARAMS ? JSON.parse(process.env.VENUE_UW_PARAMS) : undefined,
};
const venue = new VenueService(config);
const simMode = process.env.SIM_MODE === "1";

const ok = (body: unknown) => ({ status: 200, body });
const routes: Record<string, HttpRoute> = {
  "GET /health": async () => ok({ ok: true, venueId: config.venueId, kid: venue.kp.kid }),
  "GET /.well-known/agent-card.json": async () => ok(venue.agentCard()),
};

if (simMode) {
  // ---- SIM-ONLY. Never present in a deployed venue. ----
  const admin: Record<string, HttpRoute> = {
    "POST /admin/registry/update": async (_r, b) => {
      const { usdot, patch } = b as { usdot: string; patch: Record<string, unknown> };
      venue.registry.update(usdot, patch);
      venue.audit.write({ component: "sim", event: "registry-mutation", outcome: "INFO", subject: usdot, evidence: { patch } });
      return ok({ ok: true, snapshotHash: venue.registry.snapshotHash(usdot) });
    },
    "POST /admin/credential/revoke": async (_r, b) => {
      const { agentId, reason, evidence } = b as { agentId: string; reason: string; evidence?: Record<string, unknown> };
      const reg = venue.state.agents.get(agentId);
      if (!reg) return { status: 404, body: { error: "unknown agent" } };
      const entry = venue.issuer.revoke(reg.credentialId, reason, evidence);
      venue.audit.write({ component: "venue.identity", event: "revoke", outcome: "INFO", subject: agentId, evidence: { ...entry } });
      return ok({ ok: true, revocation: entry });
    },
    "POST /admin/underwriting/seed-exposure": async (_r, b) => {
      const { counterpartyUsdot, beneficiaryUsdot, amountUsd, day, note } = b as { counterpartyUsdot: string; beneficiaryUsdot: string; amountUsd: number; day: string; note: string };
      const g = venue.underwriting.seedExposure(counterpartyUsdot, beneficiaryUsdot, amountUsd, day, note);
      venue.audit.write({ component: "sim", event: "seed-exposure", outcome: "INFO", subject: counterpartyUsdot, evidence: { amountUsd, note, guaranteeId: g.guaranteeId, exposureNow: venue.underwriting.exposure(counterpartyUsdot, beneficiaryUsdot) } });
      return ok({ ok: true, guarantee: g, exposure: venue.underwriting.exposure(counterpartyUsdot, beneficiaryUsdot) });
    },
    "POST /admin/underwriting/seed-history": async (_r, b) => {
      const { usdot, history } = b as { usdot: string; history: Parameters<typeof venue.underwriting.seedHistory>[1] };
      venue.underwriting.seedHistory(usdot, history);
      return ok({ ok: true });
    },
    "POST /admin/pre-pickup-checks": async () => ok({ voided: (await venue.prePickupChecks()).map((c) => ({ commitmentId: c.commitmentId, voided: c.voided })) }),
    "GET /admin/audit": async () => ok(venue.audit.readAll()),
    "GET /admin/ledger": async () => ok(venue.ledger.all()),
    "GET /admin/tasks": async () => ok([...venue.state.tasks.values()]),
    "GET /admin/commitments": async () => ok([...venue.state.commitments.values()]),
    "GET /admin/messages": async () => ok(venue.state.messageLog()),
    "GET /admin/agents": async () => ok([...venue.state.agents.values()].map((a) => ({ agentId: a.agentId, credentialId: a.credentialId, url: a.url, envelope: a.envelope?.limits }))),
    "GET /admin/guarantees": async () => ok(venue.underwriting.allGuarantees()),
    "GET /admin/public-key": async () => ok(venue.kp.publicJwk),
  };
  Object.assign(routes, admin);
}

startServer(config.port, {
  rpcPath: "/a2a",
  rpc: (method, params, req) => venue.handleRpc(method, params, req.headers as Record<string, string | string[] | undefined>),
  routes,
}).then(() => {
  console.log(`[venue] ${config.venueId} listening on ${venue.url} (kid ${venue.kp.kid.slice(0, 12)}…)${simMode ? " SIM_MODE" : ""}`);
});
