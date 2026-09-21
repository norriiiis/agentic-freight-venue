/**
 * Venue process entrypoint. Configuration comes only from environment; the
 * venue never receives or reads either agent's data directory.
 *
 *   VENUE_DATA_DIR       own state dir
 *   VENUE_REGISTRIES     JSON [{ registryId, url, publicKey? }] — the registry processes (mock FMCSA L&I signers), keys
 *                        pinned by the operator (absent = trust on first use); the venue holds only what they sign
 *   VENUE_REGISTRY_URL   single-registry shorthand for the above (default http://127.0.0.1:4400, id fmcsa-li-mock)
 *   VENUE_REGISTRY_QUORUM      how many registries must answer fresh before standing can be judged (default 1);
 *                        standing itself needs every registry that answered to agree
 *   VENUE_REGISTRY_MAX_AGE_MS  freshness policy for a registry's word at every standing check (default 5 min)
 *   VENUE_REGULATORS     JSON [{ regulatorId, publicKey }] — insurance regulators whose signature on a filer's key the
 *                        venue checks itself (default: trust the registries' onboarding to have)
 *   VENUE_PORT           listen port (127.0.0.1)
 *   VENUE_ID             venue identifier
 *   VENUE_MAX_ROUNDS     protocol bound on negotiation rounds
 *   VENUE_REPLY_TIMEOUT_MS  cancel a negotiation when the awaited party is silent this long (default 120s)
 *   VENUE_SWEEP_MS       how often the timeout sweeper runs (default 5s)
 *   SIM_MODE=1           enables /admin/* (fault injection + introspection for the simulator ONLY)
 */
import { startServer, type HttpRoute } from "../protocol/rpc";
import { VenueService } from "./service";
import type { WitnessKey } from "../protocol/witness";
import type { OkpJwk } from "../protocol/crypto";

const config = {
  venueId: process.env.VENUE_ID ?? "venue-local",
  dataDir: process.env.VENUE_DATA_DIR ?? ".data/venue",
  registries: process.env.VENUE_REGISTRIES ? JSON.parse(process.env.VENUE_REGISTRIES) : [{ registryId: process.env.VENUE_REGISTRY_ID ?? "fmcsa-li-mock", url: process.env.VENUE_REGISTRY_URL ?? "http://127.0.0.1:4400", publicKey: process.env.VENUE_REGISTRY_KEY ? JSON.parse(process.env.VENUE_REGISTRY_KEY).publicKey : undefined }],
  registryQuorum: Number(process.env.VENUE_REGISTRY_QUORUM ?? 1),
  registryMaxAgeMs: Number(process.env.VENUE_REGISTRY_MAX_AGE_MS ?? 5 * 60_000),
  port: Number(process.env.VENUE_PORT ?? 4100),
  maxRounds: Number(process.env.VENUE_MAX_ROUNDS ?? 8),
  messageMaxAgeMs: Number(process.env.VENUE_MSG_MAX_AGE_MS ?? 5 * 60_000),
  replyTimeoutMs: Number(process.env.VENUE_REPLY_TIMEOUT_MS ?? 120_000),
  outboxMaxAttempts: Number(process.env.VENUE_OUTBOX_MAX_ATTEMPTS ?? 40),
  underwriting: process.env.VENUE_UW_PARAMS ? JSON.parse(process.env.VENUE_UW_PARAMS) : undefined,
  witnesses: process.env.VENUE_WITNESSES ? JSON.parse(process.env.VENUE_WITNESSES) : undefined,
  noticeSources: process.env.VENUE_NOTICE_SOURCES ? JSON.parse(process.env.VENUE_NOTICE_SOURCES) : undefined,
  inclusionDelayMs: Number(process.env.VENUE_INCLUSION_DELAY_MS ?? 60_000),
  regulators: process.env.VENUE_REGULATORS ? JSON.parse(process.env.VENUE_REGULATORS) : undefined,
};
const venue = new VenueService(config);
const simMode = process.env.SIM_MODE === "1";
const sweepMs = Number(process.env.VENUE_SWEEP_MS ?? 5_000);
setInterval(() => {
  venue.expireStaleTasks().catch((e) => console.error("[venue] sweeper", e));
  venue.flushOutbox().catch((e) => console.error("[venue] outbox", e));
}, sweepMs).unref();

const ok = (body: unknown) => ({ status: 200, body });
/** Who is asking (SIM: witnesses send x-witness-id so the equivocation fault can target one; a real venue would fingerprint by IP). */
const requester = (req: { headers: Record<string, string | string[] | undefined> }) => (simMode ? (Array.isArray(req.headers["x-witness-id"]) ? req.headers["x-witness-id"][0] : req.headers["x-witness-id"]) : undefined);
const routes: Record<string, HttpRoute> = {
  "GET /health": async () => ok({ ok: true, venueId: config.venueId, kid: venue.kp.kid, rootKid: venue.keys.rootPublicKey.kid }),
  /** Published venue key history: root log + every root-signed certificate and revocation, with the witnessed ledger head. Pin a root; verify the rest. */
  "GET /.well-known/venue-keys.json": async (req) => ok(venue.publishedKeyHistory(requester(req))),
  /** The current ledger head, for witnesses. */
  "GET /.well-known/ledger-head.json": async (req) => ok(venue.ledgerHead(requester(req))),
  /** The ledger is public and auditable. `?from=seq` for a witness checking that a new head extends the last one it cosigned. */
  "GET /ledger.jsonl": async (req) => {
    const u = new URL(req.url ?? "/", "http://localhost");
    const from = Number(u.searchParams.get("from") ?? 0);
    return ok(venue.ledgerViewFor(requester(req)).filter((e) => e.seq >= (Number.isFinite(from) ? from : 0)));
  },
  "GET /.well-known/agent-card.json": async () => ok(venue.agentCard()),
  /** Published credential status list (revocations + supersessions): what an offline verifier needs to judge old signatures. */
  /** Published credential status list: a projection of the ledger's CREDENTIAL_STATUS entries at a head, with the witnessed head. */
  "GET /.well-known/credential-status.json": async (req) => ok(venue.publishedStatusList(requester(req))),
};

if (simMode) {
  // ---- SIM-ONLY. Never present in a deployed venue. ----
  const admin: Record<string, HttpRoute> = {
    /** What the venue holds of the registry's word: the attestations it last verified. */
    "GET /admin/registry-mirror": async () => ok({ pinned: venue.registry.pinned, quorum: config.registryQuorum, stale: venue.registry.stale, hidden: venue.registry.hidden, attestations: venue.registry.all().map((a) => ({ registryId: a.registryId, usdot: a.usdot, asOf: a.asOf, recordHash: a.recordHash, kid: a.kid })) }),
    "POST /admin/credential/revoke": async (_r, b) => {
      const { agentId, reason, evidence } = b as { agentId: string; reason: string; evidence?: Record<string, unknown> };
      const entry = venue.revokeCredential(agentId, reason, evidence);
      if (!entry) return { status: 404, body: { error: "unknown agent" } };
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
    /** Crash the venue process at a named point inside the next commit (after-journal | after-ledger-append | after-apply). */
    "POST /admin/fault": async (_r, b) => {
      const { crashAt, holdOutbox, equivocate, suppressNotices, dropNotices, registryStale, ignoreRegistry, hideRegistries } = b as { crashAt?: string; holdOutbox?: boolean; equivocate?: { witnessIds: string[]; fromSeq: number }; suppressNotices?: boolean; dropNotices?: boolean; registryStale?: boolean; ignoreRegistry?: boolean; hideRegistries?: string[] };
      venue.simFault = crashAt || holdOutbox || equivocate || suppressNotices || dropNotices || registryStale || ignoreRegistry || hideRegistries?.length ? { crashAt: crashAt || undefined, holdOutbox: !!holdOutbox, equivocate, suppressNotices: !!suppressNotices, dropNotices: !!dropNotices, registryStale: !!registryStale, ignoreRegistry: !!ignoreRegistry, hideRegistries } : undefined;
      // A venue that read the registry once and never again: the mirror serves what it has. A venue that picks its registries: the mirror ignores the rest.
      venue.registry.stale = !!registryStale;
      venue.registry.hidden = hideRegistries ?? [];
      venue.audit.write({ component: "sim", event: "fault-armed", outcome: "INFO", evidence: { crashAt: crashAt ?? null, holdOutbox: !!holdOutbox, equivocate: equivocate ?? null, suppressNotices: !!suppressNotices, dropNotices: !!dropNotices, registryStale: !!registryStale, ignoreRegistry: !!ignoreRegistry, hideRegistries: hideRegistries ?? null } });
      return ok({ ok: true, fault: venue.simFault ?? null });
    },
    "POST /admin/flush-outbox": async () => { await venue.flushOutbox(); return ok({ pending: venue.state.outbox.length, deadLetter: venue.state.deadLetter.length }); },
    "GET /admin/dead-letter": async () => ok(venue.state.deadLetter.map((n) => ({ id: n.id, toAgentId: n.toAgentId, attempts: n.attempts, note: n.note }))),
    "GET /admin/journal": async () => ok(venue.state.readJournals()),
    "GET /admin/outbox": async () => ok(venue.state.outbox.map((n) => ({ id: n.id, toAgentId: n.toAgentId, attempts: n.attempts, note: n.note }))),
    "GET /admin/exposure": async (req) => {
      const u = new URL(req.url ?? "/", "http://localhost");
      return ok(venue.underwriting.exposure(u.searchParams.get("counterparty") ?? "", u.searchParams.get("beneficiary") ?? ""));
    },
    "POST /admin/expire-stale-tasks": async () => ok({ expired: (await venue.expireStaleTasks()).map((t) => ({ taskId: t.task.id, outcome: t.outcome })) }),
    /** `now` (ISO) lets the simulator move the clock for renewal deadlines; standing checks still use real registry time. */
    "POST /admin/pre-pickup-checks": async (_r, b) => { const at = (b as { now?: string } | undefined)?.now; return ok({ voided: (await venue.prePickupChecks(at ? new Date(at) : undefined)).map((c) => ({ commitmentId: c.commitmentId, voided: c.voided })) }); },
    "GET /admin/audit": async () => ok(venue.audit.readAll()),
    "GET /admin/ledger": async () => ok(venue.ledger.all()),
    "GET /admin/tasks": async () => ok([...venue.state.tasks.values()]),
    "GET /admin/commitments": async () => ok([...venue.state.commitments.values()]),
    "GET /admin/messages": async () => ok(venue.state.messageLog()),
    "GET /admin/agents": async () => ok([...venue.state.agents.values()].map((a) => ({ agentId: a.agentId, credentialId: a.credentialId, url: a.url, envelope: a.envelope?.limits }))),
    "GET /admin/guarantees": async () => ok(venue.underwriting.allGuarantees()),
    "GET /admin/public-key": async () => ok(venue.kp.publicJwk),
    "GET /admin/venue-keys": async () => ok(venue.keys.history()),
    "POST /admin/witnesses": async (_r, b) => { venue.registerWitness(b as WitnessKey); return ok({ ok: true, witnesses: venue.state.witnesses.map((w) => w.witnessId) }); },
    "POST /admin/notice-sources": async (_r, b) => { venue.registerNoticeSource(b as { sourceId: string; publicKey: OkpJwk; insurerName?: string }); return ok({ ok: true, sources: venue.state.noticeSources.map((s) => s.sourceId) }); },
    /** Rollback fault: a compromised venue rewriting its own history. Drops every ledger entry after `seq`. */
    "POST /admin/ledger/truncate": async (_r, b) => {
      const { seq } = b as { seq: number };
      const before = venue.ledger.head.seq;
      venue.ledger.truncate(seq);
      venue.audit.write({ component: "sim", event: "ledger-rollback", outcome: "INFO", evidence: { fromSeq: before, toSeq: venue.ledger.head.seq } });
      return ok({ ok: true, head: venue.ledgerHead(), witnessed: venue.latestWitnessedHead()?.head ?? null });
    },
    "GET /admin/credential-status": async () => ok(venue.issuer.statusList()),
  };
  Object.assign(routes, admin);
}

// Pin the registry key, then recover BEFORE serving: reconcile journal vs ledger, finish in-flight commits, re-deliver owed notices.
venue.init().then(() => venue.recover()).then((r) => {
  if (r.applied.length || r.aborted.length || r.retried.length || r.redelivered) console.log(`[venue] recovery: applied=${r.applied.length} aborted=${r.aborted.length} retried=${r.retried.length} redelivered=${r.redelivered}`);
  return startServer(config.port, {
    rpcPath: "/a2a",
    rpc: (method, params, req) => venue.handleRpc(method, params, req.headers as Record<string, string | string[] | undefined>),
    routes,
  });
}).then(() => {
  console.log(`[venue] ${config.venueId} listening on ${venue.url} (signing kid ${venue.kp.kid.slice(0, 12)}…, root ${venue.keys.rootPublicKey.kid?.slice(0, 12)}…) replyTimeout ${config.replyTimeoutMs}ms sweep ${sweepMs}ms${simMode ? " SIM_MODE" : ""}`);
});
