import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup } from "./common";
import { pickAudit } from "../scenario";
import { verifyChain, type LedgerEntry } from "../../ledger/chain";
import type { OkpJwk } from "../../protocol/crypto";
import type { Harness, AgentHandle } from "../harness";

const RATE = 2215;

/** Every invariant a crash could break. Throws on the first violation. */
async function invariants(h: Harness, broker: AgentHandle, carrier: AgentHandle, expectCommits: number, label: string) {
  const venueKey = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
  const ledger = readFileSync(join(h.venue.dir, "ledger.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
  const chain = verifyChain(ledger, { rootPublicKey: venueKey });
  const commits = ledger.filter((e) => e.type === "COMMITMENT");
  const commitments = await h.venue.commitments();
  const guarantees = (await h.venue.guarantees()).filter((g) => g.status === "ATTACHED" && !g.guaranteeId.startsWith("gtee_seed"));
  const exposure = await h.venue.exposure("2751903", "3312874");
  const journal = await h.venue.journal();
  const outbox = await h.venue.outbox();
  const brokerCommitments = readdirSync(join(broker.dir, "commitments")).length;
  const carrierCommitments = readdirSync(join(carrier.dir, "commitments")).length;
  const brokerExposure = JSON.parse(readFileSync(join(broker.dir, "exposure.json"), "utf8")) as { byCounterparty: Record<string, { outstandingUsd: number }> };
  const checks: [string, boolean, string][] = [
    ["ledger chain verifies", chain.ok, chain.error ?? ""],
    [`ledger has exactly ${expectCommits} COMMITMENT entr${expectCommits === 1 ? "y" : "ies"}`, commits.length === expectCommits, `${commits.length}`],
    ["one ledger entry per loadRef", new Set(commits.map((e) => (e.payload as { loadRef: string }).loadRef)).size === commits.length, ""],
    [`venue holds ${expectCommits} ACTIVE commitment(s)`, commitments.filter((c) => c.status === "ACTIVE").length === expectCommits, `${commitments.length}`],
    ["every commitment has exactly one ATTACHED guarantee", commitments.every((c) => guarantees.filter((g) => g.commitmentId === c.commitmentId).length === 1) && guarantees.length === expectCommits, `${guarantees.length} guarantees`],
    [`venue exposure to carrier = ${expectCommits} × $${RATE} (no double count)`, exposure.counterpartyOutstandingUsd === expectCommits * RATE, `$${exposure.counterpartyOutstandingUsd}`],
    ["journal empty", journal.length === 0, `${journal.length} pending`],
    ["outbox empty", outbox.length === 0, `${outbox.length} pending`],
    [`broker holds ${expectCommits} artifact(s)`, brokerCommitments === expectCommits, `${brokerCommitments}`],
    [`carrier holds ${expectCommits} artifact(s)`, carrierCommitments === expectCommits, `${carrierCommitments}`],
    [`broker's own exposure book = ${expectCommits} × $${RATE}`, (brokerExposure.byCounterparty["2751903"]?.outstandingUsd ?? 0) === expectCommits * RATE, `$${brokerExposure.byCounterparty["2751903"]?.outstandingUsd ?? 0}`],
  ];
  const bad = checks.filter((c) => !c[1]);
  if (bad.length) throw new Error(`${label}: invariants violated — ${bad.map((c) => `${c[0]} (${c[2]})`).join("; ")}`);
  return checks.map((c) => c[0]);
}

export const venueCrashRecovery: Scenario = {
  id: "venue-crash-recovery",
  title: "Venue process dies mid-commit — after the ledger append, before it, and after side effects — and recovers on restart",
  summary: "A commit touches the ledger, the guarantee book, four exposure books, the commitment record and two notices. The venue is killed at three different points inside that sequence and restarted on the same data directory. Each time, recovery reconciles the write-ahead journal against the ledger, finishes or discards the in-flight commit, re-delivers owed notices, and every invariant holds: one ledger entry, one guarantee, no double-counted exposure, both agents hold the artifact exactly once.",
  expect: { outcome: "COMMITTED" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    const findings: Finding[] = [];
    const phases: { label: string; crashAt: string; loadRef: string; commodity: string }[] = [
      { label: "A: crash AFTER the ledger append (the gap)", crashAt: "after-ledger-append", loadRef: LOAD.loadRef, commodity: LOAD.commodity },
      { label: "B: crash BEFORE the ledger append (journal written, nothing committed)", crashAt: "after-journal", loadRef: "L-2026-262-0420", commodity: "Canned goods, palletized" },
      { label: "C: crash AFTER side effects were persisted, before journal cleanup and notice delivery", crashAt: "after-apply", loadRef: "L-2026-262-0421", commodity: "Packaged beverages, palletized" },
    ];
    let taskA: string | undefined;
    let n = 0;
    for (const ph of phases) {
      n += 1;
      await h.venue.fault({ crashAt: ph.crashAt });
      const load = { ...LOAD, loadRef: ph.loadRef, commodity: ph.commodity, weightLbs: LOAD.weightLbs + n * 700 };
      const r = await broker.tender(load, { agentId: carrier.spec.agentId });
      taskA ??= r.taskId;
      const code = await h.venue.waitExit();
      const journalOnDisk = readdirSync(join(h.venue.dir, "state", "journal")).length;
      const ledgerBefore = readFileSync(join(h.venue.dir, "ledger.jsonl"), "utf8").split("\n").filter(Boolean).length - 1;
      say(`${ph.label}: venue exited ${code} at "${ph.crashAt}"; on disk: ${journalOnDisk} journal file(s), ${ledgerBefore} ledger entr${ledgerBefore === 1 ? "y" : "ies"} — restarting on the same data dir`);
      await h.restartVenue();
      const t = await h.venue.waitTerminal(r.taskId!, 15_000);
      await Promise.all([broker.waitStatus(r.taskId!, ["COMMITTED", "REFUSED", "CANCELED"]), carrier.waitStatus(r.taskId!, ["COMMITTED", "REFUSED", "CANCELED"])]);
      const recovery = (await h.venue.audit()).filter((e) => e.event === "recovery").at(-1);
      // The broker's in-flight ACCEPT is retried with backoff; give the acknowledgment a moment to land before counting.
      let brokerAudit = await broker.audit();
      for (let i = 0; i < 60 && !brokerAudit.some((e) => e.event === "send-retry-acknowledged" && e.taskId === r.taskId); i++) {
        await new Promise((res) => setTimeout(res, 50));
        brokerAudit = await broker.audit();
      }
      const retried = brokerAudit.filter((e) => e.event === "send-retry-acknowledged" && e.taskId === r.taskId).length;
      const committedEvents = brokerAudit.filter((e) => e.event === "committed" && e.taskId === r.taskId).length;
      const dupes = brokerAudit.filter((e) => (e.event === "committed-duplicate" || e.event === "inbound-duplicate") && e.taskId === r.taskId).length;
      say(`   recovery: ${JSON.stringify(recovery?.evidence ?? {})}; task → ${t.task.status.state} ${t.commitmentId ?? ""}; broker's in-flight ACCEPT retried and acknowledged as already-received: ${retried}; COMMITTED processed ${committedEvents}× (duplicates suppressed: ${dupes})`);
      if (t.status !== "COMMITTED") throw new Error(`${ph.label}: expected COMMITTED, got ${t.status} ${t.outcome?.reasonCode}`);
      const ok = await invariants(h, broker, carrier, n, ph.label);
      findings.push({ label: ph.label, reasonCode: "COMMITTED", by: "venue.commitment", detail: `recovery ${recovery ? `applied=${(recovery.evidence!.applied as string[]).length} aborted=${(recovery.evidence!.aborted as string[]).length} retried=${(recovery.evidence!.retriedTasks as string[]).length} redelivered=${recovery.evidence!.redelivered}` : "n/a"}; ${ok.length} invariants hold` });
    }
    // Phase D — a multi-tender sibling is open when the venue dies after the ledger append.
    // The loser must be canceled by recovery with the RIGHT reason, not left to time out.
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 900 }));
    await h.venue.fault({ crashAt: "after-ledger-append" });
    const loadD = { ...LOAD, loadRef: "L-2026-262-0422", commodity: "Household goods, palletized", weightLbs: LOAD.weightLbs + 4 * 700 };
    const [d1, d2] = await Promise.all([broker.tender(loadD, { agentId: carrier.spec.agentId }), broker.tender(loadD, { agentId: carrier2.spec.agentId })]);
    await h.venue.waitExit();
    const tasksAtCrash = h.venue.stateAtRest().tasks as Record<string, { task: { status: { state: string } } }>;
    say(`D: multi-tender; venue died after the ledger append while ${carrier2.spec.agentId}'s negotiation was ${tasksAtCrash[d2.taskId!]?.task.status.state}; 1 journal file on disk — restarting`);
    await h.restartVenue();
    const [tD1, tD2] = await Promise.all([h.venue.waitTerminal(d1.taskId!, 15_000), h.venue.waitTerminal(d2.taskId!, 15_000)]);
    await Promise.all([broker.waitStatus(d1.taskId!, ["COMMITTED"]), carrier.waitStatus(d1.taskId!, ["COMMITTED"]), carrier2.waitStatus(d2.taskId!, ["CANCELED", "REFUSED", "COMMITTED"])]);
    const recD = (await h.venue.audit()).filter((e) => e.event === "recovery").at(-1);
    const loserView = (await carrier2.tasks()).find((x) => x.taskId === d2.taskId);
    say(`   recovery: ${JSON.stringify(recD?.evidence ?? {})}; winner ${tD1.status} ${tD1.commitmentId}; sibling → ${tD2.task.status.state} (${tD2.outcome?.reasonCode}); ${carrier2.spec.agentId} told: ${loserView?.status} ${loserView?.outcome?.reasonCode}`);
    if (tD1.status !== "COMMITTED" || tD2.outcome?.reasonCode !== "LOAD_ALREADY_COMMITTED" || loserView?.outcome?.reasonCode !== "LOAD_ALREADY_COMMITTED") throw new Error("phase D: sibling was not canceled with LOAD_ALREADY_COMMITTED across the crash");
    const okD = await invariants(h, broker, carrier, 4, "D");
    findings.push({ label: "D: multi-tender sibling open at the crash", reasonCode: "LOAD_ALREADY_COMMITTED", by: "venue.commitment", detail: `sibling cancellation is inside the commit transaction (same snapshot as the winner); recovery also reconciles siblings of every ACTIVE commitment; ${okD.length} invariants hold` });

    const audit = await h.venue.audit();
    return {
      outcome: "COMMITTED",
      taskId: taskA,
      commitmentId: (await h.venue.commitments())[0]?.commitmentId,
      findings: [
        ...findings,
        { label: "how", detail: "journal (atomic) → one durable ledger append = commit point → idempotent apply keyed by commitmentId (guarantee, exposure, commitment record, task, notices, sibling cancellations, audit) → one atomic snapshot → journal delete → outbox flush; recovery reconciles journal vs ledger before serving" },
        { label: "agent side", detail: "a retry of the in-flight ACCEPT is answered NONCE_REUSED (the nonce is inside the signature) and treated as delivered; inbound notices are deduped by messageId" },
      ],
      auditRefs: pickAudit(audit, "venue", (e) => e.event === "recovery" || e.event === "crash"),
    };
  },
};
