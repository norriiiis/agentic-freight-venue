import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup } from "./common";
import { pickAudit } from "../scenario";

export const venueCrashNotification: Scenario = {
  id: "venue-crash-notification",
  title: "After the commit point: parties learn the outcome by sync ack, pull, or push — and the venue's downtime is not charged to them",
  summary: "The ledger can say 'committed' while the parties do not yet know. Three paths close that gap, and each is exercised: (1) the committing party reads the outcome from the venue's synchronous reply; (2) the other party pulls tasks/get when push is held back; (3) push, when it finally arrives, is deduplicated. Separately, a 2-second outage mid-negotiation is measured on restart and every open task's reply clock is shifted by it, so the venue's silence is never blamed on the agent it was waiting for.",
  expect: { outcome: "COMMITTED" },
  async run({ h, say }) {
    h.opts.venue = { replyTimeoutMs: 6000, sweepMs: 150 };
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    const findings: Finding[] = [];

    // ---- Part 1: outbox held → sync ack for the committing party, pull for the other, dedupe on push.
    await h.venue.fault({ holdOutbox: true });
    const r1 = await broker.tender(LOAD, { agentId: carrier.spec.agentId });
    const t1 = await h.venue.waitTerminal(r1.taskId!);
    const brokerView = await broker.waitStatus(r1.taskId!, ["COMMITTED"], 3000);
    const outboxHeld = await h.venue.outbox();
    say(`part 1: venue committed ${t1.commitmentId} with its outbox HELD (${outboxHeld.length} notices pending, none delivered)`);
    const brokerNotice = (await broker.audit()).find((e) => e.event === "task-notice" && e.taskId === r1.taskId);
    say(`   broker (the countersigning party): local status ${brokerView?.status} — learned via ${brokerNotice?.evidence?.source} (the Task returned by its own message/send)`);
    const carrierBefore = (await carrier.tasks()).find((x) => x.taskId === r1.taskId)?.status;
    const pulled = await carrier.reconcile();
    const carrierAfter = (await carrier.tasks()).find((x) => x.taskId === r1.taskId)?.status;
    const carrierNotice = (await carrier.audit()).find((e) => e.event === "task-notice" && e.taskId === r1.taskId);
    say(`   carrier (awaiting the countersign): ${carrierBefore} → reconcile() pulled tasks/get → ${carrierAfter} via ${carrierNotice?.evidence?.source}; artifact on disk`);
    if (brokerView?.status !== "COMMITTED" || carrierAfter !== "COMMITTED" || pulled.resolved.length !== 1) throw new Error("part 1: sync-ack / pull did not deliver the outcome");
    await h.venue.fault(null);
    const flushed = await h.venue.flushOutbox();
    await new Promise((res) => setTimeout(res, 300));
    const dupB = (await broker.audit()).filter((e) => e.event === "inbound-duplicate" && e.taskId === r1.taskId).length;
    const dupC = (await carrier.audit()).filter((e) => e.event === "inbound-duplicate" && e.taskId === r1.taskId).length;
    const artifactsB = (await broker.commitments()).length;
    const artifactsC = (await carrier.commitments()).length;
    say(`   outbox released: ${outboxHeld.length} notices pushed (pending now ${flushed.pending}); deduped on arrival — broker ${dupB}, carrier ${dupC}; artifacts held: broker ${artifactsB}, carrier ${artifactsC}`);
    if (dupB !== 1 || dupC !== 1 || artifactsB !== 1 || artifactsC !== 1) throw new Error("part 1: push was not deduplicated exactly once per party");
    findings.push(
      { label: "sync ack", detail: `the venue's reply to the broker's ACCEPT was the completed Task; the broker processed its venue-signed status message immediately (source=${brokerNotice?.evidence?.source})` },
      { label: "pull", detail: `carrier learned via tasks/get (source=${carrierNotice?.evidence?.source}) while the venue's outbox was held; an agent reconciles OPEN tasks on a timer too` },
      { label: "push dedupe", detail: `when the outbox was released each party received the notice again and dropped it by messageId (broker ${dupB}, carrier ${dupC}); one artifact each` },
    );

    // ---- Part 2: a 2-second outage while a slow carrier is deliberating; its reply clock must not include the outage.
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 1500 }));
    await h.venue.fault({ crashAt: "after-ledger-append" });
    const loadX = { ...LOAD, loadRef: "L-2026-262-0430", commodity: "Retail returns, palletized", weightLbs: 39_100 };
    const loadY = { ...LOAD, loadRef: "L-2026-262-0431", commodity: "Building materials, palletized", weightLbs: 40_300 };
    const [rx, ry] = await Promise.all([broker.tender(loadX, { agentId: carrier.spec.agentId }), broker.tender(loadY, { agentId: carrier2.spec.agentId })]);
    await h.venue.waitExit();
    const snapAtCrash = JSON.parse(readFileSync(join(h.venue.dir, "state", "snapshot.json"), "utf8")) as { tasks: Record<string, { awaitingSince: string; awaiting: string }>; lastAliveAt: string };
    const yBefore = snapAtCrash.tasks[ry.taskId!]!;
    say(`part 2: venue died committing ${loadX.loadRef} while ${carrier2.spec.agentId} was deliberating on ${loadY.loadRef} (awaiting since ${yBefore.awaitingSince.slice(11, 23)}); holding the restart for 2s to simulate a real outage`);
    await new Promise((res) => setTimeout(res, 2000));
    await h.restartVenue();
    const rec = (await h.venue.audit()).filter((e) => e.event === "recovery").at(-1)!;
    const yAfter = (await h.venue.tasks()).find((t) => t.task.id === ry.taskId)!;
    const shiftMs = new Date(yAfter.awaitingSince).getTime() - new Date(yBefore.awaitingSince).getTime();
    say(`   recovery measured downtime ${rec.evidence!.downtimeMs}ms from the heartbeat and shifted ${rec.evidence!.replyClocksShifted} open reply clock(s); ${loadY.loadRef} awaitingSince moved +${shiftMs}ms`);
    const [tx, ty] = await Promise.all([h.venue.waitTerminal(rx.taskId!, 20_000), h.venue.waitTerminal(ry.taskId!, 20_000)]);
    await Promise.all([broker.waitStatus(rx.taskId!, ["COMMITTED"]), broker.waitStatus(ry.taskId!, ["COMMITTED", "CANCELED", "REFUSED"]), carrier2.waitStatus(ry.taskId!, ["COMMITTED", "CANCELED", "REFUSED"])]);
    say(`   ${loadX.loadRef} → ${tx.status} (recovered commit); ${loadY.loadRef} → ${ty.status}${ty.outcome ? ` ${ty.outcome.reasonCode}` : ""} — the slow carrier was not timed out for the venue's outage`);
    if (tx.status !== "COMMITTED" || ty.status !== "COMMITTED" || shiftMs < 1500) throw new Error(`part 2: expected both COMMITTED with a ≥1500ms clock shift; got ${tx.status}/${ty.status} shift ${shiftMs}`);
    findings.push({ label: "downtime fairness", detail: `heartbeat in the snapshot; recovery shifted awaitingSince by ${rec.evidence!.downtimeMs}ms for ${rec.evidence!.replyClocksShifted} open task(s); the in-flight negotiation completed instead of being canceled as NEGOTIATION_TIMEOUT` });

    const audit = await h.venue.audit();
    return {
      outcome: "COMMITTED",
      taskId: r1.taskId,
      commitmentId: t1.commitmentId,
      findings: [...findings, { label: "dead letter", detail: `push is abandoned to a dead-letter queue after ${40} attempts; the agent can still pull — the ledger, not the notice, is the source of truth` }],
      auditRefs: pickAudit(audit, "venue", (e) => e.event === "recovery" || e.event === "fault-armed"),
    };
  },
};
