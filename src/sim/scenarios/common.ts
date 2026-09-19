import type { Harness, AgentHandle } from "../harness";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec } from "../fixtures";
import type { AgentSpec } from "../harness";
import type { NegotiationTask } from "../../venue/state";
import type { ScenarioResult } from "../scenario";
import { pickAudit } from "../scenario";

/** Standard setup: venue + credentialed broker + credentialed carrier, carrier has prior history. */
export async function standardSetup(h: Harness, opts: { broker?: Partial<AgentSpec>; carrier?: Partial<AgentSpec>; brokerPrivate?: Record<string, unknown>; carrierPrivate?: Record<string, unknown> } = {}) {
  await h.startVenue();
  await h.venue.seedHistory("2751903", CARRIER_HISTORY);
  const broker = await h.startAgent(brokerSpec(opts.broker, opts.brokerPrivate));
  const carrier = await h.startAgent(carrierSpec(opts.carrier, opts.carrierPrivate));
  return { broker, carrier };
}

/** Run one tender to terminal state and let both agents process the final notice. */
export async function negotiate(h: Harness, broker: AgentHandle, carrier: AgentHandle, load = LOAD) {
  const r = await broker.tender(load, { agentId: carrier.spec.agentId });
  if (r.localRefusal) return { localRefusal: true as const, r };
  if (!r.taskId) return { refusal: r.refusal, r };
  const t = await h.venue.waitTerminal(r.taskId);
  const terminal: Parameters<AgentHandle["waitStatus"]>[1] = ["COMMITTED", "REFUSED", "REJECTED", "VOIDED", "CANCELED"];
  // A tender rejected at intake never reaches the counterparty, so only the initiator has a record of it.
  const waits = t.task.status.state === "rejected" ? [broker.waitStatus(r.taskId, terminal)] : [broker.waitStatus(r.taskId, terminal), carrier.waitStatus(r.taskId, terminal)];
  await Promise.all(waits);
  return { task: t, r };
}

/** Turn a terminal venue task into a ScenarioResult, pulling the matching audit entries. */
export async function resultFromTask(h: Harness, t: NegotiationTask, extra: Partial<ScenarioResult> = {}): Promise<ScenarioResult> {
  const audit = await h.venue.audit();
  if (t.status === "COMMITTED") {
    return { outcome: "COMMITTED", taskId: t.task.id, commitmentId: t.commitmentId, findings: [], auditRefs: pickAudit(audit, "venue", (e) => e.taskId === t.task.id && (e.event === "commit" || e.event === "guarantee-attached")), ...extra };
  }
  const o = t.outcome!;
  return {
    outcome: t.status === "CANCELED" ? "CANCELED" : "REFUSED",
    reasonCode: o.reasonCode,
    refusedBy: o.refusedBy,
    evidence: o.evidence,
    guaranteeWouldHavePaid: o.guaranteeWouldHavePaid,
    taskId: t.task.id,
    findings: [],
    auditRefs: pickAudit(audit, "venue", (e) => e.taskId === t.task.id && e.outcome === "REFUSED"),
    ...extra,
  };
}
