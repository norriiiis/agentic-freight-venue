import type { Scenario } from "../scenario";
import { LOAD, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup, resultFromTask } from "./common";
import { pickAudit } from "../scenario";

export const multiTender: Scenario = {
  id: "multi-tender",
  title: "Broker tenders one load to two carriers in parallel; first commitment wins, the other is canceled",
  summary: "Standard practice: the broker blasts the same load to Prairie Wind and Blue Mesa. Prairie Wind converges first. The moment its commitment is recorded, the venue cancels the still-open Blue Mesa negotiation (LOAD_ALREADY_COMMITTED) — Blue Mesa learns only that the load went elsewhere. A later attempt to re-tender the committed load is refused at intake.",
  expect: { outcome: "CANCELED", reasonCode: "LOAD_ALREADY_COMMITTED", refusedBy: "venue.commitment" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { carrier: { thinkMs: 80 } });
    // Blue Mesa deliberates longer, so Prairie Wind reliably closes first.
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 600 }));

    const [r1, r2] = await Promise.all([broker.tender(LOAD, { agentId: carrier.spec.agentId }), broker.tender(LOAD, { agentId: carrier2.spec.agentId })]);
    say(`tendered ${LOAD.loadRef} to ${carrier.spec.agentId} (task ${r1.taskId!.slice(0, 13)}…) and ${carrier2.spec.agentId} (task ${r2.taskId!.slice(0, 13)}…) in parallel`);
    const [t1, t2] = await Promise.all([h.venue.waitTerminal(r1.taskId!), h.venue.waitTerminal(r2.taskId!)]);
    const terminal = ["COMMITTED", "REFUSED", "REJECTED", "VOIDED", "CANCELED"] as const;
    await Promise.all([broker.waitStatus(r1.taskId!, [...terminal]), broker.waitStatus(r2.taskId!, [...terminal]), carrier.waitStatus(r1.taskId!, [...terminal]), carrier2.waitStatus(r2.taskId!, [...terminal])]);

    const winner = t1.status === "COMMITTED" ? t1 : t2;
    const loser = winner === t1 ? t2 : t1;
    const commitments = await h.venue.commitments();
    if (commitments.filter((c) => c.status === "ACTIVE").length !== 1) throw new Error(`expected exactly one active commitment, got ${commitments.length}`);
    say(`${winner.carrierAgentId} won: ${winner.commitmentId}; ${loser.carrierAgentId} task → ${loser.task.status.state} (${loser.outcome?.reasonCode})`);

    // Re-tendering a committed load is refused at intake.
    const again = await broker.tender(LOAD, { agentId: carrier2.spec.agentId });
    const t3 = await h.venue.waitTerminal(again.taskId!);
    say(`re-tender of the committed load → ${t3.task.status.state} (${t3.outcome?.reasonCode} by ${t3.outcome?.refusedBy})`);

    const res = await resultFromTask(h, loser);
    const loserView = (await (loser.carrierAgentId === carrier.spec.agentId ? carrier : carrier2).tasks()).find((x) => x.taskId === loser.task.id);
    const audit = await h.venue.audit();
    res.findings.push(
      { label: "winning commitment", detail: `${winner.commitmentId} with ${winner.carrierAgentId} at round ${winner.round}; exactly one ACTIVE commitment for ${LOAD.loadRef}` },
      { label: "what the losing carrier was told", detail: `status ${loserView?.status}; evidence keys: ${Object.keys(loserView?.outcome?.evidence ?? {}).join(", ")} — no winner identity, no rate` },
      { label: "re-tender of a committed load", reasonCode: t3.outcome?.reasonCode, by: t3.outcome?.refusedBy, detail: `matched by ${t3.outcome?.evidence.matchedBy}` },
    );
    const inFlight = audit.find((e) => e.taskId === loser.task.id && e.reasonCode === "PROTOCOL_VIOLATION");
    if (inFlight) res.findings.push({ label: "in-flight race", reasonCode: "PROTOCOL_VIOLATION", by: "venue.protocol", detail: "the broker had already decided to counter the loser before the cancel arrived; the venue refused it against the terminal task" });
    res.auditRefs.push(...pickAudit(audit, "venue", (e) => e.taskId === t3.task.id && e.outcome === "REFUSED"));
    return res;
  },
};
