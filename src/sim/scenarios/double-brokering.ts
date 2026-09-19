import type { Scenario } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, negotiate, resultFromTask } from "./common";
import { pickAudit } from "../scenario";

export const doubleBrokering: Scenario = {
  id: "double-brokering",
  title: "Carrier accepts a load, then re-tenders it to an unverified third party (double-brokering)",
  summary: "After committing to perform the load, the carrier agent (with its local mandate bypassed) tenders the same physical load under a new reference to 'quikhaul-agent', which holds no credential. The venue matches the load fingerprint to the live commitment, notes the carrier has no brokerage authority, and that the counterparty is unverified.",
  expect: { outcome: "REFUSED", reasonCode: "DOUBLE_BROKERING_ATTEMPT", refusedBy: "venue.routing" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { carrier: { rogue: { bypassLocalMandate: true } } });
    const first = await negotiate(h, broker, carrier);
    say(`honest commitment recorded: ${first.task!.commitmentId}`);

    // Same physical load, new reference, tendered by the carrier to an unregistered party.
    const reload = { ...LOAD, loadRef: "PW-RELOAD-0417", subcontractPermitted: true };
    const r = await carrier.tender(reload, { agentId: "quikhaul-agent" });
    const t = await h.venue.waitTerminal(r.taskId!);
    const res = await resultFromTask(h, t);
    const carrierAudit = await carrier.audit();
    const local = carrierAudit.find((e) => e.component === "agent.carrier.mandate" && e.outcome === "REFUSED");
    if (local) {
      res.findings.push({ label: "carrier's own mandate refused first", reasonCode: local.reasonCode, by: "agent.carrier.mandate", detail: "mayTender=false — logged, then bypassed by fault injection (a compromised runtime)", evidence: local.evidence });
      res.auditRefs.push(...pickAudit(carrierAudit, "carrier", (e) => e === local));
    }
    res.findings.push({ label: "all venue violations", detail: (res.evidence?.allViolations as string[]).join(", ") });
    res.findings.push({ label: "original commitment", detail: `${first.task!.commitmentId} remains ACTIVE; its guarantee is the broker's evidence if the carrier double-brokers off-venue` });
    return res;
  },
};
