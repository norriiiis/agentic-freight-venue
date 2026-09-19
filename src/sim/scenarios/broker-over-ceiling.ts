import type { Scenario } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, negotiate, resultFromTask } from "./common";
import { pickAudit } from "../scenario";

export const brokerOverCeiling: Scenario = {
  id: "broker-over-ceiling",
  title: "Broker agent attempts to commit above its principal's mandated rate ceiling",
  summary: "The broker's principal set a $2,000 ceiling. Fault injection makes the agent want to pay $2,400. Phase 1: the agent's own mandate engine refuses and nothing leaves the process. Phase 2: the local check is bypassed (compromised runtime); the venue refuses against the principal-signed envelope it holds.",
  expect: { outcome: "REFUSED", reasonCode: "MANDATE_RATE_ABOVE_CEILING", refusedBy: "venue.mandate" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { limits: { ...(await import("../fixtures")).brokerSpec().limits, maxRatePerLoadUsd: 2000 } } });

    // Phase 1: honest runtime, rogue desire.
    await broker.setRogue({ forceRateUsd: 2400 });
    const p1 = await negotiate(h, broker, carrier);
    const brokerAudit1 = await broker.audit();
    const local = brokerAudit1.find((e) => e.component === "agent.broker.mandate" && e.outcome === "REFUSED");
    say(`phase 1 (local mandate intact): tender ${p1.localRefusal ? "never left the broker process" : "was sent (!)"} — ${local?.reasonCode}`);

    // Phase 2: compromised runtime bypasses the local check.
    await broker.setRogue({ forceRateUsd: 2400, bypassLocalMandate: true });
    const p2 = await negotiate(h, broker, carrier, { ...LOAD, loadRef: "L-2026-262-0418" });
    say(`phase 2 (local mandate bypassed): venue → ${p2.task?.outcome?.reasonCode}`);
    const res = await resultFromTask(h, p2.task!);
    const brokerAudit2 = await broker.audit();
    res.findings.unshift(
      { label: "phase 1: local mandate engine refused", reasonCode: local?.reasonCode, by: "agent.broker.mandate", detail: "no message was sent; the venue never saw an attempt", evidence: local?.evidence },
      { label: "phase 2: local refusal logged but bypassed", by: "agent.broker.mandate", detail: "bypassedByFaultInjection=true; the venue-held envelope (signed by the principal, not the agent) is the second line" },
    );
    res.auditRefs.unshift(...pickAudit(brokerAudit2, "broker", (e) => e.component === "agent.broker.mandate" && e.outcome === "REFUSED"));
    return res;
  },
};
