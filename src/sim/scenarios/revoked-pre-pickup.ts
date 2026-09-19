import type { Scenario } from "../scenario";
import { standardSetup, negotiate, resultFromTask } from "./common";
import { pickAudit } from "../scenario";

export const revokedPrePickup: Scenario = {
  id: "revoked-pre-pickup",
  title: "Credential revoked after agreement but before pickup",
  summary: "A commitment is recorded with a guarantee attached. FMCSA then issues an authority revocation notice for the carrier; the venue revokes its credential. The venue's pre-pickup re-verification voids the commitment, releases the guarantee on the ledger, and notifies both agents.",
  expect: { outcome: "VOIDED", reasonCode: "CREDENTIAL_REVOKED_PRE_PICKUP", refusedBy: "venue.commitment" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h);
    const first = await negotiate(h, broker, carrier);
    say(`commitment ${first.task!.commitmentId} recorded, guarantee attached`);
    await h.venue.revoke(carrier.spec.agentId, "FMCSA authority revocation notice (MC-0938251), insurer cancellation cross-referenced", { source: "stub:fmcsa-li-daily-feed", noticeDate: "2026-09-20" });
    say("credential revoked by venue identity service");
    const { voided } = await h.venue.prePickupChecks();
    await Promise.all([broker.waitStatus(first.task!.task.id, ["VOIDED"]), carrier.waitStatus(first.task!.task.id, ["VOIDED"])]);
    const audit = await h.venue.audit();
    const v = audit.find((e) => e.outcome === "VOIDED")!;
    const ledger = await h.venue.ledger();
    return {
      outcome: "VOIDED",
      reasonCode: v.reasonCode,
      refusedBy: v.component,
      evidence: v.evidence,
      guaranteeWouldHavePaid: v.evidence?.guaranteeWouldHavePaid as string,
      taskId: first.task!.task.id,
      commitmentId: first.task!.commitmentId,
      findings: [
        { label: "ledger", detail: ledger.map((e) => `${e.seq}:${e.type}`).join(" → ") },
        { label: "both agents notified", detail: `broker task status ${(await broker.tasks())[0]?.status}, carrier task status ${(await carrier.tasks())[0]?.status}; each released its local exposure` },
        { label: "voided commitments", detail: voided.map((x) => x.commitmentId).join(", ") },
      ],
      auditRefs: pickAudit(audit, "venue", (e) => e === v || e.event === "revoke"),
    };
  },
};
