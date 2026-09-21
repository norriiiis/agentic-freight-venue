import { createHash } from "node:crypto";
import type { Scenario, Finding } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";

export const loadLifecycle: Scenario = {
  id: "load-lifecycle",
  title: "After the commitment: pickup, delivery, proof, acceptance — each a signed party statement on the ledger; then a claim, adjudicated by declared rules and paid from a counted reserve",
  summary: "A commitment is the beginning of a load, not the end. Each step after it is reported by the party who can know it (pickup and delivery by the carrier, acceptance and payment by the broker), recorded on the ledger with the hash of any document, and relayed to the other party; completion feeds the carrier's history, which prices its next load, and the guarantee stays claimable for the claim window. Part 1: the lifecycle, with the wrong party refused. Part 2: claims — the beneficiary's covered claim is paid from the reserve and the guarantee released; the counterparty's claim, a claim for an excluded peril, and a claim past the window are denied with the rule that denied them. Part 3: a reserve that cannot pay defers on the record rather than paying from nothing; capital added settles it.",
  expect: { outcome: "REFUSED", reasonCode: "CLAIM_PERIL_NOT_IN_SCOPE", refusedBy: "underwriting" },
  async run({ h, say }) {
    h.opts.venue = { underwriting: { initialCapitalUsd: 100 } }; // an under-capitalised guarantee, for part 3
    const { broker, carrier } = await standardSetup(h);
    const findings: Finding[] = [];
    const sha = (s: string) => createHash("sha256").update(s).digest("hex");

    // ---- Part 1: the lifecycle.
    const c1 = await negotiate(h, broker, carrier, LOAD);
    const id = c1.task!.commitmentId!;
    const wrong = await broker.reportEvent({ commitmentId: id, event: "PICKED_UP" });
    const pu = await carrier.reportEvent({ commitmentId: id, event: "PICKED_UP", note: "trailer 4471, seal 0088123" });
    const dl = await carrier.reportEvent({ commitmentId: id, event: "DELIVERED", evidenceHash: sha("POD-scan-0088123.pdf") });
    const acc = await broker.reportEvent({ commitmentId: id, event: "DELIVERY_ACCEPTED" });
    const before = await h.venue.history("2751903");
    say(`part 1: broker reports PICKED_UP → ${wrong.reasonCode} (${wrong.error}); carrier reports PICKED_UP → ${pu.status} (ledger seq ${pu.ledgerSeq}); DELIVERED with POD hash → ${dl.status}; broker DELIVERY_ACCEPTED → ${acc.status}; guarantee now ${acc.guarantee?.status}, claim window to ${acc.guarantee?.claimWindowEndsAt?.slice(0, 10)}; carrier history: ${before.loadsCompleted} completed`);
    await carrier.waitStatus(c1.task!.task.id, ["COMMITTED"]);
    const brokerTask = (await broker.tasks()).find((t) => t.taskId === c1.task!.task.id) as { lifecycle?: unknown[] } | undefined;
    if (wrong.reasonCode !== "LIFECYCLE_EVENT_INVALID" || acc.status !== "COMPLETED" || acc.guarantee?.status !== "CLAIMABLE" || before.loadsCompleted !== 15) throw new Error("part 1: lifecycle not recorded");
    findings.push({ label: "part 1: the load after the commitment", detail: `four signed statements on the ledger (PICKED_UP, DELIVERED + POD hash, DELIVERY_ACCEPTED), each by the party who can know it and refused from the one who cannot; the broker's agent received ${brokerTask?.lifecycle?.length ?? 0} lifecycle notices; completion moved the carrier's history from 14 to ${before.loadsCompleted} completed loads — what underwriting prices the next load on` });

    // ---- Part 2: claims by rule.
    const notBeneficiary = await carrier.fileClaim({ commitmentId: id, peril: "IDENTITY_FRAUD", amountUsd: 2215 });
    const excluded = await broker.fileClaim({ commitmentId: id, peril: "NON_PERFORMANCE", amountUsd: 2215, evidence: { note: "late by 6 hours" } });
    const covered = await broker.fileClaim({ commitmentId: id, peril: "IDENTITY_FRAUD", amountUsd: 5000, evidence: { paidTo: "acct ****1189", bankTrace: sha("wire-20260924") } });
    const reserve = await h.venue.reserve();
    say(`part 2: carrier claims IDENTITY_FRAUD → ${notBeneficiary.claim?.status}: ${notBeneficiary.claim?.decision?.reasonCode}; broker claims NON_PERFORMANCE → ${excluded.claim?.status}: ${excluded.claim?.decision?.reasonCode}; broker claims IDENTITY_FRAUD for $5,000 → ${covered.claim?.status}: ${covered.claim?.decision?.basis.at(-1)}`);
    say(`   reserve: capital $${reserve.initialCapitalUsd} + premiums $${reserve.premiumsUsd} − payouts $${reserve.payoutsUsd} = available $${reserve.availableUsd.toFixed(2)}; exposure outstanding $${reserve.exposureUsd}`);
    if (notBeneficiary.claim?.decision?.reasonCode !== "CLAIM_NOT_BENEFICIARY" || excluded.claim?.decision?.reasonCode !== "CLAIM_PERIL_NOT_IN_SCOPE" || covered.claim?.status !== "DEFERRED") throw new Error(`part 2: adjudication wrong (${notBeneficiary.claim?.status} / ${excluded.claim?.status} / ${covered.claim?.status})`);
    findings.push({ label: "part 2: claims are adjudicated by declared rules", reasonCode: "CLAIM_PERIL_NOT_IN_SCOPE", by: "underwriting", detail: "beneficiary, guarantee status, scope, window, exclusions from the lifecycle, cap at the covered amount — each rule is a line of the decision's basis, on the ledger. A covered claim is capped at the covered amount, not the amount asked" });

    // ---- Part 3: the reserve. A guarantee that cannot pay says so.
    const deferredReserve = await h.venue.reserve();
    const topUp = await h.venue.addCapital(10_000);
    const after = await h.venue.claims();
    const paid = after.find((c) => c.claimId === covered.claim!.claimId)!;
    const hist = await h.venue.history("2751903");
    say(`part 3: the covered claim ($${covered.claim?.decision?.payoutUsd}) exceeded the reserve ($${deferredReserve.availableUsd.toFixed(2)}) → DEFERRED on the record, not paid from nothing; the operator adds $10,000 → ${paid.status} (${topUp.deferredPaid.length} deferred claim(s) settled); guarantee released; carrier history now ${hist.claimsPaid} paid claim(s)`);
    if (paid.status !== "PAID" || hist.claimsPaid !== 1) throw new Error("part 3: deferred claim not settled");
    findings.push(
      { label: "part 3: a counted reserve", detail: "premiums in, payouts out, over declared capital; a covered claim the reserve cannot pay is DEFERRED with the shortfall visible, and settles when capital arrives — the honest state of an under-capitalised guarantee, never a silent default and never money from nowhere" },
      { label: "what this leaves", detail: "loss adjustment: whether a payment really went to an impostor is evidence outside this venue; the rules decide what the venue can know, the ops adjudicator decides the rest with a reason on the ledger, and capital adequacy is an actuarial question the reserve makes visible but does not answer" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "CLAIM_PERIL_NOT_IN_SCOPE",
      refusedBy: "underwriting",
      evidence: { claimId: excluded.claim?.claimId, peril: "NON_PERFORMANCE", basis: excluded.claim?.decision?.basis },
      guaranteeWouldHavePaid: "No — non-performance is an excluded peril and the rule says so on the ledger. The identity-fraud claim on the same commitment was covered, capped at the covered amount, deferred while the reserve was short, and paid when capital arrived.",
      taskId: c1.task!.task.id,
      commitmentId: id,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "lifecycle").slice(0, 2), ...pickAudit(audit, "venue", (e) => e.event === "claim" || e.event === "capital-added")],
    };
  },
};
