import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec } from "../fixtures";
import { negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { OkpJwk } from "../../protocol/crypto";
import type { LedgerEntry } from "../../ledger/chain";

const day = (d: number) => new Date(Date.now() + d * 86_400_000);
const at = (d: number, hhmm = "13:00") => `${day(d).toISOString().slice(0, 10)}T${hhmm}:00.000Z`;
const load = (pickupDay: number, deliveryDay: number, loadRef: string, commodity: string, weightLbs: number) => ({ ...LOAD, loadRef, commodity, weightLbs, origin: { ...LOAD.origin, windowStart: at(pickupDay), windowEnd: at(pickupDay, "19:00") }, destination: { ...LOAD.destination, windowStart: at(deliveryDay), windowEnd: at(deliveryDay, "21:00") } });

export const insuranceRenewal: Scenario = {
  id: "insurance-renewal",
  title: "The statutory window: a load delivering beyond what the insurer's word can assure is committed conditionally, and the origin must speak again by pickup — or the commitment voids in time to re-cover",
  summary: "An insurer's word signed at S assures coverage through S + 30 days (its statutory notice), so a load delivering 35 days out cannot be assured by any word signed today. Refusing such loads is no product; trusting mirrors for the gap is the collusion hole. The window makes renewal arithmetic instead: a word signed at or after delivery − 30 reaches delivery, and it must be on file before the truck moves. The venue commits CONDITIONALLY, records the condition in the artifact, and enforces it. Part 1: the late load commits with a renewal condition; a verifier sees 'conditional', not 'fine'. Part 2: a renewal signed too early cannot reach delivery and does not satisfy it. Part 3: one signed in the window does — recorded on the ledger, both parties told, the verifier satisfied. Part 4: pickup arrives with no renewal — the venue voids and releases the guarantee, and the verifier says so. Part 5: the renewal is where the insurer gets to say no — it discloses a cancellation, and the commitment voids at once.",
  expect: { outcome: "VOIDED", reasonCode: "INSURANCE_RENEWAL_NOT_PRESENTED", refusedBy: "venue.commitment" },
  async run({ h, say }) {
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    const insurer = await h.startInsurer("great-plains-mutual");
    const policy = { usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };
    const coi = insurer.attest(policy);
    const broker = await h.startAgent(brokerSpec({ thinkMs: 60, limits: { ...brokerSpec().limits, requireInsurerAttestation: true } }));
    const carrier = await h.startAgent(carrierSpec({ thinkMs: 60, insurerAttestation: coi }));
    const insurerKey = { witnessId: insurer.insurerId, publicKey: insurer.kp.publicJwk };
    const registryKey = await h.registry.key();
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (id: string) => JSON.parse(readFileSync(join(broker.dir, "commitments", `${id}.json`), "utf8")) as CommitmentArtifact;
    const ledger = () => readFileSync(join(h.venue.dir, "ledger.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
    const verify = (art: CommitmentArtifact, asOf: Date) => verifyArtifact(art, { pinnedRootKey: root, registryKeys: [registryKey], insurerKeys: [insurerKey], requireInsurerAttestation: true, asOf, ledger: ledger() });
    const check = (v: ReturnType<typeof verifyArtifact>, n: string) => v.checks.find((c) => c.name === `carrier.insurer.${n}`)?.detail;
    const findings: Finding[] = [];
    const d = (iso?: string) => iso?.slice(0, 10);

    // ---- Part 1: a load delivering 35 days out. The COI signed today assures through day 30. Conditional commitment.
    const p1 = await negotiate(h, broker, carrier, load(33, 35, "L-2026-298-0901", "Bagged fertilizer, palletized", 41_600));
    if (p1.task!.status !== "COMMITTED") throw new Error(`part 1: expected a conditional commitment, got ${p1.task!.status} ${p1.task!.outcome?.reasonCode}`);
    const art1 = artifactOf(p1.task!.commitmentId!);
    const cond = art1.insurance?.renewal;
    const v1 = verify(art1, new Date());
    say(`part 1: load delivers ${d(art1.terms.delivery.windowEnd)}; the carrier's COI (as of ${d(coi.asOf)}) assures through ${d(day(30).toISOString())} → COMMITTED ${art1.commitmentId.slice(0, 16)}… CONDITIONALLY: renewal signed on or after ${d(cond?.earliestSignedAt)}, on file by pickup ${d(cond?.dueBy)}; guarantee ${art1.underwriting.decision === "GUARANTEED" ? "attached" : "none"}`);
    say(`   verifier requiring the origin's word, judging today → ${v1.reasonCode ?? "VERIFIED"}: ${check(v1, "renewal-due")?.slice(0, 140)}`);
    if (!cond || v1.reasonCode !== "INSURANCE_RENEWAL_PENDING") throw new Error("part 1: condition not recorded or not judged pending");
    findings.push({ label: "part 1: conditional, not refused", reasonCode: "INSURANCE_RENEWAL_PENDING", by: "ledger/verify", detail: `the artifact records the condition the venue bound itself to: a renewal signed ≥ ${d(cond.earliestSignedAt)} (delivery − 30) on file by pickup ${d(cond.dueBy)}. Until then the verdict is "conditional", never "fine" — and never "trust the mirrors for the gap"` });

    // ---- Part 2: too early. A word signed on day 2 assures through day 32: still short of day 35.
    const early = insurer.attest(policy, day(2));
    const r2 = await carrier.presentInsurance(early);
    const mid = (await h.venue.commitments()).find((c) => c.commitmentId === art1.commitmentId)!;
    say(`part 2: carrier presents a renewal signed ${d(early.asOf)} (assures through ${d(day(32).toISOString())}) → ${r2.ok ? "on file" : r2.reasonCode}; condition satisfied: ${!!mid.renewal?.satisfied} — a word signed before ${d(cond.earliestSignedAt)} cannot reach delivery`);
    if (!r2.ok || mid.renewal?.satisfied) throw new Error("part 2: an early renewal should not satisfy the condition");

    // ---- Part 3: in the window. Recorded on the ledger, both parties told.
    const good = insurer.attest(policy, day(6));
    const r3 = await carrier.presentInsurance(good);
    await new Promise((r) => setTimeout(r, 300));
    const after = (await h.venue.commitments()).find((c) => c.commitmentId === art1.commitmentId)!;
    const renewalEntry = ledger().find((e) => e.type === "INSURANCE_RENEWAL" && (e.payload as { commitmentId?: string }).commitmentId === art1.commitmentId);
    const brokerHas = existsSync(join(broker.dir, "commitments", `${art1.commitmentId}.renewals.json`));
    const v3 = verify(art1, day(34));
    say(`part 3: carrier presents a renewal signed ${d(good.asOf)} (assures through ${d(day(36).toISOString())} ≥ delivery) → ${r3.ok ? "on file" : r3.reasonCode}; condition satisfied at ${after.renewal?.satisfied?.at.slice(11, 19)}Z, ledger seq ${renewalEntry?.seq} INSURANCE_RENEWAL; broker holds the origin's word beside its artifact: ${brokerHas}`);
    say(`   verifier judging the day after pickup, with the ledger → ${v3.ok ? "VERIFIED" : v3.reasonCode}: ${check(v3, "assured-through-delivery")?.slice(0, 120)}`);
    if (!after.renewal?.satisfied || !renewalEntry || !brokerHas || !v3.ok) throw new Error("part 3: renewal not recorded end to end");
    findings.push({ label: "part 3: the origin spoke again, in the window", detail: "the renewal is the insurer's signed word, recorded as its own ledger entry and delivered to both parties; the verifier finds it on the ledger or in the party's own file and the condition is discharged" });

    // ---- Part 4: a further load, no renewal by pickup. The venue voids in time to re-cover.
    const p4 = await negotiate(h, broker, carrier, load(38, 40, "L-2026-303-0922", "Steel coil, tarped", 43_200));
    if (p4.task!.status !== "COMMITTED") throw new Error(`part 4: expected a conditional commitment, got ${p4.task!.status} ${p4.task!.outcome?.reasonCode}`);
    const art4 = artifactOf(p4.task!.commitmentId!);
    const { voided } = await h.venue.prePickupChecks(new Date(day(38).getTime() + 3_600_000));
    await Promise.all([broker.waitStatus(p4.task!.task.id, ["VOIDED"]), carrier.waitStatus(p4.task!.task.id, ["VOIDED"])]);
    const rec4 = (await h.venue.commitments()).find((c) => c.commitmentId === art4.commitmentId)!;
    const v4 = verify(art4, new Date(day(38).getTime() + 3_600_000));
    say(`part 4: load delivers ${d(art4.terms.delivery.windowEnd)}; word on file (as of ${d(good.asOf)}) assures through ${d(day(36).toISOString())} → conditional (renewal ≥ ${d(art4.insurance?.renewal?.earliestSignedAt)} by ${d(art4.insurance?.renewal?.dueBy)}). Pickup arrives, nothing presented → ${rec4.status} ${rec4.voided?.reasonCode}; guarantee released; both agents notified`);
    say(`   verifier judging after pickup → ${v4.reasonCode ?? "VERIFIED"}: ${check(v4, "renewal-not-presented")?.slice(0, 140)}`);
    if (rec4.status !== "VOIDED" || rec4.voided?.reasonCode !== "INSURANCE_RENEWAL_NOT_PRESENTED" || voided.length !== 1 || v4.reasonCode !== "INSURANCE_RENEWAL_NOT_PRESENTED") throw new Error("part 4: deadline not enforced");
    findings.push({ label: "part 4: the deadline is the venue's to enforce", reasonCode: "INSURANCE_RENEWAL_NOT_PRESENTED", by: "venue.commitment", detail: "pickup came and the origin had not spoken; the venue voids, releases the guarantee, and tells both parties — the broker re-covers the load instead of dispatching an unassured carrier. The verifier reaches the same verdict from the artifact and the clock" });

    // ---- Part 5: the renewal is where the insurer gets to say no.
    const p5 = await negotiate(h, broker, carrier, load(38, 40, "L-2026-303-0947", "Lumber, bundled", 39_400));
    if (p5.task!.status !== "COMMITTED") throw new Error(`part 5: expected a conditional commitment, got ${p5.task!.status} ${p5.task!.outcome?.reasonCode}`);
    const art5 = artifactOf(p5.task!.commitmentId!);
    const disclosing = insurer.attest({ ...policy, cancellation: { filedDate: d(day(9).toISOString())!, effectiveDate: d(day(39).toISOString())! } }, day(12));
    const r5 = await carrier.presentInsurance(disclosing);
    await Promise.all([broker.waitStatus(p5.task!.task.id, ["VOIDED"]), carrier.waitStatus(p5.task!.task.id, ["VOIDED"])]);
    const rec5 = (await h.venue.commitments()).find((c) => c.commitmentId === art5.commitmentId)!;
    say(`part 5: another conditional commitment ${art5.commitmentId.slice(0, 16)}…; the carrier presents a renewal signed ${d(disclosing.asOf)} in which the insurer discloses a cancellation effective ${d(day(39).toISOString())} — before delivery → ${rec5.status} ${rec5.voided?.reasonCode} on ${(rec5.voided?.evidence as { source?: string })?.source}; presentInsurance reported voided: ${r5.voided?.length ?? 0}`);
    if (rec5.status !== "VOIDED" || rec5.voided?.reasonCode !== "INSURANCE_CANCELLATION_PENDING") throw new Error("part 5: the origin's no was not honoured");
    findings.push(
      { label: "part 5: the renewal is the insurer's chance to say no", reasonCode: "INSURANCE_CANCELLATION_PENDING", by: "venue.commitment", detail: "requiring the origin to speak again is not paperwork: a cancellation filed since the last word shows up in the next one, and the commitment voids at once, before dispatch" },
      { label: "what this leaves", detail: "the insurer's honesty about its own policy — which is where a trust problem becomes a legal one — and the notice period itself: a statutory fact this protocol reads (49 CFR 387.313) and cannot lengthen. Loads booked further out than the notice period are always conditional; that is not a gap, it is the truth about insurance, made explicit" },
    );

    const audit = await h.venue.audit();
    const v = audit.find((e) => e.outcome === "VOIDED" && e.reasonCode === "INSURANCE_RENEWAL_NOT_PRESENTED")!;
    return {
      outcome: "VOIDED",
      reasonCode: v.reasonCode,
      refusedBy: v.component,
      evidence: v.evidence,
      guaranteeWouldHavePaid: v.evidence?.guaranteeWouldHavePaid as string,
      taskId: p4.task!.task.id,
      commitmentId: art4.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "renewal-satisfied"), ...pickAudit(audit, "venue", (e) => e.outcome === "VOIDED")],
    };
  },
};
