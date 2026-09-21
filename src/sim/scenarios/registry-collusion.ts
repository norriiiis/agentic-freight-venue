import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec } from "../fixtures";
import { negotiate, resultFromTask } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { OkpJwk } from "../../protocol/crypto";
import type { InsuranceFiling, RegistryRef } from "../../protocol/registry";

const day = (offsetDays: number) => new Date(Date.now() + offsetDays * 86_400_000).toISOString().slice(0, 10);
type Ev = { registry?: RegistryRef; source?: string; dissentingRegistries?: RegistryRef[]; falseAttestations?: { registryId: string; claimedSyncAt: string; missing: { source: string; cancellationFiledDate: string } }[]; counterpartyInsuranceAssuredThrough?: string; assuredBy?: string; assuredThrough?: string };

export const registryCollusion: Scenario = {
  id: "registry-collusion",
  title: "Colluding mirrors: a signed lie is convicted by any honest word — a peer's, its own later, or the origin's — and the origin's word cannot be forged",
  summary: "Independence among registry mirrors is configuration, not proof, so two of three collude: they keep serving the record without the insurer's cancellation and sign a sync time they never had. Two things make that a losing game. Every attestation states when its mirror synced, and every cancellation carries the date it was FILED — so a mirror claiming a sync after a filing it does not show has signed a falsehood, proven by any word that shows the filing. And the ORIGIN of the fact, the insurer, signs it directly: a word no mirror can forge, whose statutory 30-day notice turns 'no cancellation as of T' into coverage assured through T+30. Part 1: honest venue, the honest mirror outranks the two liars, and the refusal names the lie. Part 2: the venue hides the honest mirror and commits on the two liars, for a load delivering beyond what the insurer's word on file assures; a verifier who trusts any two mirrors is fooled; one with the honest mirror's word today convicts the liars; one who requires the origin's word through delivery refuses. Part 3: a broker whose mandate requires the origin's word — the commitment forms conditionally because the word on file runs out before delivery, the condition makes the insurer speak again, and its fresh word discloses the cancellation: voided before dispatch.",
  expect: { outcome: "REFUSED", reasonCode: "REGISTRY_FALSE_ATTESTATION", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    h.opts.venue = { registryQuorum: 2 };
    const [a, b, c] = await h.startRegistries(["li-mirror-a", "li-mirror-b", "li-mirror-c"]);
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    // The carrier's insurer, and the COI the carrier keeps on file (signed today: no cancellation on the books).
    const insurer = await h.startInsurer("great-plains-mutual", "Great Plains Mutual Insurance Co");
    const policy = { usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };
    const coi = insurer.attest(policy);
    const broker = await h.startAgent(brokerSpec({ thinkMs: 60 }));
    const carrier = await h.startAgent(carrierSpec({ thinkMs: 60, insurerAttestation: coi }));
    const keys = await Promise.all(h.registries.map((r) => r.key()));
    const insurerKey = insurer.key;
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (id: string) => JSON.parse(readFileSync(join(broker.dir, "commitments", `${id}.json`), "utf8")) as CommitmentArtifact;
    const failing = (v: ReturnType<typeof verifyArtifact>) => v.checks.filter((x) => !x.ok).map((x) => `${x.name}: ${x.detail}`);
    const policyMs = h.opts.venue?.registryMaxAgeMs ?? 1000;
    const findings: Finding[] = [];
    // A load delivering beyond the 30 days the COI on file can assure (33–35 days out).
    const late = (loadRef: string, commodity: string, weightLbs: number) => ({ ...LOAD, loadRef, commodity, weightLbs, origin: { ...LOAD.origin, windowStart: `${day(33)}T13:00:00.000Z`, windowEnd: `${day(33)}T19:00:00.000Z` }, destination: { ...LOAD.destination, windowStart: `${day(35)}T13:00:00.000Z`, windowEnd: `${day(35)}T21:00:00.000Z` } });

    // ---- Control: the near load; three mirrors and the origin agree; the COI assures through delivery.
    const c0 = await negotiate(h, broker, carrier, LOAD);
    const art0 = artifactOf(c0.task!.commitmentId!);
    const v0 = verifyArtifact(art0, { pinnedRootKey: root, registryKeys: keys, insurerKeys: [insurerKey], requireInsurerAttestation: true });
    say(`control: ${c0.task!.status} — artifact carries ${art0.registry?.attestations.carrier.length} mirror attestations and the carrier's insurer's word (${art0.insurance?.carrier?.insurerId}, as of ${art0.insurance?.carrier?.asOf.slice(0, 10)}); verifier requiring the origin's word through delivery → ${v0.ok ? "VERIFIED" : v0.reasonCode}: ${v0.checks.find((x) => x.name === "carrier.insurer.assured-through-delivery")?.detail}`);
    if (!v0.ok) throw new Error(`control failed: ${failing(v0).join("; ")}`);

    // ---- The event: the insurer files a cancellation with FMCSA (filed yesterday, effective in 29 days). Mirrors b and c
    //      collude: they freeze the old record and sign a sync time they never had.
    const filed = day(-1);
    const effective = day(29);
    await b!.fault({ freeze: true, claimsCurrent: true });
    await c!.fault({ freeze: true, claimsCurrent: true });
    const rec = await a!.record("2751903");
    const cancelled: InsuranceFiling[] = rec.insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: effective, cancellationFiledDate: filed, cancellationReceivedDate: filed } : f));
    await h.registryUpdate("2751903", { insurance: cancelled });
    say(`registry: Great Plains Mutual files BMC-91X cancellation for PRAIRIE WIND — filed ${filed}, effective ${effective}. ${a!.registryId} shows it. ${b!.registryId} and ${c!.registryId} keep serving the old record and claim a current sync.`);

    // ---- Part 1: honest venue. The honest mirror outranks the liars, and the lie is named.
    await new Promise((r) => setTimeout(r, policyMs + 200));
    const p1 = await negotiate(h, broker, carrier, late("L-2026-297-0801", "Bagged fertilizer, palletized", 41_600));
    const r1 = await resultFromTask(h, p1.task!);
    const e1 = (r1.evidence ?? {}) as Ev;
    say(`part 1: late load (delivers ${day(35)}) → ${r1.outcome} ${r1.reasonCode} (${r1.refusedBy}) on ${e1.registry?.registryId}'s word; dissenting: ${e1.dissentingRegistries?.map((d) => d.registryId).join(", ")}`);
    say(`   false attestations: ${e1.falseAttestations?.map((f) => `${f.registryId} claimed sync ${f.claimedSyncAt.slice(11, 19)}Z, lacks the filing of ${f.missing.cancellationFiledDate} shown by ${f.missing.source}`).join("; ")}`);
    if (r1.reasonCode !== "INSURANCE_CANCELLATION_PENDING" || e1.falseAttestations?.length !== 2) throw new Error("part 1: liars not named");
    findings.push({ label: "part 1: a lie has a date on it", reasonCode: "REGISTRY_FALSE_ATTESTATION", by: "venue.identity", detail: `${b!.registryId} and ${c!.registryId} signed a sync time later than the filing date ${a!.registryId} shows and served a record without the filing. Not "stale" — a stale mirror says so in its sync claim — but false, and provably so from the two signatures` });

    // ---- Part 2: the venue hides the honest mirror and commits on the two liars, beyond what the origin's word assures.
    await h.venue.fault({ hideRegistries: [a!.registryId] });
    const p2 = await negotiate(h, broker, carrier, late("L-2026-297-0822", "Steel coil, tarped", 43_200));
    if (p2.task!.status !== "COMMITTED") throw new Error(`part 2: expected the venue to commit on the liars, got ${p2.task!.status} ${p2.task!.outcome?.reasonCode}`);
    const art2 = artifactOf(p2.task!.commitmentId!);
    const vAny = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys });
    const vToday = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys, currentAttestations: [await a!.attest("2751903")] });
    const vOrigin = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys, insurerKeys: [insurerKey], requireInsurerAttestation: true });
    const vOriginLate = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys, insurerKeys: [insurerKey], requireInsurerAttestation: true, asOf: new Date(new Date(art2.terms.pickup.windowStart).getTime() + 3_600_000) });
    const fresh = insurer.attest({ ...policy, cancellation: { filedDate: filed, effectiveDate: effective } });
    const vOriginToday = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys, insurerKeys: [insurerKey], currentInsurerAttestations: [fresh] });
    say(`part 2: venue hides ${a!.registryId} → COMMITS ${art2.commitmentId.slice(0, 16)}… on ${art2.registry?.attestations.carrier.map((x) => x.registryId).join(", ")} with guarantee ${art2.underwriting.decision === "GUARANTEED" ? "ATTACHED" : "none"}; the COI in the artifact is as of ${art2.insurance?.carrier?.asOf.slice(0, 10)}, delivery ${day(35)}`);
    say(`   verifier trusting any two mirrors → ${vAny.ok ? "VERIFIED (!)" : vAny.reasonCode}`);
    say(`   verifier with ${a!.registryId}'s word today → ${vToday.reasonCode ?? "VERIFIED"}: ${vToday.checks.find((x) => x.name === `carrier.registry[${b!.registryId}].true-when-signed`)?.detail?.slice(0, 200)}`);
    say(`   verifier requiring the origin's word through delivery, judging today → ${vOrigin.reasonCode ?? "VERIFIED"}: ${vOrigin.checks.find((x) => x.name === "carrier.insurer.renewal-due")?.detail?.slice(0, 200)}`);
    say(`   …judging after pickup, no renewal ever recorded → ${vOriginLate.reasonCode ?? "VERIFIED"}`);
    say(`   verifier with the insurer's word today → ${vOriginToday.reasonCode ?? "VERIFIED"}: ${vOriginToday.checks.find((x) => x.name === "carrier.insurer.standing-per-current-word")?.detail?.slice(0, 120)}; liars convicted by the origin: ${vOriginToday.checks.filter((x) => x.name.endsWith("true-when-signed") && !x.ok).length}`);
    if (!vAny.ok || vToday.reasonCode !== "REGISTRY_FALSE_ATTESTATION" || vOrigin.reasonCode !== "INSURANCE_RENEWAL_PENDING" || vOriginLate.reasonCode !== "INSURANCE_RENEWAL_NOT_PRESENTED" || vOriginToday.reasonCode !== "REGISTRY_FALSE_ATTESTATION" || art2.underwriting.decision !== "GUARANTEED") throw new Error(`part 2: collusion not caught: ${vToday.reasonCode} / ${vOrigin.reasonCode} / ${vOriginLate.reasonCode} / ${vOriginToday.reasonCode}`);
    findings.push(
      { label: "part 2: any-k is fooled; one honest word convicts", reasonCode: "REGISTRY_FALSE_ATTESTATION", by: "ledger/verify", detail: `two colluding mirrors satisfy a verifier who accepts any two. But their attestations carry sync claims, and ${a!.registryId}'s word today shows a filing dated before those claims: the artifact itself becomes the proof against them. Collusion has to be total and permanent to be safe — one honest word, ever, and the lie is on the record with signatures` },
      { label: "part 2: the origin bounds what mirrors can promise", reasonCode: "INSURANCE_RENEWAL_PENDING", by: "ledger/verify", detail: `the insurer's word on file (no cancellation as of ${coi.asOf.slice(0, 10)}) assures coverage through ${day(30)} by statute; this load delivers ${day(35)}. For the gap only the mirrors vouched, and a verifier who requires the origin's word does not accept mirrors for it, colluding or not: the commitment is conditional on the insurer speaking again by pickup — and this venue recorded no such condition, so after pickup the verdict is that no renewal was ever presented` },
    );

    // ---- Part 3: a principal who requires the origin's word. The venue still hides the honest mirror; the liars still
    //      say insured; the commitment forms — CONDITIONALLY, because the word on file falls short of delivery. The
    //      condition forces the origin to speak again, and that is where the collusion dies.
    await h.venue.fault({ hideRegistries: [a!.registryId] });
    const broker2 = await h.startAgent(brokerSpec({ agentId: "blue-mesa-broker-agent", entity: { usdot: "1984411", mc: "MC-0711450", legalName: "BLUE MESA CARRIERS INC" }, proofOfControlToken: "poc-bluemesa-4e77", principalName: "Blue Mesa Carriers — Brokerage Desk", thinkMs: 60, limits: { ...brokerSpec().limits, requireInsurerAttestation: true } }));
    const p3 = await negotiate(h, broker2, carrier, late("L-2026-297-0840", "Lumber, bundled", 39_400));
    if (p3.task!.status !== "COMMITTED") throw new Error(`part 3: expected a conditional commitment, got ${p3.task!.status} ${p3.task!.outcome?.reasonCode}`);
    const art3 = JSON.parse(readFileSync(join(broker2.dir, "commitments", `${p3.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    say(`part 3a: ${broker2.spec.agentId} (mandate: the counterparty's insurer must vouch) tenders the late load; two liars vouch, the COI on file runs out ${art3.insurance?.carrier?.asOf.slice(0, 10)}+30 → COMMITTED ${art3.commitmentId.slice(0, 16)}… CONDITIONALLY: renewal signed ≥ ${art3.insurance?.renewal?.earliestSignedAt.slice(0, 10)}, on file by pickup ${art3.insurance?.renewal?.dueBy.slice(0, 10)}`);
    if (!art3.insurance?.renewal) throw new Error("part 3a: no renewal condition recorded");
    const pr = await carrier.presentInsurance(fresh);
    await Promise.all([broker2.waitStatus(p3.task!.task.id, ["VOIDED"]), carrier.waitStatus(p3.task!.task.id, ["VOIDED"])]);
    const rec3 = (await h.venue.commitments()).find((c) => c.commitmentId === art3.commitmentId)!;
    say(`part 3b: the carrier presents a fresh COI (${pr.ok ? "accepted" : pr.reasonCode}) — the honest insurer discloses the cancellation (filed ${filed}, effective ${effective}) → ${rec3.status} ${rec3.voided?.reasonCode} on ${(rec3.voided?.evidence as { source?: string })?.source}; guarantee released; both told before dispatch`);
    if (rec3.status !== "VOIDED" || rec3.voided?.reasonCode !== "INSURANCE_CANCELLATION_PENDING") throw new Error("part 3b: origin's word did not prevail");
    await h.venue.fault(null);
    findings.push(
      { label: "part 3: the origin's word cannot be forged, and the window makes it speak again", reasonCode: "INSURANCE_CANCELLATION_PENDING", by: "venue.commitment", detail: "a principal who requires the insurer's own signature is protected whatever the mirrors do: the word on file fell short of delivery, so the commitment carried a renewal condition; the renewal is the insurer's, and it disclosed the cancellation — the commitment voided at once, guarantee released, before the truck moved" },
      { label: "what this leaves", detail: "the insurer's honesty about its own policy, which has nowhere further to go — an insurer that attests coverage it will not honour answers to its regulator and to estoppel, not to this protocol" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "REGISTRY_FALSE_ATTESTATION",
      refusedBy: "ledger/verify",
      evidence: { commitmentId: art2.commitmentId, mirrorsInArtifact: art2.registry!.attestations.carrier.map((x) => ({ registryId: x.registryId, claimedSync: x.upstreamAsOf })), filing: { filed, effective, shownBy: a!.registryId }, failedChecks: failing(vToday).filter((x) => x.includes("true-when-signed")), withOriginsWord: failing(vOriginToday).filter((x) => x.includes("insurer")) },
      guaranteeWouldHavePaid: "Attached on two mirrors' word that was false when signed, for a load delivering beyond what the carrier's own insurer had assured. The artifact holds the lie with signatures on it; the claim is against the venue, and the mirrors answer to whoever pinned them.",
      taskId: p2.task!.task.id,
      commitmentId: art2.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "registry-false-attestation").slice(0, 2), ...pickAudit(audit, "venue", (e) => e.taskId === p1.task!.task.id && e.outcome === "REFUSED"), ...pickAudit(audit, "venue", (e) => e.taskId === p3.task!.task.id && e.outcome === "VOIDED")],
    };
  },
};
