import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec } from "../fixtures";
import { negotiate, resultFromTask } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { OkpJwk } from "../../protocol/crypto";
import type { InsuranceFiling } from "../../protocol/registry";

const day = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString().slice(0, 10);
type Ev = { insurerId?: string; signedAt?: string; missing?: { source: string; cancellationFiledDate: string }; error?: string; note?: string; insurerName?: string | null; policyNumber?: string };

export const insurerOfRecord: Scenario = {
  id: "insurer-of-record",
  title: "The origin's honesty: only the insurer of record can speak, a lie by the origin is convicted by the mirrors, and a principal can accept nothing less than an undertaking",
  summary: "The insurer's word was the one thing left to trust. It is answered the same three ways as everything before it. Identity: the registry's filing names the insurer of record and the policy, so an attestation from anyone else — however well signed — is not the origin's word. Accountability, symmetric with the mirrors': an insurer that signs 'no cancellation' after the date the registry received its own filing has signed a falsehood, and the mirrors convict it. Liability: a certificate of insurance 'confers no rights'; an attestation can instead carry an UNDERTAKING — a signed promise not to deny a covered loss for an undisclosed lapse — and a principal or verifier can accept nothing less. Part 1: an impostor insurer, and the real insurer attesting a policy not on file — both refused as not of record. Part 2: the real insurer files a cancellation, then signs a courtesy COI omitting it; the commitment made on that word is convicted once the registry publishes the filing, and the venue refuses the next load on that word — an origin caught lying is not an origin. Part 3: a principal who requires an undertaking refuses a certificate and accepts the promise.",
  expect: { outcome: "REFUSED", reasonCode: "INSURER_FALSE_ATTESTATION", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    // The insurer of record for PRAIRIE WIND's BMC-91X (as the registry filing names it), and another registered insurer.
    const gpm = await h.startInsurer("great-plains-mutual", "Great Plains Mutual Insurance Co");
    const coastal = await h.startInsurer("coastal-commercial", "Coastal Commercial Auto Ins");
    const policy = { usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };
    const coi = gpm.attest({ ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const broker = await h.startAgent(brokerSpec({ thinkMs: 60, limits: { ...brokerSpec().limits, requireInsurerAttestation: true } }));
    const carrier = await h.startAgent(carrierSpec({ thinkMs: 60, insurerAttestation: coi }));
    const registryKey = await h.registry.key();
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (dir: string, id: string) => JSON.parse(readFileSync(join(dir, "commitments", `${id}.json`), "utf8")) as CommitmentArtifact;
    const verify = (art: CommitmentArtifact, extra: Parameters<typeof verifyArtifact>[1] = {}) => verifyArtifact(art, { pinnedRootKey: root, registryKeys: [registryKey], insurerKeys: [gpm.key, coastal.key], requireInsurerAttestation: true, ...extra });
    const check = (v: ReturnType<typeof verifyArtifact>, n: string) => v.checks.find((c) => c.name === n)?.detail;
    const findings: Finding[] = [];
    const near = (loadRef: string, commodity: string, weightLbs: number) => ({ ...LOAD, loadRef, commodity, weightLbs });

    // ---- Control: the insurer of record, with an undertaking.
    const c0 = await negotiate(h, broker, carrier, LOAD);
    const art0 = artifactOf(broker.dir, c0.task!.commitmentId!);
    const v0 = verify(art0, { requireInsurerUndertaking: true });
    say(`control: ${c0.task!.status} — the carrier's word is ${art0.insurance?.carrier?.insurerId}'s, ${check(v0, "carrier.insurer[great-plains-mutual].of-record")}, with undertaking ${art0.insurance?.carrier?.undertaking}; verifier requiring an undertaking → ${v0.ok ? "VERIFIED" : v0.reasonCode}`);
    if (!v0.ok) throw new Error(`control failed: ${v0.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")}`);

    // ---- Part 1: not of record. A registered insurer that is not this policy's; the real insurer on a policy the registry does not show.
    const impostor = await carrier.presentInsurance(coastal.attest({ ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" }));
    const fake = await carrier.presentInsurance(gpm.attest({ ...policy, policyNumber: "TRK-0099999-26", undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" }));
    say(`part 1: ${coastal.insurerId} attests PRAIRIE WIND's policy ${policy.policyNumber} → ${impostor.reasonCode}: ${(impostor.evidence as Ev)?.error}`);
    say(`   ${gpm.insurerId} attests policy TRK-0099999-26 → ${fake.reasonCode}: ${(fake.evidence as Ev)?.error}`);
    if (impostor.reasonCode !== "INSURER_NOT_OF_RECORD" || fake.reasonCode !== "INSURER_NOT_OF_RECORD") throw new Error("part 1: not-of-record attestations accepted");
    findings.push({ label: "part 1: only the insurer of record can speak", reasonCode: "INSURER_NOT_OF_RECORD", by: "venue.identity", detail: "the registry filing is public and names the insurer and the policy; a well-signed attestation from any other insurer, or about any other policy, is somebody's word, not the origin's. The same check runs in the verifier against the registry attestations in the artifact" });

    // ---- Part 2: the origin lies by omission. It files a cancellation, then signs a COI that does not mention it.
    const filed = day(-1);
    const effective = day(29);
    const courtesy = gpm.attest({ ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" }); // signed today; the filing was received yesterday
    const r2 = await carrier.presentInsurance(courtesy);
    const c2 = await negotiate(h, broker, carrier, near("L-2026-263-1010", "Bagged fertilizer, palletized", 41_600));
    if (!r2.ok || c2.task!.status !== "COMMITTED") throw new Error(`part 2: expected the courtesy COI to pass before the filing was public (${r2.reasonCode} / ${c2.task!.status})`);
    const art2 = artifactOf(broker.dir, c2.task!.commitmentId!);
    const rec = await h.registry.record("2751903");
    // The notice is dated yesterday (the insurer's act); the registry receives and publishes it today.
    const cancelled: InsuranceFiling[] = rec.insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: effective, cancellationFiledDate: filed, cancellationReceivedDate: day(0) } : f));
    await h.registryUpdate("2751903", { insurance: cancelled });
    say(`part 2: Great Plains Mutual filed a BMC-91X cancellation on ${filed} (effective ${effective}) and then, today, signed a courtesy COI saying nothing of it — with an undertaking. The registry receives the notice today; until then no mirror could know: COI on file, near load COMMITTED ${art2.commitmentId.slice(0, 16)}…`);
    await new Promise((r) => setTimeout(r, 1200));
    const vLie = verify(art2, { currentAttestations: [await h.registry.attest("2751903")] });
    say(`   the registry publishes the filing; verifier with the registry's word today → ${vLie.reasonCode ?? "VERIFIED"}: ${check(vLie, "carrier.insurer[great-plains-mutual].true-when-signed")?.slice(0, 200)}`);
    const p2 = await negotiate(h, broker, carrier, near("L-2026-263-1031", "Steel coil, tarped", 43_200));
    const r2b = await resultFromTask(h, p2.task!);
    const e2 = (r2b.evidence ?? {}) as Ev;
    say(`   next tender on that word (a near load — coverage is in fact in force through delivery) → ${r2b.outcome} ${r2b.reasonCode} (${r2b.refusedBy}): ${e2.note}`);
    if (vLie.reasonCode !== "INSURER_FALSE_ATTESTATION" || r2b.reasonCode !== "INSURER_FALSE_ATTESTATION") throw new Error(`part 2: the origin's lie was not convicted (${vLie.reasonCode} / ${r2b.reasonCode})`);
    findings.push(
      { label: "part 2: the mirrors convict the origin", reasonCode: "INSURER_FALSE_ATTESTATION", by: "ledger/verify", detail: `symmetric with how the origin convicts a mirror: the insurer signed at ${courtesy.asOf.slice(0, 10)}; the registry received the insurer's own cancellation filing on ${filed}; the attestation does not disclose it. Two signatures — the insurer's and the registry's — and the falsehood is on the record with a name on it. With an undertaking attached, it is also a liability the artifact documents` },
      { label: "part 2: an origin caught lying is not an origin", reasonCode: "INSURER_FALSE_ATTESTATION", by: "venue.identity", detail: "coverage for the next near load was in fact in force; the venue refused anyway, because the principal requires the origin's word and a false word is no word. The refusal names the lie rather than reporting the word as missing" },
    );

    // ---- Part 3: a certificate is a belief; an undertaking is a liability. A principal can accept nothing less.
    const honest = gpm.attest({ ...policy, cancellation: { filedDate: filed, effectiveDate: effective } }); // truthful, no undertaking
    const r3 = await carrier.presentInsurance(honest);
    const broker2 = await h.startAgent(brokerSpec({ agentId: "blue-mesa-broker-agent", entity: { usdot: "1984411", mc: "MC-0711450", legalName: "BLUE MESA CARRIERS INC" }, proofOfControlToken: "poc-bluemesa-4e77", principalName: "Blue Mesa Carriers — Brokerage Desk", thinkMs: 60, limits: { ...brokerSpec().limits, requireInsurerUndertaking: true } }));
    const p3a = await negotiate(h, broker2, carrier, near("L-2026-263-1052", "Lumber, bundled", 39_400));
    const r3a = await resultFromTask(h, p3a.task!);
    say(`part 3a: the insurer comes clean — an honest COI disclosing the cancellation (${r3.ok ? "on file" : r3.reasonCode}), but a certificate only. ${broker2.spec.agentId} (mandate: undertaking required) tenders a near load → ${r3a.outcome} ${r3a.reasonCode} (${r3a.refusedBy}): ${((r3a.evidence ?? {}) as Ev).note}`);
    if (!r3.ok || r3a.reasonCode !== "MANDATE_INSURER_UNDERTAKING_REQUIRED") throw new Error("part 3a: certificate accepted where an undertaking was required");
    const bound = gpm.attest({ ...policy, cancellation: { filedDate: filed, effectiveDate: effective }, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const r3b = await carrier.presentInsurance(bound);
    const p3b = await negotiate(h, broker2, carrier, near("L-2026-263-1073", "Canned goods, palletized", 42_800));
    if (!r3b.ok || p3b.task!.status !== "COMMITTED") throw new Error(`part 3b: undertaking not accepted (${r3b.reasonCode} / ${p3b.task!.status} ${p3b.task!.outcome?.reasonCode})`);
    const art3 = artifactOf(broker2.dir, p3b.task!.commitmentId!);
    const v3 = verify(art3, { requireInsurerUndertaking: true, currentAttestations: [await h.registry.attest("2751903")] });
    say(`part 3b: the same insurer, the same disclosure, with the undertaking → COMMITTED ${art3.commitmentId.slice(0, 16)}…; verifier requiring an undertaking, with today's registry word → ${v3.ok ? "VERIFIED" : v3.reasonCode}: ${check(v3, "carrier.insurer[great-plains-mutual].true-when-signed") || "true when signed"}; undertaking ${art3.insurance?.carrier?.undertaking}`);
    if (!v3.ok) throw new Error(`part 3b: ${v3.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join("; ")}`);
    findings.push(
      { label: "part 3: a certificate is a belief; an undertaking is a liability", reasonCode: "MANDATE_INSURER_UNDERTAKING_REQUIRED", by: "venue.mandate", detail: "a COI famously confers no rights. The protocol cannot make an insurer pay; it can make sure the only word that satisfies a principal's policy is one the insurer has signed itself into liability for — and the artifact is then the estoppel file: the undertaking, the terms it was relied on for, and the ledger position" },
      { label: "what this leaves", detail: "an insurer that signs an undertaking and then refuses to honour it — which is no longer a trust problem the protocol can name but a breach with the evidence pre-assembled; and the binding of an insurer's key to its name, which the venue operator configures here and an insurer directory (NAIC-rooted) would certify in production" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "INSURER_FALSE_ATTESTATION",
      refusedBy: "ledger/verify",
      evidence: { commitmentId: art2.commitmentId, insurer: courtesy.insurerId, signedAt: courtesy.asOf, undertaking: courtesy.undertaking, filingReceived: filed, effective, failedChecks: vLie.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`) },
      guaranteeWouldHavePaid: "The guarantee was attached on the insurer's signed word, which was false when signed. Coverage for this near load was in force regardless; had it not been, the undertaking makes the denial the insurer's breach, and the artifact — attestation, filing date, ledger position — is the claim file against the insurer, not a coverage question for the guarantee.",
      taskId: c2.task!.task.id,
      commitmentId: art2.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "insurer-false-attestation").slice(0, 1), ...pickAudit(audit, "venue", (e) => e.event === "present-insurance" && e.outcome === "REFUSED"), ...pickAudit(audit, "venue", (e) => e.taskId === p2.task!.task.id && e.outcome === "REFUSED"), ...pickAudit(audit, "venue", (e) => e.taskId === p3a.task!.task.id && e.outcome === "REFUSED")],
    };
  },
};
