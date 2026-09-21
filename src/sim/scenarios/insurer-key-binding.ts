import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec } from "../fixtures";
import { negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { generateKeyPair, type OkpJwk } from "../../protocol/crypto";

type Ev = { error?: string; note?: string; registriesShowingKey?: string[]; registriesDissenting?: string[]; rule?: string; kid?: string };

export const insurerKeyBinding: Scenario = {
  id: "insurer-key-binding",
  title: "Whose key is the insurer's is a registry fact: the filer directory, attested by the mirrors — not the venue operator's configuration, and nothing a verifier must pin",
  summary: "An insurer that files with the registry is a registered FILER, and its registration — the name it files under and the keys it signs with, with their validity and revocations — is attested by the same mirrors under the same quorum, unanimity, freshness and accountability as any record. So the binding of a key to the name on a filing is nobody's configuration. Control: a verifier pins only the registries and derives the insurer's key from the filer directory in the artifact. Part 1: the venue operator registers an impostor's key under the insurer's name; the impostor's COI is refused — the registries do not list that key, and the operator's binding does not count. Part 2: the insurer rotates its key with the registry; a mirror that stopped syncing (and claims otherwise) still shows the old key valid; a thief signing with the old key is refused by unanimity, and the mirror's false word is on the record. Part 3: the new key is accepted; the commitment signed under the old key before its revocation still verifies with the registries' word today.",
  expect: { outcome: "REFUSED", reasonCode: "INSURER_KEY_NOT_OF_RECORD", refusedBy: "venue.identity" },
  async run({ h, say }) {
    h.opts.venue = { registryQuorum: 2 };
    const [a, b, c] = await h.startRegistries(["li-mirror-a", "li-mirror-b", "li-mirror-c"]);
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    const gpm = await h.startInsurer("great-plains-mutual", "Great Plains Mutual Insurance Co");
    const policy = { usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };
    const coi = gpm.attest({ ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const broker = await h.startAgent(brokerSpec({ thinkMs: 60, limits: { ...brokerSpec().limits, requireInsurerAttestation: true } }));
    const carrier = await h.startAgent(carrierSpec({ thinkMs: 60, insurerAttestation: coi }));
    const keys = await Promise.all(h.registries.map((r) => r.key()));
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (id: string) => JSON.parse(readFileSync(join(broker.dir, "commitments", `${id}.json`), "utf8")) as CommitmentArtifact;
    // The verifier pins the REGISTRIES and nothing else: no insurer key, no venue list.
    const verify = (art: CommitmentArtifact, extra: Parameters<typeof verifyArtifact>[1] = {}) => verifyArtifact(art, { pinnedRootKey: root, registryKeys: keys, requireInsurerAttestation: true, ...extra });
    const findings: Finding[] = [];
    const near = (loadRef: string, commodity: string, weightLbs: number) => ({ ...LOAD, loadRef, commodity, weightLbs });

    // ---- Control: the key comes from the registries' word in the artifact.
    const c0 = await negotiate(h, broker, carrier, LOAD);
    const art0 = artifactOf(c0.task!.commitmentId!);
    const v0 = verify(art0);
    const filers = art0.insurance?.filers?.carrier ?? [];
    say(`control: ${c0.task!.status} — the artifact carries the registries' word on who ${coi.insurerId} is: ${filers.length} filer attestations (${filers.map((f) => f.registryId).join(", ")}), name "${filers[0]?.registration?.legalName}", key ${coi.kid.slice(0, 12)}… valid from ${filers[0]?.registration?.keys[0]?.validFrom.slice(11, 19)}Z; verifier pinning only the registries → ${v0.ok ? "VERIFIED" : v0.reasonCode}`);
    if (!v0.ok || filers.length !== 3) throw new Error(`control failed: ${v0.checks.filter((x) => !x.ok).map((x) => `${x.name}: ${x.detail}`).join("; ")}`);
    findings.push({ label: "control: nothing to pin beyond the registries", detail: "the insurer's key is derived from filer attestations embedded in the artifact — verified under the pinned registry keys, a quorum fresh at commitment, unanimous that the signing key was the filer's at signing time. An insurer key pinned out of band is a cross-check, not a requirement" });

    // ---- Part 1: the venue operator binds an impostor's key to the insurer's name.
    const impostor = generateKeyPair();
    await h.venue.registerNoticeSource(gpm.insurerId, impostor.publicJwk, gpm.insurerName);
    const forged = gpm.signWith(impostor, { ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const r1 = await carrier.presentInsurance(forged);
    const e1 = (r1.evidence ?? {}) as Ev;
    say(`part 1: the venue operator registers key ${impostor.kid.slice(0, 12)}… as "${gpm.insurerName}"; a COI signed with it is presented → ${r1.reasonCode}: ${e1.error}`);
    say(`   ${e1.note}`);
    if (r1.reasonCode !== "INSURER_KEY_NOT_OF_RECORD") throw new Error("part 1: the operator's binding was honoured");
    findings.push({ label: "part 1: the operator's binding does not count", reasonCode: "INSURER_KEY_NOT_OF_RECORD", by: "venue.identity", detail: "the venue's own configuration named the impostor's key as the insurer's, and the venue refused anyway: the registries list one key for that filer, and it is not this one. A fooled or dishonest operator cannot make an impostor into the origin" });

    // ---- Part 2: rotation at the registry; a mirror that hides the revocation; a thief with the old key.
    await c!.fault({ freeze: true, claimsCurrent: true });
    const k2 = generateKeyPair();
    const revokedAt = new Date().toISOString();
    await h.registerFiler({ insurerId: gpm.insurerId, legalName: gpm.insurerName, publicKey: k2.publicJwk, kid: k2.kid });
    await h.revokeFilerKey({ insurerId: gpm.insurerId, kid: gpm.kp.kid, revokedAt, reason: "ROTATION" });
    await new Promise((r) => setTimeout(r, 1200));
    const thief = gpm.signWith(gpm.kp, { ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const r2 = await carrier.presentInsurance(thief);
    const e2 = (r2.evidence ?? {}) as Ev;
    const audit2 = await h.venue.audit();
    const lie = audit2.find((e) => e.event === "registry-false-attestation" && (e.evidence as { filer?: string }).filer === gpm.insurerId);
    say(`part 2: ${gpm.insurerId} registers key ${k2.kid.slice(0, 12)}… with the registries and revokes ${gpm.kp.kid.slice(0, 12)}… (rotation, ${revokedAt.slice(11, 19)}Z); ${c!.registryId} stopped syncing yet claims a current sync. A COI signed with the old key → ${r2.reasonCode}: ${e2.error}`);
    say(`   showing the revocation: ${e2.registriesDissenting?.join(", ")}; still vouching for the old key: ${e2.registriesShowingKey?.join(", ")} — ${e2.rule}; ${c!.registryId}'s false word audited: ${!!lie} (${(lie?.evidence as { missing?: { revokedAt: string } })?.missing?.revokedAt ? `claimed sync after the revocation it does not show` : ""})`);
    if (r2.reasonCode !== "INSURER_KEY_NOT_OF_RECORD" || !e2.registriesShowingKey?.includes(c!.registryId) || !lie) throw new Error("part 2: revoked key or lying mirror not caught");
    findings.push({ label: "part 2: a revocation is news that cannot be un-known", reasonCode: "INSURER_KEY_NOT_OF_RECORD", by: "venue.identity", detail: `two mirrors show the old key revoked; the third, frozen and claiming a current sync, shows it valid — unanimity refuses, and the third has signed a falsehood the other two prove (${lie?.reasonCode}). Same rules as for standing, because the filer directory is a record like any other` });

    // ---- Part 3: the new key is accepted; history is preserved.
    await c!.fault({ freeze: false });
    await new Promise((r) => setTimeout(r, 1200)); // the venue's word on the filer ages past its policy; the thawed mirror is asked again
    const fresh = gpm.signWith(k2, { ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const r3 = await carrier.presentInsurance(fresh);
    const c3 = await negotiate(h, broker, carrier, near("L-2026-263-1101", "Bagged fertilizer, palletized", 41_600));
    const art3 = artifactOf(c3.task!.commitmentId!);
    const v3 = verify(art3);
    const today = await Promise.all(h.registries.map((r) => r.attestFiler(gpm.insurerId)));
    const v0today = verify(art0, { currentFilerAttestations: today });
    say(`part 3: a COI under the new key → ${r3.ok ? "on file" : r3.reasonCode}; commitment ${c3.task!.status}; verifier pinning only the registries → ${v3.ok ? "VERIFIED" : v3.reasonCode} (COI in artifact under key ${art3.insurance?.carrier?.kid.slice(0, 12)}…, per ${art3.insurance?.filers?.carrier?.map((f) => f.registryId).join(", ")})`);
    say(`   the control commitment, signed under the old key before its revocation, with the registries' word TODAY → ${v0today.ok ? "VERIFIED" : v0today.reasonCode}: valid at signing time is what a historical record needs`);
    if (!r3.ok || c3.task!.status !== "COMMITTED" || !v3.ok || !v0today.ok || art3.insurance?.carrier?.kid !== k2.kid) throw new Error(`part 3: rotation not honoured (${r3.reasonCode} / ${v3.reasonCode} / ${v0today.reasonCode})`);
    findings.push(
      { label: "part 3: rotation with the registry, not with the venue", detail: "the insurer rotates the way it files — with the registry — and every venue and verifier learns of it the same way, through the mirrors. A routine rotation keeps old signatures good; a COMPROMISE revocation as of a time would not, exactly as for agent and venue keys" },
      { label: "what this leaves", detail: "the registry's own filer onboarding: how the upstream satisfies itself that the entity registering as an insurer is that insurer — the proof-of-control problem one level up, rooted in the regulators' company registers and outside this protocol; and the registries' honesty about filers, which is held to the same mirrors, quorum and accountability as everything else" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "INSURER_KEY_NOT_OF_RECORD",
      refusedBy: "venue.identity",
      evidence: { insurerId: gpm.insurerId, operatorConfiguredKid: impostor.kid, registriesListKid: gpm.kp.kid, error: e1.error, note: e1.note },
      guaranteeWouldHavePaid: "N/A — refused before any transaction. Had the operator's binding counted, a guarantee would have attached on an impostor's word about coverage; the registries' filer directory is what stops a venue from being able to vouch for anyone it likes.",
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "present-insurance" && e.outcome === "REFUSED"), ...pickAudit(audit, "venue", (e) => e.event === "registry-false-attestation").slice(0, 1)],
    };
  },
};
