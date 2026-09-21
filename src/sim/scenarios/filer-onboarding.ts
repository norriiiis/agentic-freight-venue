import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec } from "../fixtures";
import { negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { generateKeyPair, type OkpJwk } from "../../protocol/crypto";
import { signRegulatorAttestation } from "../../protocol/registry";

type Ev = { error?: string; note?: string };

export const filerOnboarding: Scenario = {
  id: "filer-onboarding",
  title: "How a filer gets into the directory: on its regulator's word, by account rather than by name, and never by appointing its own successor",
  summary: "The filer directory was only as good as the registry's onboarding. Two anchors close it. A filing names the filer ACCOUNT that submitted it, so the insurer of record is an account, not a name — a same-named filer onboarded later is of record for nothing it did not file. And a filer's key is registered only against its REGULATOR's signed word that this licensed insurer files under this key; the registry accepts nothing less at onboarding or rotation, carries the word in the registration, and a verifier who pins the regulator checks the root itself. Control: the chain from a broker's decision to the regulator's license verifies end to end. Part 1: a fraudster registers as a filer under the insurer's name — with no regulator word, then with a forged one — and is refused by the registry. Part 2: a genuinely licensed insurer with the very same name attests the policy and is not of record: the filing was submitted by another account. Part 3: a thief holding the insurer's current key cannot appoint its successor; the regulator licenses the real one; the stolen key is revoked as compromised as of the theft, and the thief's later word is void while the earlier commitment stands.",
  expect: { outcome: "REFUSED", reasonCode: "FILER_UNLICENSED", refusedBy: "registry.onboarding" },
  async run({ h, say }) {
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    const regulator = await h.regulator();
    const gpm = await h.startInsurer("great-plains-mutual", "Great Plains Mutual Insurance Co", { naicCode: "24601" });
    const policy = { usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };
    const coi = gpm.attest({ ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const broker = await h.startAgent(brokerSpec({ thinkMs: 60, limits: { ...brokerSpec().limits, requireInsurerAttestation: true } }));
    const carrier = await h.startAgent(carrierSpec({ thinkMs: 60, insurerAttestation: coi }));
    const registryKey = await h.registry.key();
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (id: string) => JSON.parse(readFileSync(join(broker.dir, "commitments", `${id}.json`), "utf8")) as CommitmentArtifact;
    const verify = (art: CommitmentArtifact, extra: Parameters<typeof verifyArtifact>[1] = {}) => verifyArtifact(art, { pinnedRootKey: root, registryKeys: [registryKey], regulatorKeys: [regulator.key], requireInsurerAttestation: true, ...extra });
    const findings: Finding[] = [];
    const filers = () => h.registry.filers();

    // ---- Control: venue root → registry → filer → regulator, all pinned by the verifier, all signed.
    const c0 = await negotiate(h, broker, carrier, LOAD);
    const art0 = artifactOf(c0.task!.commitmentId!);
    const v0 = verify(art0);
    const regn = art0.insurance?.filers?.carrier?.[0]?.registration;
    say(`control: ${c0.task!.status} — ${gpm.insurerId} is registered as "${regn?.legalName}" (NAIC ${regn?.naicCode}), key ${regn?.keys[0]?.kid.slice(0, 12)}… licensed by ${regn?.keys[0]?.licensedBy?.regulatorId} at ${regn?.keys[0]?.licensedBy?.asOf.slice(11, 19)}Z; the filing on the carrier's record names filer ${gpm.insurerId}; verifier pinning the registry AND the regulator → ${v0.ok ? "VERIFIED" : v0.reasonCode}`);
    if (!v0.ok || !regn?.keys[0]?.licensedBy) throw new Error(`control failed: ${v0.checks.filter((x) => !x.ok).map((x) => `${x.name}: ${x.detail}`).join("; ")}`);
    findings.push({ label: "control: the root is the regulator", detail: "the filer registration in the artifact carries the regulator's signed attestation binding the licensed name to the key; a verifier who pins the regulator checks that signature itself, and one who does not is trusting the registries' onboarding to have — which is now the registries' declared basis, not an assumption" });

    // ---- Part 1: a fraudster registers as a filer under the insurer's name.
    const fraud = generateKeyPair();
    const r1a = await h.registry.registerFiler({ insurerId: "gpm-fraud", legalName: gpm.insurerName, publicKey: fraud.publicJwk, kid: fraud.kid });
    const forged = signRegulatorAttestation(generateKeyPair(), regulator.regulatorId, { naicCode: "24601", legalName: gpm.insurerName, publicKey: fraud.publicJwk });
    const r1b = await h.registry.registerFiler({ insurerId: "gpm-fraud", legalName: gpm.insurerName, publicKey: fraud.publicJwk, kid: fraud.kid, licensedBy: forged });
    say(`part 1: "gpm-fraud" asks the registry to register key ${fraud.kid.slice(0, 12)}… as "${gpm.insurerName}" with no regulator word → ${r1a.ok ? "REGISTERED (!)" : `${r1a.reasonCode}: ${(r1a as { evidence: Ev }).evidence.error}`}`);
    say(`   …with a forged ${regulator.regulatorId} attestation → ${r1b.ok ? "REGISTERED (!)" : `${r1b.reasonCode}: ${(r1b as { evidence: Ev }).evidence.error}`}; filers on the registry: ${(await filers()).map((f) => f.insurerId).join(", ")}`);
    if (r1a.ok || r1a.reasonCode !== "FILER_UNLICENSED" || r1b.ok || r1b.reasonCode !== "FILER_UNLICENSED") throw new Error("part 1: unlicensed filer registered");
    findings.push({ label: "part 1: no license, no key", reasonCode: "FILER_UNLICENSED", by: "registry.onboarding", detail: "the registry registers a filer's key on the regulator's signed word or not at all. A name is not a credential; a forged attestation fails under the regulator's pinned key. This is the proof-of-control problem one level up, and its root is the regulator's company register — where insurer identity is already established for licensing" });

    // ---- Part 2: a licensed insurer with the very same name. Of record for nothing it did not file.
    const twin = await h.startInsurer("gpm-nebraska", gpm.insurerName, { naicCode: "31337" });
    const r2 = await carrier.presentInsurance(twin.attest({ ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" }));
    say(`part 2: ${twin.insurerId} — a genuinely licensed insurer (NAIC ${twin.naicCode}) filing under the identical name "${twin.insurerName}" — attests PRAIRIE WIND's policy → ${r2.reasonCode}: ${(r2.evidence as Ev)?.error}`);
    if (r2.reasonCode !== "INSURER_NOT_OF_RECORD") throw new Error("part 2: same-named filer accepted as of record");
    findings.push({ label: "part 2: by account, not by name", reasonCode: "INSURER_NOT_OF_RECORD", by: "venue.identity", detail: "the filing on the carrier's record names the filer account that submitted it; another account with the same licensed name — real license, real key, real registration — is of record for nothing it did not file. Name collisions stop mattering" });

    // ---- Part 3: a thief with the current key cannot appoint a successor; the regulator can; compromise voids what followed.
    const thiefKey = generateKeyPair();
    const r3a = await h.registry.rotateFilerKey({ insurerId: gpm.insurerId, publicKey: thiefKey.publicJwk, kid: thiefKey.kid });
    const r3b = await h.registry.rotateFilerKey({ insurerId: gpm.insurerId, publicKey: thiefKey.publicJwk, kid: thiefKey.kid, licensedBy: signRegulatorAttestation(gpm.kp, regulator.regulatorId, { naicCode: gpm.naicCode, legalName: gpm.insurerName, publicKey: thiefKey.publicJwk }) });
    say(`part 3: a thief holding ${gpm.insurerId}'s current key tries to register a successor key → ${r3a.ok ? "REGISTERED (!)" : `${r3a.reasonCode}: ${(r3a as { evidence: Ev }).evidence.error}`}; with a "regulator attestation" signed by the stolen key → ${r3b.ok ? "REGISTERED (!)" : r3b.reasonCode}`);
    if (r3a.ok || r3a.reasonCode !== "FILER_ROTATION_UNAUTHORIZED" || r3b.ok) throw new Error("part 3: the current key appointed its successor");
    const k2 = generateKeyPair();
    const theftAt = new Date().toISOString(); // after the control commitment, before the thief speaks
    const rot = await h.rotateFilerKey({ insurerId: gpm.insurerId, publicKey: k2.publicJwk, kid: k2.kid, licensedBy: regulator.license({ naicCode: gpm.naicCode, legalName: gpm.insurerName, publicKey: k2.publicJwk }) });
    const rev = await h.revokeFilerKey({ insurerId: gpm.insurerId, kid: gpm.kp.kid, revokedAt: theftAt, reason: "COMPROMISE", authorization: gpm.selfRevoke(k2, { kid: gpm.kp.kid, revokedAt: theftAt, reason: "COMPROMISE" }) });
    await new Promise((r) => setTimeout(r, 1200));
    const thiefWord = gpm.signWith(gpm.kp, { ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const r3c = await carrier.presentInsurance(thiefWord);
    const today = [await h.registry.attestFiler(gpm.insurerId)];
    const v0today = verify(art0, { currentFilerAttestations: today });
    say(`   the regulator licenses ${k2.kid.slice(0, 12)}… → rotation ${rot.every((o) => o.ok) ? "accepted" : "refused"}; ${gpm.insurerId} revokes the stolen key as COMPROMISED as of ${theftAt.slice(11, 19)}Z (signed with the new key) → ${rev.every((o) => o.ok) ? "recorded" : "refused"}; the thief's COI → ${r3c.reasonCode}`);
    say(`   the control commitment (signed ${coi.asOf.slice(11, 19)}Z, before the theft) with the registry's word today → ${v0today.ok ? "VERIFIED" : v0today.reasonCode}`);
    if (!rot.every((o) => o.ok) || !rev.every((o) => o.ok) || r3c.reasonCode !== "INSURER_KEY_NOT_OF_RECORD" || !v0today.ok) throw new Error(`part 3: rotation/compromise not handled (${r3c.reasonCode} / ${v0today.reasonCode})`);
    findings.push(
      { label: "part 3: the party that uses a key does not hold the authority to replace it", reasonCode: "FILER_ROTATION_UNAUTHORIZED", by: "registry.onboarding", detail: "the same principle as agent keys (the principal), the venue key (the root) and the root (its pre-commitment): a filer's successor is licensed by the regulator, never appointed by the current key, so a stolen key cannot become permanent. The current key may revoke itself — harmless in a thief's hands — and a compromise revocation as of a time voids what the key signed after it while leaving what came before" },
      { label: "what this leaves", detail: "the regulator: its honesty about who it licenses and the distribution of its key, which is the one binding that is the law's rather than a protocol's — the terminus every earlier entry pointed at. Below it there is nothing to sign with" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "FILER_UNLICENSED",
      refusedBy: "registry.onboarding",
      evidence: { attempted: { insurerId: "gpm-fraud", legalName: gpm.insurerName, kid: fraud.kid }, withoutRegulatorWord: (r1a as { evidence: Ev }).evidence, withForgedRegulatorWord: (r1b as { evidence: Ev }).evidence, registeredFilers: (await filers()).map((f) => ({ insurerId: f.insurerId, legalName: f.legalName, naicCode: f.naicCode })) },
      guaranteeWouldHavePaid: "N/A — refused at the registry, before any venue saw a key. Had the fraudster been registered, its word would still not have been of record for a filing it did not submit; the two anchors are independent, and both had to fail for an impostor to become the origin.",
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "present-insurance" && e.outcome === "REFUSED")],
    };
  },
};
