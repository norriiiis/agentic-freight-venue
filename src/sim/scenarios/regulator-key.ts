import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec, blueMesaCarrierSpec } from "../fixtures";
import { negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { generateKeyPair, type OkpJwk } from "../../protocol/crypto";
import { rootCommitment, signRootEvent } from "../../protocol/venue-keys";
import { signInsurerAttestation, signRegulatorAttestation } from "../../protocol/registry";

type Ev = { error?: string; offeredKid?: string; currentKid?: string; regulatorAnchor?: { regulatorId: string; kid?: string; source: string }[] };

export const regulatorKey: Scenario = {
  id: "regulator-key",
  title: "How anyone knows the regulator's key: a pre-rotation log learned once, mirrored by the registries, that a thief cannot move and a registry cannot be handed",
  summary: "Nothing sits above a regulator to vouch for it, so its identity is the same construction as the venue root's: a key-event log with pre-rotation. Each key commits to the hash of its successor; a rotation reveals the committed key and is signed by it; a compromise is declared by the successor as of a time. Whoever learned any key once follows every rotation mechanically and can never be walked to a key the regulator did not pre-commit to. The registries mirror the log as a record, so a party that pins only the registries learns the regulator's identity from k independent mirrors. Control: a verifier that pinned the regulator's establishment key, and one that pinned only the registries, both verify. Part 1: the regulator rotates; a filer licensed under the new key is accepted; the verifier that pinned the old key follows the log through the artifact. Part 2: a thief holding the regulator's current key publishes a 'rotation' to their own key — refused by the registries, because rotation needs the key the regulator holds offline. Part 3: a registry cannot be handed a new regulator root by anyone. Part 4: the regulator declares its key compromised as of a time; licenses it signed after that are void, earlier ones stand.",
  expect: { outcome: "REFUSED", reasonCode: "REGULATOR_ROTATION_UNAUTHORIZED", refusedBy: "registry.onboarding" },
  async run({ h, say }) {
    await h.startRegistries(["li-mirror-a", "li-mirror-b"]);
    h.opts.venue = { registryQuorum: 2 };
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    await h.venue.seedHistory("1984411", CARRIER_HISTORY);
    const regulator = await h.regulator();
    const gpm = await h.startInsurer("great-plains-mutual", "Great Plains Mutual Insurance Co", { naicCode: "24601" });
    const policy = { usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };
    const coi = gpm.attest({ ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" });
    const broker = await h.startAgent(brokerSpec({ thinkMs: 60, limits: { ...brokerSpec().limits, requireInsurerAttestation: true } }));
    const carrier = await h.startAgent(carrierSpec({ thinkMs: 60, insurerAttestation: coi }));
    const keys = await Promise.all(h.registries.map((r) => r.key()));
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (id: string) => JSON.parse(readFileSync(join(broker.dir, "commitments", `${id}.json`), "utf8")) as CommitmentArtifact;
    // Two verifiers: one pinned the regulator's ESTABLISHMENT key long ago; one pins only the registries.
    const pinnedOnce = (art: CommitmentArtifact, extra: Parameters<typeof verifyArtifact>[1] = {}) => verifyArtifact(art, { pinnedRootKey: root, registryKeys: keys, regulatorKeys: [regulator.key], requireInsurerAttestation: true, ...extra });
    const registriesOnly = (art: CommitmentArtifact, extra: Parameters<typeof verifyArtifact>[1] = {}) => verifyArtifact(art, { pinnedRootKey: root, registryKeys: keys, requireInsurerAttestation: true, ...extra });
    const anchor = (v: ReturnType<typeof verifyArtifact>) => v.checks.find((c) => c.name === `carrier.regulator[${regulator.regulatorId}].anchored`)?.detail;
    const findings: Finding[] = [];
    const near = (loadRef: string, commodity: string, weightLbs: number) => ({ ...LOAD, loadRef, commodity, weightLbs });

    // ---- Control.
    const c0 = await negotiate(h, broker, carrier, LOAD);
    const art0 = artifactOf(c0.task!.commitmentId!);
    const v0a = pinnedOnce(art0);
    const v0b = registriesOnly(art0);
    say(`control: ${c0.task!.status} — the artifact carries the registries' word on ${regulator.regulatorId}'s key log (${art0.insurance?.regulators?.map((r) => r.registryId).join(", ")}; ${art0.insurance?.regulators?.[0]?.log?.length} event(s), head ${regulator.kp.kid.slice(0, 12)}…)`);
    say(`   verifier that pinned the establishment key → ${v0a.ok ? "VERIFIED" : v0a.reasonCode}: ${anchor(v0a)}`);
    say(`   verifier that pins only the registries → ${v0b.ok ? "VERIFIED" : v0b.reasonCode}: ${anchor(v0b)}`);
    if (!v0a.ok || !v0b.ok) throw new Error(`control failed: ${[...v0a.checks, ...v0b.checks].filter((x) => !x.ok).map((x) => `${x.name}: ${x.detail}`).join("; ")}`);
    findings.push({ label: "control: two ways to know the regulator", detail: "pin any key the regulator ever had — you learned it once — and walk its log; or pin nothing but the registries, and take who the regulator is from k independent mirrors that attest the same log. Either way the licensing signature is checked, not assumed" });

    // ---- Part 1: the regulator rotates; the old pin still resolves the new key through the log.
    const k0 = regulator.kp.kid;
    const rot = await regulator.rotate();
    await new Promise((r) => setTimeout(r, 1200));
    const fcc = await h.startInsurer("four-corners-casualty", "Four Corners Casualty", { naicCode: "31007" });
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 60, insurerAttestation: fcc.attest({ usdot: "1984411", policyNumber: "FC-88210-25", type: "BIPD", form: "BMC-91X", coverageToUsd: 1_000_000, effectiveDate: "2025-01-01", undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" }) }));
    const c1 = await negotiate(h, broker, carrier2, near("L-2026-263-1201", "Bagged fertilizer, palletized", 41_600));
    const art1 = artifactOf(c1.task!.commitmentId!);
    const v1 = pinnedOnce(art1);
    say(`part 1: ${regulator.regulatorId} rotates ${k0.slice(0, 12)}… → ${rot.rootKid.slice(0, 12)}… (the pre-committed successor; seq ${rot.seq}); both registries accept the event. ${fcc.insurerId} is licensed under the NEW key; ${carrier2.spec.agentId} commits (${c1.task!.status}); the verifier that pinned the OLD key → ${v1.ok ? "VERIFIED" : v1.reasonCode}: ${anchor(v1)}`);
    if (c1.task!.status !== "COMMITTED" || !v1.ok) throw new Error(`part 1: rotation not followed (${v1.reasonCode}: ${v1.checks.filter((x) => !x.ok).map((x) => x.detail).join("; ")})`);
    findings.push({ label: "part 1: learn once, follow forever", detail: "the verifier pinned the regulator years ago; the rotation reached it through the artifact, whose registries' word carries the log, and the walk from the old key to the new one needs nothing from anyone — the commitment was in the old key's event" });

    // ---- Part 2: a thief holding the regulator's CURRENT key publishes a rotation to their own key.
    const thief = generateKeyPair();
    const forged = regulator.forgeRotation(thief);
    const r2 = await Promise.all(h.registries.map((r) => r.regulatorEvent(regulator.regulatorId, forged)));
    say(`part 2: a thief with the regulator's current key signs a "rotation" (seq ${forged.seq}, countersigned by the stolen key) to ${thief.kid.slice(0, 12)}… → ${r2.map((o, i) => `${h.registries[i]!.registryId}: ${o.ok ? "ACCEPTED (!)" : `${o.reasonCode} — ${(o.evidence as Ev)?.error}`}`).join("; ")}`);
    if (r2.some((o) => o.ok) || r2.some((o) => o.reasonCode !== "REGULATOR_ROTATION_UNAUTHORIZED")) throw new Error("part 2: forged regulator rotation accepted");
    findings.push({ label: "part 2: rotation needs the key held offline", reasonCode: "REGULATOR_ROTATION_UNAUTHORIZED", by: "registry.onboarding", detail: "the current key's signature on a rotation is worth nothing: the successor must be the key the previous event committed to, and must sign for itself. A thief who stole the signing key did not steal the pre-committed successor, so the regulator's identity cannot be taken — only, at worst, used until the compromise is declared" });

    // ---- Part 3: nobody can hand a registry a new regulator root.
    const fake = generateKeyPair();
    const fakeEst = signRootEvent(fake, { seq: 0, nextRootCommitment: rootCommitment(generateKeyPair().publicJwk), at: new Date().toISOString(), reason: "ESTABLISHMENT" });
    const r3 = await h.registries[0]!.pinRegulator({ regulatorId: regulator.regulatorId, establishment: fakeEst });
    say(`part 3: ${h.registries[0]!.registryId}'s operator is handed a fresh "establishment" for ${regulator.regulatorId} under key ${fake.kid.slice(0, 12)}… → ${r3.ok ? "ACCEPTED (!)" : `${r3.reasonCode}: ${(r3.evidence as Ev)?.error}`}`);
    if (r3.ok || r3.reasonCode !== "REGULATOR_ROTATION_UNAUTHORIZED") throw new Error("part 3: registry accepted a new regulator root");
    findings.push({ label: "part 3: a registry bootstraps a regulator once", reasonCode: "REGULATOR_ROTATION_UNAUTHORIZED", by: "registry.onboarding", detail: "after the first establishment, a registry's knowledge of the regulator moves only by pre-committed rotation events the regulator publishes; its operator cannot be talked into a different root. The bootstrap itself is the ceremony every root has — the law's binding, done once" });

    // ---- Part 4: compromise. What the stolen key signed after the declared time is void; before it stands.
    const stolen = regulator.kp; // the current key leaks; the thief licenses an impostor under it
    const impostor = generateKeyPair();
    const leakAt = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 50));
    const badLicense = { naicCode: "24601", legalName: gpm.insurerName, publicKey: impostor.publicJwk };
    const stolenLic = signRegulatorAttestation(stolen, regulator.regulatorId, badLicense);
    const onboarded = await h.registerFiler({ insurerId: "gpm-impostor", legalName: gpm.insurerName, publicKey: impostor.publicJwk, kid: impostor.kid, licensedBy: stolenLic });
    const comp = await regulator.compromise(leakAt);
    await new Promise((r) => setTimeout(r, 1200));
    const r4 = await carrier.presentInsurance(signInsurerAttestation(impostor, "gpm-impostor", { ...policy, undertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" }, undefined, gpm.insurerName));
    const today = await Promise.all(h.registries.map((r) => r.attestRegulator(regulator.regulatorId)));
    const v1today = pinnedOnce(art1, { currentRegulatorAttestations: today });
    say(`part 4: the current key leaks; before anyone knows, a thief licenses "gpm-impostor" under it and the registries onboard it (${onboarded.every((o) => o.ok) ? "registered" : "refused"}). The regulator declares the key COMPROMISED as of ${leakAt.slice(11, 19)}Z (event seq ${comp.seq}, signed by the pre-committed successor).`);
    say(`   the impostor's COI (its filer key licensed at ${stolenLic.asOf.slice(11, 19)}Z, after the compromise time) → ${r4.reasonCode}: ${(r4.evidence as Ev)?.error?.slice(0, 120)}`);
    say(`   part 1's commitment (${fcc.insurerId} licensed at ${art1.insurance?.filers?.carrier?.[0]?.registration?.keys[0]?.licensedBy?.asOf.slice(11, 19)}Z, before it) with the registries' word today → ${v1today.ok ? "VERIFIED" : v1today.reasonCode}`);
    if (r4.reasonCode !== "REGULATOR_KEY_UNTRUSTED" || !v1today.ok) throw new Error(`part 4: compromise semantics wrong (${r4.reasonCode} / ${v1today.reasonCode}: ${v1today.checks.filter((x) => !x.ok).map((x) => x.detail).join("; ")})`);
    findings.push(
      { label: "part 4: a stolen regulator key buys a window, not an identity", reasonCode: "REGULATOR_KEY_UNTRUSTED", by: "venue.identity", detail: "licenses the stolen key signed after the declared compromise time are void wherever the log is read — the venue, every mirror, every verifier — while licenses it signed before stand. The blast radius is the detection window, exactly as for the venue root" },
      { label: "what this leaves", detail: "the regulator's founding ceremony and the separate custody of its pre-committed next key, and its honesty about whom it licenses. That is where a chain of signatures reaches the law and stops: below the regulator there is no key, only a statute" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "REGULATOR_ROTATION_UNAUTHORIZED",
      refusedBy: "registry.onboarding",
      evidence: { forgedEvent: { seq: forged.seq, offeredKid: forged.rootKid, signedBy: "the thief, countersigned by the stolen current key" }, registries: Object.fromEntries(r2.map((o, i) => [h.registries[i]!.registryId, { reasonCode: o.reasonCode, ...(o.evidence as Ev) }])) },
      guaranteeWouldHavePaid: "N/A — refused at the registries before any license could be signed under the thief's key. Had a registry accepted the forged rotation, every filer the thief licensed would have looked regulator-backed to anyone trusting that registry alone; the pre-commitment is what makes the regulator's identity nobody's to take.",
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "present-insurance" && e.outcome === "REFUSED")],
    };
  },
};
