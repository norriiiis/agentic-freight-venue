import { describe, it, expect } from "vitest";
import { generateKeyPair, signJws } from "../src/protocol/crypto";
import { attestationFreshAt, contradictedBy, coverageAssuredThrough, filingsShownBy, insurerStanding, signAttestation, signInsurerAttestation, standing, verifyAttestation, verifyInsurerAttestation, type RegistryAttestation, type RegistryRecord } from "../src/protocol/registry";
import { buildArtifact, verifyArtifact } from "../src/ledger/artifact";
import { signCert } from "../src/protocol/venue-keys";
import { buildMessage, signMessage } from "../src/protocol/envelope";
import { termsHash, type Terms } from "../src/protocol/freight";
import type { Credential } from "../src/protocol/types";
import { LOAD } from "../src/sim/fixtures";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const records = JSON.parse(readFileSync(join(import.meta.dirname, "../src/identity/fixtures/registry.json"), "utf8")) as (RegistryRecord & { _proofOfControlToken: string; _vettingFlags: string[] })[];
const pub = (usdot: string): RegistryRecord => {
  const { _proofOfControlToken: _t, _vettingFlags: _f, ...r } = records.find((x) => x.usdot === usdot)!;
  return r;
};
const CARRIER = "2751903";
const BROKER = "3312874";
const T = new Date("2026-09-20T12:00:00.000Z");
const cancelled = (rec: RegistryRecord, on: string): RegistryRecord => ({ ...rec, insurance: rec.insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: on } : f)) });

describe("registry attestation", () => {
  it("signs the record with the registry's clock and verifies only under that key", () => {
    const reg = generateKeyPair();
    const a = signAttestation(reg, "fmcsa-li-mock", CARRIER, pub(CARRIER), T);
    expect(verifyAttestation(a, reg.publicJwk)).toBe(true);
    expect(verifyAttestation(a, generateKeyPair().publicJwk)).toBe(false);
    // Any edit — to the record, the clock, or the subject — breaks it.
    expect(verifyAttestation({ ...a, asOf: "2026-09-21T12:00:00.000Z" }, reg.publicJwk)).toBe(false);
    expect(verifyAttestation({ ...a, record: cancelled(a.record!, "2026-09-01") }, reg.publicJwk)).toBe(false);
    expect(verifyAttestation({ ...a, usdot: BROKER }, reg.publicJwk)).toBe(false);
    // A signed "not found" is a valid attestation too.
    const none = signAttestation(reg, "fmcsa-li-mock", "0000000", null, T);
    expect(verifyAttestation(none, reg.publicJwk)).toBe(true);
    expect(none.recordHash).toBe("");
  });

  it("freshness is judged at the moment of reliance", () => {
    const reg = generateKeyPair();
    const a = signAttestation(reg, "r", CARRIER, pub(CARRIER), T);
    expect(attestationFreshAt(a, new Date(T.getTime() + 1000), 5000).ok).toBe(true);
    expect(attestationFreshAt(a, new Date(T.getTime() + 6000), 5000)).toMatchObject({ ok: false, ageMs: 6000 });
    // From the future beyond skew: a clock is wrong; not "fresh".
    expect(attestationFreshAt(a, new Date(T.getTime() - 120_000), 5000, 60_000).ok).toBe(false);
  });
});

describe("standing over a registry record", () => {
  it("knows a cancellation ahead of time", () => {
    const rec = pub(CARRIER);
    expect(standing(rec, T).ok).toBe(true);
    // Already effective: lapsed now.
    expect(standing(cancelled(rec, "2026-09-18"), T)).toMatchObject({ ok: false, reasonCode: "INSURANCE_LAPSED" });
    // Filed for a date after the commitment but before delivery: the carrier would be uninsured in transit.
    const pending = standing(cancelled(rec, "2026-09-24"), T, { through: new Date("2026-09-24T21:00:00.000Z") });
    expect(pending).toMatchObject({ ok: false, reasonCode: "INSURANCE_CANCELLATION_PENDING" });
    expect((pending.evidence.cancellingBeforeThrough as { cancellationDate: string }[])[0]!.cancellationDate).toBe("2026-09-24");
    // Cancelling after delivery: fine for this load.
    expect(standing(cancelled(rec, "2026-09-25"), T, { through: new Date("2026-09-24T21:00:00.000Z") }).ok).toBe(true);
    expect(standing(null, T)).toMatchObject({ ok: false, reasonCode: "ONBOARDING_ENTITY_NOT_FOUND" });
  });
});

// ---- the artifact: what the venue relied on, held to its own policy, and rerun by the verifier

function cred(venue: ReturnType<typeof generateKeyPair>, agent: ReturnType<typeof generateKeyPair>, agentId: string, usdot: string, mc: string, entityType: Credential["subject"]["entity"]["entityType"]): Credential {
  const unsigned = {
    credentialId: `cred_${agentId}`, schema: "freight-venue/agent-credential/v1" as const,
    subject: { agentId, entity: { usdot, mc, legalName: agentId.toUpperCase(), entityType }, publicKey: agent.publicJwk },
    issuer: { venueId: "v", kid: venue.kid }, issuedAt: new Date(T.getTime() - 86_400_000).toISOString(), expiresAt: new Date(T.getTime() + 86_400_000).toISOString(),
    evidence: { registrySnapshotHash: "x", registryCheckedAt: "", insuranceCheckedAt: "", vettingProvider: "stub", vettingFlags: [], proofOfControl: "stub" },
  };
  return { ...unsigned, issuerSignature: signJws(unsigned, venue, { typ: "agent-credential+jws" }, true) };
}

function makeArtifact(registry: ReturnType<typeof generateKeyPair>, atts: { broker: RegistryAttestation | RegistryAttestation[]; carrier: RegistryAttestation | RegistryAttestation[] }, policyMs = 60_000, opts: { registries?: { registryId: string; publicKey: import("../src/protocol/crypto").OkpJwk }[]; quorum?: number } = {}) {
  const root = generateKeyPair();
  const venue = generateKeyPair();
  const cert = signCert(root, venue.publicJwk, 0, "INITIAL", new Date(T.getTime() - 2 * 86_400_000));
  const b = generateKeyPair();
  const c = generateKeyPair();
  const bc = cred(venue, b, "broker-1", BROKER, "MC-1088412", "BROKER");
  const cc = cred(venue, c, "carrier-1", CARRIER, "MC-0938251", "CARRIER");
  const terms: Terms = { loadRef: LOAD.loadRef, load: LOAD, rateUsd: 2215, pickup: { windowStart: LOAD.origin.windowStart, windowEnd: LOAD.origin.windowEnd }, delivery: { windowStart: LOAD.destination.windowStart, windowEnd: LOAD.destination.windowEnd }, paymentTermsDays: 30, brokerAgentId: "broker-1", carrierAgentId: "carrier-1", brokerEntity: { usdot: BROKER, mc: "MC-1088412" }, carrierEntity: { usdot: CARRIER, mc: "MC-0938251" } };
  const accept = (kp: ReturnType<typeof generateKeyPair>, agentId: string, credentialId: string) =>
    signMessage(buildMessage({ role: "user", data: { type: "ACCEPT", loadRef: terms.loadRef, round: 3, terms, termsHash: termsHash(terms), from: { agentId, usdot: "x" } }, taskId: "t", contextId: "c", senderAgentId: agentId, credentialId }), kp);
  const a = buildArtifact(
    { venue: { venueId: "v", rootPublicKey: root.publicJwk, certs: [cert] }, terms, termsHash: termsHash(terms), acceptances: { broker: accept(b, "broker-1", bc.credentialId), carrier: accept(c, "carrier-1", cc.credentialId) }, credentials: { broker: bc, carrier: cc }, registry: { registries: opts.registries ?? [{ registryId: "fmcsa-li-mock", publicKey: registry.publicJwk }], attestations: { broker: [atts.broker].flat(), carrier: [atts.carrier].flat() }, policy: { maxAgeMs: policyMs, quorum: opts.quorum ?? 1 } }, underwriting: { decision: "GUARANTEED", riskScore: 0.01, guarantee: { guaranteeId: "g", coveredAmountUsd: 2215, premiumUsd: 40, scope: [], exclusions: [], conditions: [] } }, ledger: { seq: 1, prevHash: "0".repeat(64) } },
    venue,
  );
  // buildArtifact stamps createdAt with the wall clock; the attestations are relative to it.
  return { artifact: a, root: root.publicJwk, registryKey: { registryId: "fmcsa-li-mock", publicKey: registry.publicJwk } };
}

describe("artifact carries the registry's word", () => {
  const reg = generateKeyPair();
  const fresh = (usdot: string, rec = pub(usdot), ageMs = 0) => signAttestation(reg, "fmcsa-li-mock", usdot, rec, new Date(Date.now() - ageMs));

  it("verifies when the word is fresh, genuine, and consistent with committing", () => {
    const { artifact, root, registryKey } = makeArtifact(reg, { broker: fresh(BROKER), carrier: fresh(CARRIER) });
    const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [registryKey] });
    expect(v.ok, JSON.stringify(v.checks.filter((c) => !c.ok))).toBe(true);
    expect(v.checks.find((c) => c.name === "carrier.registry.standing-at-commitment")?.ok).toBe(true);
  });

  it("REGISTRY_STALE: the venue relied on word older than the policy it declares", () => {
    const { artifact, root, registryKey } = makeArtifact(reg, { broker: fresh(BROKER), carrier: fresh(CARRIER, pub(CARRIER), 120_000) }, 60_000);
    const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [registryKey] });
    expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_STALE" });
    // A verifier with a laxer policy of its own may accept it; a stricter one may not.
    expect(verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [registryKey], maxRegistryAgeMs: 600_000 }).ok).toBe(true);
  });

  it("REGISTRY_CONTRADICTS_COMMITMENT: the venue's own embedded word shows the lapse", () => {
    const { artifact, root, registryKey } = makeArtifact(reg, { broker: fresh(BROKER), carrier: fresh(CARRIER, cancelled(pub(CARRIER), "2026-09-18")) });
    const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [registryKey] });
    expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_CONTRADICTS_COMMITMENT" });
    expect(v.checks.find((c) => c.name === "carrier.registry.standing-at-commitment")?.detail).toContain("INSURANCE_LAPSED");
  });

  it("REGISTRY_CONTRADICTS_COMMITMENT: the registry's word fetched later settles it without the venue", () => {
    // The venue embedded pre-cancellation word (fresh enough, so no STALE); today's record shows the filing was already cancelled then.
    const { artifact, root, registryKey } = makeArtifact(reg, { broker: fresh(BROKER), carrier: fresh(CARRIER) });
    const today = signAttestation(reg, "fmcsa-li-mock", CARRIER, cancelled(pub(CARRIER), "2026-09-18"), new Date(Date.now() + 3_600_000));
    const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [registryKey], currentAttestations: [today] });
    expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_CONTRADICTS_COMMITMENT" });
    // A pending-at-the-time cancellation before delivery counts too.
    const pending = signAttestation(reg, "fmcsa-li-mock", CARRIER, cancelled(pub(CARRIER), "2026-09-24"), new Date(Date.now() + 3_600_000));
    const v2 = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [registryKey], currentAttestations: [pending] });
    expect(v2.checks.find((c) => c.name === "carrier.registry.standing-per-current-record")?.detail).toContain("INSURANCE_CANCELLATION_PENDING");
  });

  it("REGISTRY_ATTESTATION_INVALID: forged, re-keyed, or about someone else", () => {
    const impostor = generateKeyPair();
    const forged = signAttestation(impostor, "fmcsa-li-mock", CARRIER, pub(CARRIER), new Date());
    const { artifact, root, registryKey } = makeArtifact(reg, { broker: fresh(BROKER), carrier: forged });
    expect(verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [registryKey] })).toMatchObject({ ok: false, reasonCode: "REGISTRY_ATTESTATION_INVALID" });
    // Without a pinned key the verifier falls back to the EMBEDDED key — which is the real registry's here, so the forgery still fails.
    expect(verifyArtifact(artifact, { pinnedRootKey: root })).toMatchObject({ ok: false, reasonCode: "REGISTRY_ATTESTATION_INVALID" });
    // The venue naming a different "registry" than the one the verifier pins.
    const other = makeArtifact(impostor, { broker: signAttestation(impostor, "fmcsa-li-mock", BROKER, pub(BROKER)), carrier: forged });
    expect(verifyArtifact(other.artifact, { pinnedRootKey: other.root, registryKeys: [registryKey] })).toMatchObject({ ok: false, reasonCode: "REGISTRY_ATTESTATION_INVALID" });
    // Subject swap: the carrier's slot carries the broker's attestation.
    const swapped = makeArtifact(reg, { broker: fresh(BROKER), carrier: fresh(BROKER) });
    expect(verifyArtifact(swapped.artifact, { pinnedRootKey: swapped.root, registryKeys: [registryKey] })).toMatchObject({ ok: false, reasonCode: "REGISTRY_ATTESTATION_INVALID" });
  });

  it("REGISTRY_ATTESTATION_MISSING: a verifier that pins the registry does not take 'we checked' on trust", () => {
    const { artifact, root, registryKey } = makeArtifact(reg, { broker: fresh(BROKER), carrier: fresh(CARRIER) });
    // (Stripping the field also breaks the venue attestation, since it is inside the content hash — a venue that never
    // embedded one would have signed without it. Either way the pinned verifier reports the absence.)
    const stripped = { ...artifact, registry: undefined } as typeof artifact;
    const v = verifyArtifact(stripped, { pinnedRootKey: root, registryKeys: [registryKey] });
    expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_ATTESTATION_MISSING" });
    expect(v.checks.find((c) => c.name === "registry.attestations-present")?.ok).toBe(false);
    // A verifier that pins no registry runs no registry checks on an artifact that carries none (pre-attestation artifacts).
    expect(verifyArtifact(stripped, { pinnedRootKey: root }).checks.some((c) => c.name.startsWith("registry.") || c.name.includes(".registry."))).toBe(false);
  });

  describe("several registries", () => {
    const A = generateKeyPair(), B = generateKeyPair(), C = generateKeyPair();
    const keys = [{ registryId: "mirror-a", publicKey: A.publicJwk }, { registryId: "mirror-b", publicKey: B.publicJwk }, { registryId: "mirror-c", publicKey: C.publicJwk }];
    const word = (kp: ReturnType<typeof generateKeyPair>, id: string, usdot: string, rec = pub(usdot), ageMs = 0) => signAttestation(kp, id, usdot, rec, new Date(Date.now() - ageMs));
    const three = (usdot: string, recs: [RegistryRecord, RegistryRecord, RegistryRecord] = [pub(usdot), pub(usdot), pub(usdot)]) => [word(A, "mirror-a", usdot, recs[0]), word(B, "mirror-b", usdot, recs[1]), word(C, "mirror-c", usdot, recs[2])];
    const build = (carrier: RegistryAttestation[], quorum = 2) => makeArtifact(A, { broker: three(BROKER), carrier }, 60_000, { registries: keys, quorum });

    it("verifies with a quorum of unanimous registries", () => {
      const { artifact, root } = build(three(CARRIER));
      const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: keys });
      expect(v.ok, JSON.stringify(v.checks.filter((c) => !c.ok))).toBe(true);
      expect(v.checks.find((c) => c.name === "carrier.registry.quorum")?.detail).toContain("3 pinned registries");
    });

    it("unanimity: one registry's word of a lapse blocks, however many say otherwise", () => {
      const lapsed = cancelled(pub(CARRIER), "2026-09-18");
      const { artifact, root } = build(three(CARRIER, [pub(CARRIER), pub(CARRIER), lapsed]));
      const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: keys });
      expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_CONTRADICTS_COMMITMENT" });
      expect(v.checks.find((c) => c.name === "carrier.registry.standing-at-commitment")?.detail).toMatch(/mirror-c: INSURANCE_LAPSED.*mirror-a, mirror-b showed standing/);
    });

    it("REGISTRY_QUORUM_NOT_MET: too few pinned registries vouch, or a named one is absent", () => {
      // The venue embedded only mirror-a's word (quorum 2 declared).
      const { artifact, root } = build([word(A, "mirror-a", CARRIER)]);
      expect(verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: keys })).toMatchObject({ ok: false, reasonCode: "REGISTRY_QUORUM_NOT_MET" });
      // A verifier that pins only mirror-a and needs 1 is satisfied…
      expect(verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: [keys[0]!], minRegistries: 1 }).ok).toBe(true);
      // …unless it names a registry the venue left out.
      const full = build(three(CARRIER));
      const dropped = { ...full.artifact, registry: { ...full.artifact.registry!, attestations: { ...full.artifact.registry!.attestations, carrier: full.artifact.registry!.attestations.carrier.filter((x) => x.registryId !== "mirror-c") } } };
      const v = verifyArtifact(dropped, { pinnedRootKey: full.root, registryKeys: keys, requiredRegistries: ["mirror-c"] });
      expect(v.reasonCode).toBe("REGISTRY_QUORUM_NOT_MET");
      expect(v.checks.find((c) => c.name === "carrier.registry.quorum")?.detail).toContain("required registry mirror-c absent");
      // Unpinned registries in the artifact do not count toward the verifier's quorum.
      const strangers = build([word(generateKeyPair(), "mirror-x", CARRIER), word(generateKeyPair(), "mirror-y", CARRIER)]);
      expect(verifyArtifact(strangers.artifact, { pinnedRootKey: strangers.root, registryKeys: keys })).toMatchObject({ ok: false, reasonCode: "REGISTRY_QUORUM_NOT_MET" });
    });

    it("REGISTRY_STALE vs QUORUM: stale signatures explain a missed quorum", () => {
      const { artifact, root } = build([word(A, "mirror-a", CARRIER), word(B, "mirror-b", CARRIER, pub(CARRIER), 120_000), word(C, "mirror-c", CARRIER, pub(CARRIER), 120_000)]);
      expect(verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: keys })).toMatchObject({ ok: false, reasonCode: "REGISTRY_STALE" });
    });

    it("REGISTRY_DISAGREEMENT: mirrors differ on the facts without differing on the verdict", () => {
      // mirror-c shows a cancellation effective long after delivery: still in standing, but not the same record.
      const later = cancelled(pub(CARRIER), "2027-01-01");
      const { artifact, root } = build(three(CARRIER, [pub(CARRIER), pub(CARRIER), later]));
      const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: keys });
      expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_DISAGREEMENT" });
      expect(v.checks.find((c) => c.name === "carrier.registry.standing-at-commitment")?.ok).toBe(true);
    });

    it("current word from several registries: any lapse blocks, and the split is named", () => {
      const { artifact, root } = build(three(CARRIER));
      const today = [word(A, "mirror-a", CARRIER, cancelled(pub(CARRIER), "2026-09-18"), -3_600_000), word(B, "mirror-b", CARRIER, pub(CARRIER), -3_600_000)];
      const v = verifyArtifact(artifact, { pinnedRootKey: root, registryKeys: keys, currentAttestations: today });
      expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_CONTRADICTS_COMMITMENT" });
      expect(v.checks.find((c) => c.name === "carrier.registry.standing-per-current-record")?.detail).toMatch(/mirror-a.*INSURANCE_LAPSED.*mirror-b say otherwise/);
    });
  });

  describe("accountability and the origin", () => {
    const A = generateKeyPair(), B = generateKeyPair();
    const keys = [{ registryId: "mirror-a", publicKey: A.publicJwk }, { registryId: "mirror-b", publicKey: B.publicJwk }];
    const ins = generateKeyPair();
    const insurerKey = { witnessId: "gpm", publicKey: ins.publicJwk };
    const now = new Date();
    const dayOff = (d: number) => new Date(now.getTime() + d * 86_400_000).toISOString().slice(0, 10);
    const withFiling = (rec: RegistryRecord, filed: string, effective: string): RegistryRecord => ({ ...rec, insurance: rec.insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: effective, cancellationFiledDate: filed } : f)) });
    const policy = { usdot: CARRIER, policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };

    it("freshness is judged on the mirror's sync claim, not its signing clock", () => {
      // An honest frozen mirror: signed now, synced an hour ago — stale under a 5-minute policy.
      const honest = signAttestation(A, "mirror-a", CARRIER, pub(CARRIER), now, new Date(now.getTime() - 3_600_000));
      expect(attestationFreshAt(honest, now, 300_000).ok).toBe(false);
      // A lying frozen mirror: claims a current sync — passes freshness, and answers for the record.
      const liar = signAttestation(A, "mirror-a", CARRIER, pub(CARRIER), now, now);
      expect(attestationFreshAt(liar, now, 300_000).ok).toBe(true);
    });

    it("a mirror claiming a sync after a filing it does not show has signed a falsehood", () => {
      const liar = signAttestation(A, "mirror-a", CARRIER, pub(CARRIER), now, now);
      const honest = signAttestation(B, "mirror-b", CARRIER, withFiling(pub(CARRIER), dayOff(-1), dayOff(29)), now, now);
      const proof = contradictedBy(liar, filingsShownBy(honest));
      expect(proof).toMatchObject({ registryId: "mirror-a", missing: { source: "mirror-b", cancellationFiledDate: dayOff(-1) } });
      // An honest lagging mirror whose sync predates the filing is not contradicted — merely stale.
      const lagging = signAttestation(A, "mirror-a", CARRIER, pub(CARRIER), now, new Date(now.getTime() - 3 * 86_400_000));
      expect(contradictedBy(lagging, filingsShownBy(honest))).toBeUndefined();
      // Showing the same filing is not a contradiction; showing it filed later than claimed sync neither.
      expect(contradictedBy(honest, filingsShownBy(honest))).toBeUndefined();
    });

    it("the insurer's word: signed, assured through the statutory notice, and standing per its own disclosure", () => {
      const coi = signInsurerAttestation(ins, "gpm", policy, now);
      expect(verifyInsurerAttestation(coi, ins.publicJwk)).toBe(true);
      expect(verifyInsurerAttestation(coi, generateKeyPair().publicJwk)).toBe(false);
      expect(coverageAssuredThrough(coi).getTime()).toBe(now.getTime() + 30 * 86_400_000);
      expect(insurerStanding(coi, now, new Date(now.getTime() + 20 * 86_400_000)).ok).toBe(true);
      const disclosed = signInsurerAttestation(ins, "gpm", { ...policy, cancellation: { filedDate: dayOff(-1), effectiveDate: dayOff(29) } }, now);
      expect(coverageAssuredThrough(disclosed).toISOString().slice(0, 10)).toBe(dayOff(29));
      expect(insurerStanding(disclosed, now, new Date(now.getTime() + 35 * 86_400_000))).toMatchObject({ ok: false, reasonCode: "INSURANCE_CANCELLATION_PENDING" });
      expect(insurerStanding(disclosed, new Date(now.getTime() + 40 * 86_400_000))).toMatchObject({ ok: false, reasonCode: "INSURANCE_LAPSED" });
    });

    it("REGISTRY_FALSE_ATTESTATION: a colluding mirror in the artifact is convicted by any honest word", () => {
      const filedRec = withFiling(pub(CARRIER), dayOff(-1), dayOff(60)); // cancels well after delivery: standing fine, the lie is about the record
      const liar = signAttestation(A, "mirror-a", CARRIER, pub(CARRIER), now, now);
      const honest = signAttestation(B, "mirror-b", CARRIER, filedRec, now, now);
      // In the artifact itself: the venue embedded both, and mirror-b's word convicts mirror-a's (disagreement too, but the lie ranks first).
      const both = makeArtifact(A, { broker: [signAttestation(A, "mirror-a", BROKER, pub(BROKER)), signAttestation(B, "mirror-b", BROKER, pub(BROKER))], carrier: [liar, honest] }, 60_000, { registries: keys, quorum: 2 });
      expect(verifyArtifact(both.artifact, { pinnedRootKey: both.root, registryKeys: keys })).toMatchObject({ ok: false, reasonCode: "REGISTRY_FALSE_ATTESTATION" });
      // Only the liar embedded (quorum 1); the honest mirror's word today convicts it.
      const alone = makeArtifact(A, { broker: signAttestation(A, "mirror-a", BROKER, pub(BROKER)), carrier: liar }, 60_000, { registries: keys, quorum: 1 });
      expect(verifyArtifact(alone.artifact, { pinnedRootKey: alone.root, registryKeys: keys }).ok).toBe(true);
      const v = verifyArtifact(alone.artifact, { pinnedRootKey: alone.root, registryKeys: keys, currentAttestations: [signAttestation(B, "mirror-b", CARRIER, filedRec, new Date(now.getTime() + 3_600_000))] });
      expect(v).toMatchObject({ ok: false, reasonCode: "REGISTRY_FALSE_ATTESTATION" });
      expect(v.checks.find((c) => c.name === "carrier.registry[mirror-a].true-when-signed")?.detail).toContain("mirror-b show");
      // …or by the origin's word, which discloses the filing.
      const originsWord = signInsurerAttestation(ins, "gpm", { ...policy, cancellation: { filedDate: dayOff(-1), effectiveDate: dayOff(60) } }, now);
      expect(verifyArtifact(alone.artifact, { pinnedRootKey: alone.root, registryKeys: keys, insurerKeys: [insurerKey], currentInsurerAttestations: [originsWord] })).toMatchObject({ ok: false, reasonCode: "REGISTRY_FALSE_ATTESTATION" });
    });

    it("the origin's word in the artifact: required, assured through delivery, and contradicting", () => {
      const honest = signAttestation(A, "mirror-a", CARRIER, pub(CARRIER), now, now);
      const base = { broker: signAttestation(A, "mirror-a", BROKER, pub(BROKER)), carrier: honest };
      const without = makeArtifact(A, base, 60_000, { registries: keys, quorum: 1 });
      expect(verifyArtifact(without.artifact, { pinnedRootKey: without.root, registryKeys: keys, insurerKeys: [insurerKey], requireInsurerAttestation: true })).toMatchObject({ ok: false, reasonCode: "INSURER_ATTESTATION_MISSING" });
      expect(verifyArtifact(without.artifact, { pinnedRootKey: without.root, registryKeys: keys }).ok).toBe(true);
      // With a COI: LOAD delivers within the statutory window of a word signed now.
      const coi = signInsurerAttestation(ins, "gpm", policy, now);
      const withCoi = { ...without.artifact, insurance: { carrier: coi } };
      // (re-attesting is the venue's job; here the content hash changes, so only the insurer checks are inspected)
      const v = verifyArtifact(withCoi, { pinnedRootKey: without.root, registryKeys: keys, insurerKeys: [insurerKey], requireInsurerAttestation: true });
      expect(v.checks.find((c) => c.name === "carrier.insurer.assured-through-delivery")?.ok).toBe(true);
      expect(v.checks.find((c) => c.name === "carrier.insurer[gpm].signed")?.ok).toBe(true);
      // A COI signed 40 days before commitment assures only through 10 days before it: not through delivery.
      const old = signInsurerAttestation(ins, "gpm", policy, new Date(now.getTime() - 40 * 86_400_000));
      const vOld = verifyArtifact({ ...without.artifact, insurance: { carrier: old } }, { pinnedRootKey: without.root, registryKeys: keys, insurerKeys: [insurerKey], requireInsurerAttestation: true });
      expect(vOld.checks.find((c) => c.name === "carrier.insurer.assured-through-delivery")?.ok).toBe(false);
      // A COI disclosing a cancellation before delivery contradicts the commitment.
      const disclosed = signInsurerAttestation(ins, "gpm", { ...policy, cancellation: { filedDate: dayOff(-31), effectiveDate: dayOff(-1) } }, now);
      const vBad = verifyArtifact({ ...without.artifact, insurance: { carrier: disclosed } }, { pinnedRootKey: without.root, registryKeys: keys, insurerKeys: [insurerKey] });
      expect(vBad.checks.find((c) => c.name === "carrier.insurer.standing-at-commitment")?.ok).toBe(false);
      // Forged under another key: invalid.
      const forged = signInsurerAttestation(generateKeyPair(), "gpm", policy, now);
      const vForged = verifyArtifact({ ...without.artifact, insurance: { carrier: forged } }, { pinnedRootKey: without.root, registryKeys: keys, insurerKeys: [insurerKey] });
      expect(vForged.checks.find((c) => c.name === "carrier.insurer[gpm].signed")?.ok).toBe(false);
    });
  });
});
