import { describe, it, expect } from "vitest";
import { generateKeyPair, signJws } from "../src/protocol/crypto";
import { attestationFreshAt, signAttestation, standing, verifyAttestation, type RegistryAttestation, type RegistryRecord } from "../src/protocol/registry";
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

function makeArtifact(registry: ReturnType<typeof generateKeyPair>, atts: { broker: RegistryAttestation; carrier: RegistryAttestation }, policyMs = 60_000) {
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
    { venue: { venueId: "v", rootPublicKey: root.publicJwk, certs: [cert] }, terms, termsHash: termsHash(terms), acceptances: { broker: accept(b, "broker-1", bc.credentialId), carrier: accept(c, "carrier-1", cc.credentialId) }, credentials: { broker: bc, carrier: cc }, registry: { registryId: "fmcsa-li-mock", publicKey: registry.publicJwk, attestations: atts, policy: { maxAgeMs: policyMs } }, underwriting: { decision: "GUARANTEED", riskScore: 0.01, guarantee: { guaranteeId: "g", coveredAmountUsd: 2215, premiumUsd: 40, scope: [], exclusions: [], conditions: [] } }, ledger: { seq: 1, prevHash: "0".repeat(64) } },
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
});
