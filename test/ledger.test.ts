import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "../src/protocol/crypto";
import { Ledger, verifyChain } from "../src/ledger/chain";
import { buildArtifact, verifyArtifact, type CommitmentArtifact } from "../src/ledger/artifact";
import { buildMessage, signMessage } from "../src/protocol/envelope";
import { termsHash, type Terms } from "../src/protocol/freight";
import { signJws } from "../src/protocol/crypto";
import type { Credential } from "../src/protocol/types";
import { LOAD } from "../src/sim/fixtures";

function cred(venue: ReturnType<typeof generateKeyPair>, agent: ReturnType<typeof generateKeyPair>, agentId: string, usdot: string, mc: string, entityType: Credential["subject"]["entity"]["entityType"]): Credential {
  const unsigned = {
    credentialId: `cred_${agentId}`, schema: "freight-venue/agent-credential/v1" as const,
    subject: { agentId, entity: { usdot, mc, legalName: agentId.toUpperCase(), entityType }, publicKey: agent.publicJwk },
    issuer: { venueId: "v", kid: venue.kid }, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    evidence: { registrySnapshotHash: "x", registryCheckedAt: "", insuranceCheckedAt: "", vettingProvider: "stub", vettingFlags: [], proofOfControl: "stub" },
  };
  return { ...unsigned, issuerSignature: signJws(unsigned, venue, { typ: "agent-credential+jws" }, true) };
}

function makeArtifact() {
  const venue = generateKeyPair();
  const b = generateKeyPair();
  const c = generateKeyPair();
  const bc = cred(venue, b, "broker-1", "3312874", "MC-1088412", "BROKER");
  const cc = cred(venue, c, "carrier-1", "2751903", "MC-0938251", "CARRIER");
  const terms: Terms = { loadRef: LOAD.loadRef, load: LOAD, rateUsd: 2215, pickup: { windowStart: LOAD.origin.windowStart, windowEnd: LOAD.origin.windowEnd }, delivery: { windowStart: LOAD.destination.windowStart, windowEnd: LOAD.destination.windowEnd }, paymentTermsDays: 30, brokerAgentId: "broker-1", carrierAgentId: "carrier-1", brokerEntity: { usdot: "3312874", mc: "MC-1088412" }, carrierEntity: { usdot: "2751903", mc: "MC-0938251" } };
  const accept = (kp: ReturnType<typeof generateKeyPair>, agentId: string, credentialId: string) =>
    signMessage(buildMessage({ role: "user", data: { type: "ACCEPT", loadRef: terms.loadRef, round: 3, terms, termsHash: termsHash(terms), from: { agentId, usdot: "x" } }, taskId: "t", contextId: "c", senderAgentId: agentId, credentialId }), kp);
  const artifact = buildArtifact(
    { venue: { venueId: "v", publicKey: venue.publicJwk }, terms, termsHash: termsHash(terms), acceptances: { broker: accept(b, "broker-1", bc.credentialId), carrier: accept(c, "carrier-1", cc.credentialId) }, credentials: { broker: bc, carrier: cc }, underwriting: { decision: "UNGUARANTEED" }, ledger: { seq: 1, prevHash: "0".repeat(64) } },
    venue,
  );
  return { artifact, venue, b, c };
}

describe("ledger chain", () => {
  it("appends, chains, signs, and detects edits/removals", () => {
    const kp = generateKeyPair();
    const dir = mkdtempSync(join(tmpdir(), "fv-ledger-"));
    const l = new Ledger(join(dir, "ledger.jsonl"), kp);
    l.append("COMMITMENT", { commitmentId: "a", rateUsd: 1 });
    l.append("COMMITMENT", { commitmentId: "b", rateUsd: 2 });
    const entries = l.all();
    expect(verifyChain(entries, kp.publicJwk).ok).toBe(true);
    const edited = structuredClone(entries);
    (edited[1]!.payload as { rateUsd: number }).rateUsd = 999;
    expect(verifyChain(edited, kp.publicJwk)).toMatchObject({ ok: false, firstBadSeq: 1 });
    const removed = [entries[0]!, entries[2]!];
    expect(verifyChain(removed, kp.publicJwk)).toMatchObject({ ok: false, firstBadSeq: 2 });
    expect(verifyChain(entries, generateKeyPair().publicJwk).ok).toBe(false);
  });
});

describe("commitment artifact verifies independently", () => {
  it("genuine artifact passes every check with a pinned venue key", () => {
    const { artifact, venue } = makeArtifact();
    const v = verifyArtifact(artifact, { pinnedVenueKey: venue.publicJwk });
    expect(v.ok, JSON.stringify(v.checks.filter((c) => !c.ok))).toBe(true);
    expect(v.checks.length).toBeGreaterThan(15);
  });
  it("rate altered → RECORD_TAMPERED (attestation, hash, and both ACCEPTs disagree)", () => {
    const { artifact, venue } = makeArtifact();
    const t: CommitmentArtifact = JSON.parse(JSON.stringify(artifact));
    t.terms.rateUsd = 100;
    const v = verifyArtifact(t, { pinnedVenueKey: venue.publicJwk });
    expect(v).toMatchObject({ ok: false, reasonCode: "RECORD_TAMPERED" });
    expect(v.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual(expect.arrayContaining(["venue.attestation", "terms.hash", "broker.accept.terms-match", "carrier.accept.terms-match"]));
  });
  it("carrier signature swapped for another key → carrier.accept.signature fails", () => {
    const { artifact, venue } = makeArtifact();
    const t: CommitmentArtifact = JSON.parse(JSON.stringify(artifact));
    const other = generateKeyPair();
    t.acceptances.carrier = signMessage({ ...t.acceptances.carrier, metadata: { ...t.acceptances.carrier.metadata, sig: undefined } }, other);
    const v = verifyArtifact(t, { pinnedVenueKey: venue.publicJwk });
    expect(v.ok).toBe(false);
    expect(v.checks.find((c) => c.name === "carrier.accept.signature")?.ok).toBe(false);
  });
  it("wrong venue key pinned → attestation and credential issuer checks fail", () => {
    const { artifact } = makeArtifact();
    const v = verifyArtifact(artifact, { pinnedVenueKey: generateKeyPair().publicJwk });
    expect(v.ok).toBe(false);
    expect(v.checks.find((c) => c.name === "venue.attestation")?.ok).toBe(false);
    expect(v.checks.find((c) => c.name === "broker.credential.issuer-signature")?.ok).toBe(false);
  });
  it("verifies with only the embedded key when none is pinned (weaker trust, flagged by the CLI)", () => {
    const { artifact } = makeArtifact();
    expect(verifyArtifact(artifact).ok).toBe(true);
  });
});
