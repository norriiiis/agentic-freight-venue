import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "../src/protocol/crypto";
import { Ledger, verifyChain } from "../src/ledger/chain";
import { buildArtifact, reattestArtifact, verifyArtifact, type CommitmentArtifact } from "../src/ledger/artifact";
import { makeResolver, signCert, signRevocation, verifyCert, verifyRevocation } from "../src/protocol/venue-keys";
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
  const root = generateKeyPair();
  const venue = generateKeyPair();
  const cert = signCert(root, venue.publicJwk, 0, "INITIAL", new Date(Date.now() - 60_000));
  const b = generateKeyPair();
  const c = generateKeyPair();
  const bc = cred(venue, b, "broker-1", "3312874", "MC-1088412", "BROKER");
  const cc = cred(venue, c, "carrier-1", "2751903", "MC-0938251", "CARRIER");
  const terms: Terms = { loadRef: LOAD.loadRef, load: LOAD, rateUsd: 2215, pickup: { windowStart: LOAD.origin.windowStart, windowEnd: LOAD.origin.windowEnd }, delivery: { windowStart: LOAD.destination.windowStart, windowEnd: LOAD.destination.windowEnd }, paymentTermsDays: 30, brokerAgentId: "broker-1", carrierAgentId: "carrier-1", brokerEntity: { usdot: "3312874", mc: "MC-1088412" }, carrierEntity: { usdot: "2751903", mc: "MC-0938251" } };
  const accept = (kp: ReturnType<typeof generateKeyPair>, agentId: string, credentialId: string) =>
    signMessage(buildMessage({ role: "user", data: { type: "ACCEPT", loadRef: terms.loadRef, round: 3, terms, termsHash: termsHash(terms), from: { agentId, usdot: "x" } }, taskId: "t", contextId: "c", senderAgentId: agentId, credentialId }), kp);
  const artifact = buildArtifact(
    { venue: { venueId: "v", rootPublicKey: root.publicJwk, certs: [cert] }, terms, termsHash: termsHash(terms), acceptances: { broker: accept(b, "broker-1", bc.credentialId), carrier: accept(c, "carrier-1", cc.credentialId) }, credentials: { broker: bc, carrier: cc }, underwriting: { decision: "UNGUARANTEED" }, ledger: { seq: 1, prevHash: "0".repeat(64) } },
    venue,
  );
  return { artifact, venue, root, cert, b, c };
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
    const { artifact, root } = makeArtifact();
    const v = verifyArtifact(artifact, { pinnedRootKey: root.publicJwk });
    expect(v.ok, JSON.stringify(v.checks.filter((c) => !c.ok))).toBe(true);
    expect(v.checks.length).toBeGreaterThan(15);
  });
  it("rate altered → RECORD_TAMPERED (attestation, hash, and both ACCEPTs disagree)", () => {
    const { artifact, root } = makeArtifact();
    const t: CommitmentArtifact = JSON.parse(JSON.stringify(artifact));
    t.terms.rateUsd = 100;
    const v = verifyArtifact(t, { pinnedRootKey: root.publicJwk });
    expect(v).toMatchObject({ ok: false, reasonCode: "RECORD_TAMPERED" });
    expect(v.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual(expect.arrayContaining(["venue.attestation[0].signature", "terms.hash", "broker.accept.terms-match", "carrier.accept.terms-match"]));
  });
  it("carrier signature swapped for another key → carrier.accept.signature fails", () => {
    const { artifact, root } = makeArtifact();
    const t: CommitmentArtifact = JSON.parse(JSON.stringify(artifact));
    const other = generateKeyPair();
    t.acceptances.carrier = signMessage({ ...t.acceptances.carrier, metadata: { ...t.acceptances.carrier.metadata, sig: undefined } }, other);
    const v = verifyArtifact(t, { pinnedRootKey: root.publicJwk });
    expect(v.ok).toBe(false);
    expect(v.checks.find((c) => c.name === "carrier.accept.signature")?.ok).toBe(false);
  });
  it("wrong venue root pinned → embedded certs do not verify, so attestation and issuer checks fail", () => {
    const { artifact } = makeArtifact();
    const v = verifyArtifact(artifact, { pinnedRootKey: generateKeyPair().publicJwk });
    expect(v).toMatchObject({ ok: false, reasonCode: "VENUE_KEY_UNTRUSTED" });
    expect(v.checks.find((c) => c.name === "venue.certs.signed-by-root")?.ok).toBe(false);
    expect(v.checks.find((c) => c.name === "venue.attestation.any-trusted")?.ok).toBe(false);
    expect(v.checks.find((c) => c.name === "broker.credential.issuer-signature")?.ok).toBe(false);
  });
  it("verifies with only the embedded key when none is pinned (weaker trust, flagged by the CLI)", () => {
    const { artifact } = makeArtifact();
    expect(verifyArtifact(artifact).ok).toBe(true);
  });
});

describe("artifact verification with a credential status list", () => {
  it("a compromise declared before the signature fails trusted-at-signing; a later routine rotation does not", () => {
    const { artifact } = makeArtifact();
    const carrierCred = artifact.credentials.carrier;
    const signedAt = (artifact.acceptances.carrier.metadata as { ts: string }).ts;
    const before = new Date(new Date(signedAt).getTime() - 1000).toISOString();
    const after = new Date(new Date(signedAt).getTime() + 1000).toISOString();
    const compromised = verifyArtifact(artifact, { statusList: [{ credentialId: carrierCred.credentialId, status: "SUPERSEDED", at: after, reason: "COMPROMISE", compromisedAt: before }] });
    expect(compromised).toMatchObject({ ok: false, reasonCode: "COMMITMENT_UNDER_COMPROMISED_KEY" });
    expect(compromised.checks.find((c) => c.name === "carrier.credential.trusted-at-signing")?.ok).toBe(false);
    const rotated = verifyArtifact(artifact, { statusList: [{ credentialId: carrierCred.credentialId, status: "SUPERSEDED", at: after, reason: "ROTATION", graceUntil: after }] });
    expect(rotated.ok).toBe(true);
    const revokedLater = verifyArtifact(artifact, { statusList: [{ credentialId: carrierCred.credentialId, status: "REVOKED", at: after, reason: "authority revoked" }] });
    expect(revokedLater.ok).toBe(true);
    expect(verifyArtifact(artifact).ok).toBe(true); // no status list: signatures still verify
  });
});

describe("venue key hierarchy", () => {
  it("certificates and revocations verify only against the root that signed them", () => {
    const root = generateKeyPair();
    const op = generateKeyPair();
    const cert = signCert(root, op.publicJwk, 0, "INITIAL", new Date(Date.now() - 120_000));
    expect(verifyCert(cert, root.publicJwk)).toBe(true);
    expect(verifyCert(cert, generateKeyPair().publicJwk)).toBe(false);
    expect(verifyCert({ ...cert, seq: 9 }, root.publicJwk)).toBe(false);
    const rev = signRevocation(root, op.kid, "COMPROMISE", new Date().toISOString());
    expect(verifyRevocation(rev, root.publicJwk)).toBe(true);
    const r = makeResolver(root.publicJwk, { certs: [cert], revocations: [rev] });
    expect(r.key(op.kid)?.x).toBe(op.publicJwk.x);
    expect(r.untrustedAt(op.kid, new Date(Date.now() - 60_000))).toBeUndefined();
    expect(r.untrustedAt(op.kid, new Date(Date.now() + 60_000))).toMatch(/compromised/);
    expect(makeResolver(root.publicJwk, { certs: [signCert(generateKeyPair(), op.publicJwk, 0, "INITIAL")], revocations: [] }).key(op.kid)).toBeUndefined();
  });

  it("a chain verifies across a rotation from the root alone; compromised-era entries need a RESEAL", () => {
    const dir = mkdtempSync(join(tmpdir(), "fv-chain-"));
    const root = generateKeyPair();
    let active = generateKeyPair();
    const cert0 = signCert(root, active.publicJwk, 0, "INITIAL", new Date(Date.now() - 1000));
    const l = new Ledger(join(dir, "ledger.jsonl"), () => active, cert0);
    l.append("COMMITMENT", { commitmentId: "a" });
    // routine rotation: successor signs the KEY_ROTATION entry that carries its own root-signed cert
    const k1 = generateKeyPair();
    const cert1 = signCert(root, k1.publicJwk, 1, "ROTATION");
    l.append("KEY_ROTATION", { previousKid: active.kid, cert: cert1, revocation: null }, k1);
    active = k1;
    l.append("COMMITMENT", { commitmentId: "b" });
    const ok = verifyChain(l.all(), { rootPublicKey: root.publicJwk });
    expect(ok.ok).toBe(true);
    expect(ok.keysSeen?.length).toBe(2);
    expect(verifyChain(l.all(), { rootPublicKey: generateKeyPair().publicJwk }).ok).toBe(false);
    // compromise of k1 declared as of before entry "b": that entry becomes untrusted...
    const T = new Date(Date.now() - 500).toISOString();
    const k2 = generateKeyPair();
    const cert2 = signCert(root, k2.publicJwk, 2, "COMPROMISE");
    const rev1 = signRevocation(root, k1.kid, "COMPROMISE", T);
    l.append("KEY_ROTATION", { previousKid: k1.kid, cert: cert2, revocation: rev1 }, k2);
    active = k2;
    const bad = verifyChain(l.all(), { rootPublicKey: root.publicJwk });
    expect(bad.ok).toBe(false);
    expect(bad.untrustedSeqs).toEqual([3]);
    // ...until the new key reseals it
    l.append("RESEAL", { fromSeq: 3, toSeq: 3, previousKid: k1.kid });
    expect(verifyChain(l.all(), { rootPublicKey: root.publicJwk }).ok).toBe(true);
    // a KEY_ROTATION entry whose cert is not root-signed breaks the chain
    const forged = l.all().map((e) => ({ ...e }));
    (forged[2]!.payload as { cert: unknown }).cert = signCert(generateKeyPair(), k1.publicJwk, 1, "ROTATION");
    expect(verifyChain(forged, { rootPublicKey: root.publicJwk }).ok).toBe(false);
  });

  it("artifact: attestation under a venue key later declared compromised fails with the history; re-attestation under the new key restores it", () => {
    const { artifact, root, venue, cert } = makeArtifact();
    const T = new Date(new Date(artifact.venueAttestations[0]!.at).getTime() - 1000).toISOString();
    const rev = signRevocation(root, venue.kid, "COMPROMISE", T);
    const withHistory = verifyArtifact(artifact, { pinnedRootKey: root.publicJwk, keyHistory: { certs: [cert], revocations: [rev] } });
    expect(withHistory).toMatchObject({ ok: false, reasonCode: "VENUE_KEY_UNTRUSTED" });
    expect(verifyArtifact(artifact, { pinnedRootKey: root.publicJwk }).ok).toBe(true); // invisible offline without the history
    // the venue re-attests under a new certified key (credentials re-signed under it too)
    const k2 = generateKeyPair();
    const cert2 = signCert(root, k2.publicJwk, 1, "COMPROMISE");
    const resign = (c: typeof artifact.credentials.broker) => {
      const { issuerSignature: _s, ...u } = c;
      const re = { ...u, issuer: { venueId: "v", kid: k2.kid }, signedAt: new Date().toISOString() };
      return { ...re, issuerSignature: signJws(re, k2, { typ: "agent-credential+jws" }, true) };
    };
    const re = reattestArtifact(artifact, k2, { credentials: { broker: resign(artifact.credentials.broker), carrier: resign(artifact.credentials.carrier) }, addCerts: [cert2] });
    expect(re.venueAttestations.at(-1)?.kid).toBe(k2.kid);
    const v = verifyArtifact(re, { pinnedRootKey: root.publicJwk, keyHistory: { certs: [cert, cert2], revocations: [rev] } });
    expect(v.ok, JSON.stringify(v.checks.filter((c) => !c.ok))).toBe(true);
  });
});

import { rootCommitment, signRootEvent, walkRootLog } from "../src/protocol/venue-keys";
import { Ledger as Ledger2 } from "../src/ledger/chain";

describe("root pre-rotation", () => {
  function ceremony() {
    const r0 = generateKeyPair();
    const r1 = generateKeyPair();
    const r2 = generateKeyPair();
    const e0 = signRootEvent(r0, { seq: 0, nextRootCommitment: rootCommitment(r1.publicJwk), at: new Date(Date.now() - 5000).toISOString(), reason: "ESTABLISHMENT" });
    return { r0, r1, r2, e0 };
  }

  it("a rotation is accepted only if the revealed root matches the prior commitment and signs the event itself", () => {
    const { r0, r1, r2, e0 } = ceremony();
    const good = signRootEvent(r1, { seq: 1, previousRootKid: r0.kid, nextRootCommitment: rootCommitment(r2.publicJwk), at: new Date().toISOString(), reason: "ROTATION" }, r0);
    const walk = walkRootLog(r0.publicJwk, [e0, good])!;
    expect(walk.current.kid).toBe(r1.kid);
    expect([...walk.roots.keys()]).toEqual([r0.kid, r1.kid]);
    // thief with r0 rotates to their own key, countersigned by r0: commitment mismatch → rejected
    const thief = generateKeyPair();
    const bad = signRootEvent(thief, { seq: 1, previousRootKid: r0.kid, nextRootCommitment: rootCommitment(generateKeyPair().publicJwk), at: new Date().toISOString(), reason: "ROTATION" }, r0);
    const w2 = walkRootLog(r0.publicJwk, [e0, bad])!;
    expect(w2.current.kid).toBe(r0.kid);
    expect(w2.rejected[0]?.why).toMatch(/pre-committed/);
    // the right key but signed by someone else → rejected
    const forged = { ...good, signature: bad.signature };
    expect(walkRootLog(r0.publicJwk, [e0, forged])!.current.kid).toBe(r0.kid);
    // a verifier that pinned r1 directly walks from there
    expect(walkRootLog(r1.publicJwk, [e0, good])!.current.kid).toBe(r1.kid);
  });

  it("resolver: certificates by a root declared compromised after their signing stay trusted; those signed after do not; a re-certification restores a genuine key's whole tenure", () => {
    const { r0, r1, r2, e0 } = ceremony();
    const op = generateKeyPair();
    const certByR0 = signCert(r0, op.publicJwk, 0, "INITIAL", new Date(Date.now() - 4000));
    const rot1 = signRootEvent(r1, { seq: 1, previousRootKid: r0.kid, nextRootCommitment: rootCommitment(r2.publicJwk), at: new Date(Date.now() - 3000).toISOString(), reason: "ROTATION" }, r0);
    const T = new Date(Date.now() - 2000).toISOString();
    const thief = generateKeyPair();
    const thiefCert = signCert(r1, thief.publicJwk, 99, "ROTATION", new Date(Date.now() - 1000)); // signed AFTER T with stolen r1
    const genuineCertByR1 = signCert(r1, op.publicJwk, 1, "ROTATION", new Date(Date.now() - 2500)); // signed BEFORE T
    const r3 = generateKeyPair();
    const comp = signRootEvent(r2, { seq: 2, previousRootKid: r1.kid, nextRootCommitment: rootCommitment(r3.publicJwk), at: new Date().toISOString(), reason: "COMPROMISE", compromisedAt: T });
    const res = makeResolver(r0.publicJwk, { rootLog: [e0, rot1, comp], certs: [certByR0, genuineCertByR1, thiefCert], revocations: [] });
    expect(res.rootKids()).toEqual([r0.kid, r1.kid, r2.kid]);
    expect(res.untrustedAt(thief.kid, new Date())).toMatch(/compromised before the certificate was signed/);
    expect(res.untrustedAt(op.kid, new Date())).toBeUndefined(); // still has an R0 cert and a pre-T R1 cert
    // a key whose ONLY cert was signed by r1 after T is dead until re-certified under r2 with its original validFrom
    const late = generateKeyPair();
    const lateCert = signCert(r1, late.publicJwk, 2, "ROTATION", new Date(Date.now() - 1500), new Date(Date.now() - 1500));
    const res2 = makeResolver(r0.publicJwk, { rootLog: [e0, rot1, comp], certs: [lateCert], revocations: [] });
    expect(res2.untrustedAt(late.kid, new Date())).toBeDefined();
    const recert = signCert(r2, late.publicJwk, 3, "RECERTIFICATION", new Date(), new Date(Date.now() - 1500));
    res2.add(recert);
    expect(res2.untrustedAt(late.kid, new Date())).toBeUndefined();
    expect(res2.untrustedAt(late.kid, new Date(Date.now() - 1400))).toBeUndefined(); // whole tenure
  });

  it("ledger: GENESIS + ROOT_ROTATION let a chain verify from the founding root after the root changed", () => {
    const dir = mkdtempSync(join(tmpdir(), "fv-root-"));
    const { r0, r1, r2, e0 } = ceremony();
    const op = generateKeyPair();
    const cert0 = signCert(r0, op.publicJwk, 0, "INITIAL", new Date(Date.now() - 4000));
    const l = new Ledger2(join(dir, "ledger.jsonl"), op, cert0, e0);
    l.append("COMMITMENT", { commitmentId: "a" });
    const rot = signRootEvent(r1, { seq: 1, previousRootKid: r0.kid, nextRootCommitment: rootCommitment(r2.publicJwk), at: new Date().toISOString(), reason: "ROTATION" }, r0);
    l.append("ROOT_ROTATION", { rootEvent: rot, recert: null });
    // a new operational key certified by the NEW root
    const op2 = generateKeyPair();
    const cert1 = signCert(r1, op2.publicJwk, 1, "ROTATION");
    l.append("KEY_ROTATION", { previousKid: op.kid, cert: cert1, revocation: null }, op2);
    const l2 = new Ledger2(join(dir, "ledger.jsonl"), op2);
    l2.append("COMMITMENT", { commitmentId: "b" });
    const v = verifyChain(l2.all(), { rootPublicKey: r0.publicJwk });
    expect(v.ok, v.error).toBe(true);
    expect(v.rootsSeen).toEqual([r0.kid, r1.kid]);
    expect(verifyChain(l2.all(), { rootPublicKey: r1.publicJwk }).ok).toBe(true); // pinned the later root: fine too
    expect(verifyChain(l2.all(), { rootPublicKey: generateKeyPair().publicJwk }).ok).toBe(false);
  });
});

import { partyWitnessKeys } from "../src/ledger/artifact";

describe("party witness keys", () => {
  it("come straight from the artifact's credentials — the keys each party transacted with", () => {
    const { artifact, b, c } = makeArtifact();
    const keys = partyWitnessKeys(artifact);
    expect(keys.map((k) => k.witnessId)).toEqual(["broker-1", "carrier-1"]);
    expect(keys[0]!.publicKey.x).toBe(b.publicJwk.x);
    expect(keys[1]!.publicKey.x).toBe(c.publicJwk.x);
  });
});
