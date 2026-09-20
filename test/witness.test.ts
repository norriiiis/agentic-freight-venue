import { describe, it, expect } from "vitest";
import { generateKeyPair, signJws } from "../src/protocol/crypto";
import { signReceipt, verifyReceipt, witnessedAsOf } from "../src/protocol/witness";
import { buildArtifact, verifyArtifact, type CommitmentArtifact } from "../src/ledger/artifact";
import { signCert } from "../src/protocol/venue-keys";
import { buildMessage, signMessage } from "../src/protocol/envelope";
import { termsHash, type Terms } from "../src/protocol/freight";
import type { Credential } from "../src/protocol/types";
import { LOAD } from "../src/sim/fixtures";

const head = { seq: 7, hash: "a".repeat(64), ts: "2026-09-20T12:00:00.000Z" };

describe("witness receipts", () => {
  it("verify only against the witness key that signed them, over exactly the head they name", () => {
    const w = generateKeyPair();
    const r = signReceipt(w, "witness-1", "venue-x", head, new Date("2026-09-20T12:00:05.000Z"));
    expect(verifyReceipt(r, w.publicJwk)).toBe(true);
    expect(verifyReceipt(r, generateKeyPair().publicJwk)).toBe(false);
    expect(verifyReceipt({ ...r, seq: 8 }, w.publicJwk)).toBe(false);
    expect(verifyReceipt({ ...r, at: "2026-09-21T00:00:00.000Z" }, w.publicJwk)).toBe(false);
  });
  it("witnessedAsOf takes the latest time among receipts by PINNED witnesses for THIS head and venue", () => {
    const w1 = generateKeyPair();
    const w2 = generateKeyPair();
    const stranger = generateKeyPair();
    const r1 = signReceipt(w1, "w1", "venue-x", head, new Date("2026-09-20T12:00:05.000Z"));
    const r2 = signReceipt(w2, "w2", "venue-x", head, new Date("2026-09-20T12:00:09.000Z"));
    const rs = signReceipt(stranger, "w3", "venue-x", head, new Date("2026-09-20T13:00:00.000Z")); // not pinned
    const rOther = signReceipt(w1, "w1", "venue-y", head, new Date("2026-09-20T14:00:00.000Z"));   // other venue
    const pub = { venueId: "venue-x", witnessed: { head, receipts: [r1, r2, rs, rOther] } };
    const a = witnessedAsOf(pub, [{ witnessId: "w1", publicKey: w1.publicJwk }, { witnessId: "w2", publicKey: w2.publicJwk }]);
    expect(a.at?.toISOString()).toBe("2026-09-20T12:00:09.000Z");
    expect(a.by.sort()).toEqual(["w1", "w2"]);
    expect(witnessedAsOf(pub, [{ witnessId: "w9", publicKey: generateKeyPair().publicJwk }]).at).toBeUndefined();
    expect(witnessedAsOf({ venueId: "venue-x", witnessed: null }, []).at).toBeUndefined();
  });
});

describe("artifact freshness with pinned witnesses", () => {
  function artifact() {
    const root = generateKeyPair();
    const venue = generateKeyPair();
    const cert = signCert(root, venue.publicJwk, 0, "INITIAL", new Date("2026-09-20T10:00:00.000Z"));
    const b = generateKeyPair();
    const c = generateKeyPair();
    const cred = (kp: ReturnType<typeof generateKeyPair>, agentId: string, usdot: string, mc: string, entityType: Credential["subject"]["entity"]["entityType"]): Credential => {
      const u = { credentialId: `cred_${agentId}`, schema: "freight-venue/agent-credential/v1" as const, subject: { agentId, entity: { usdot, mc, legalName: agentId, entityType }, publicKey: kp.publicJwk }, issuer: { venueId: "v", kid: venue.kid }, issuedAt: "2026-09-20T10:30:00.000Z", signedAt: "2026-09-20T10:30:00.000Z", expiresAt: "2026-12-20T10:30:00.000Z", evidence: { registrySnapshotHash: "x", registryCheckedAt: "", insuranceCheckedAt: "", vettingProvider: "stub", vettingFlags: [], proofOfControl: "stub" } };
      return { ...u, issuerSignature: signJws(u, venue, { typ: "agent-credential+jws" }, true) };
    };
    const bc = cred(b, "broker-1", "3312874", "MC-1088412", "BROKER");
    const cc = cred(c, "carrier-1", "2751903", "MC-0938251", "CARRIER");
    const terms: Terms = { loadRef: LOAD.loadRef, load: LOAD, rateUsd: 2215, pickup: { windowStart: LOAD.origin.windowStart, windowEnd: LOAD.origin.windowEnd }, delivery: { windowStart: LOAD.destination.windowStart, windowEnd: LOAD.destination.windowEnd }, paymentTermsDays: 30, brokerAgentId: "broker-1", carrierAgentId: "carrier-1", brokerEntity: { usdot: "3312874", mc: "MC-1088412" }, carrierEntity: { usdot: "2751903", mc: "MC-0938251" } };
    const accept = (kp: ReturnType<typeof generateKeyPair>, agentId: string, credentialId: string) => {
      const m = buildMessage({ role: "user", data: { type: "ACCEPT", loadRef: terms.loadRef, round: 3, terms, termsHash: termsHash(terms), from: { agentId, usdot: "x" } }, taskId: "t", contextId: "c", senderAgentId: agentId, credentialId });
      (m.metadata as { ts: string }).ts = "2026-09-20T11:00:00.000Z";
      return signMessage(m, kp);
    };
    const a: CommitmentArtifact = buildArtifact({ venue: { venueId: "v", rootPublicKey: root.publicJwk, certs: [cert] }, terms, termsHash: termsHash(terms), acceptances: { broker: accept(b, "broker-1", bc.credentialId), carrier: accept(c, "carrier-1", cc.credentialId) }, credentials: { broker: bc, carrier: cc }, underwriting: { decision: "UNGUARANTEED" }, ledger: { seq: 1, prevHash: "0".repeat(64) } }, venue);
    return { a, root };
  }
  const w = generateKeyPair();
  const wk = [{ witnessId: "w1", publicKey: w.publicJwk }];
  const pubAt = (at: string) => ({ venueId: "v", asOf: at, head, witnessed: { head, receipts: [signReceipt(w, "w1", "v", head, new Date(at))] }, entries: [] });

  it("a witnessed list judged strictly at a moment before the witness time is fresh; after it is STATUS_STALE; without witnesses nothing is said", () => {
    const { a, root } = artifact();
    const list = pubAt("2026-09-20T12:00:00.000Z");
    expect(verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, asOf: new Date("2026-09-20T11:59:00.000Z"), maxStalenessMs: 0 }).ok).toBe(true);
    const stale = verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, asOf: new Date("2026-09-20T12:01:00.000Z"), maxStalenessMs: 0 });
    expect(stale).toMatchObject({ ok: false, reasonCode: "STATUS_STALE" });
    expect(stale.witnessed?.statusAsOf).toBe("2026-09-20T12:00:00.000Z");
    // tolerance turns the same question into "fresh enough"
    expect(verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, asOf: new Date("2026-09-20T12:01:00.000Z"), maxStalenessMs: 5 * 60_000 }).ok).toBe(true);
    // no pinned witnesses: the list is taken at its word, and the question is not even asked
    const naive = verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list });
    expect(naive.ok).toBe(true);
    expect(naive.checks.some((c) => c.name.startsWith("status."))).toBe(false);
  });
  it("a list with no witnessed head, or receipts by no pinned witness, is STATUS_NOT_WITNESSED", () => {
    const { a, root } = artifact();
    expect(verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: { venueId: "v", asOf: "x", head, witnessed: null, entries: [] }, witnessKeys: wk })).toMatchObject({ ok: false, reasonCode: "STATUS_NOT_WITNESSED" });
    const other = generateKeyPair();
    expect(verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: { venueId: "v", asOf: "x", head, witnessed: { head, receipts: [signReceipt(other, "w1", "v", head)] }, entries: [] }, witnessKeys: wk })).toMatchObject({ ok: false, reasonCode: "STATUS_NOT_WITNESSED" });
  });
});

import { makeEquivocationProof, verifyEquivocationProof } from "../src/protocol/witness";

describe("equivocation proofs and witness quorum", () => {
  const w1 = generateKeyPair();
  const w2 = generateKeyPair();
  const keys = [{ witnessId: "w1", publicKey: w1.publicJwk }, { witnessId: "w2", publicKey: w2.publicJwk }];
  const h1 = { seq: 5, hash: "1".repeat(64), ts: "" };
  const h2 = { seq: 5, hash: "2".repeat(64), ts: "" };

  it("a proof is two validly signed receipts, same venue and seq, different hashes — and nothing else", () => {
    const r1 = signReceipt(w1, "w1", "v", h1);
    const r2 = signReceipt(w2, "w2", "v", h2);
    const p = makeEquivocationProof(r1, r2, "w1")!;
    expect(p.seq).toBe(5);
    expect(verifyEquivocationProof(p, keys)).toBe(true);
    expect(verifyEquivocationProof(p, [keys[0]!])).toBe(false);                       // w2 not pinned
    expect(makeEquivocationProof(r1, signReceipt(w2, "w2", "v", h1), "w1")).toBeUndefined(); // same hash: agreement, not proof
    expect(makeEquivocationProof(r1, signReceipt(w2, "w2", "v", { ...h2, seq: 6 }), "w1")).toBeUndefined(); // different seq
    expect(makeEquivocationProof(r1, signReceipt(w2, "w2", "other-venue", h2), "w1")).toBeUndefined();
    const forged = { ...p, receipts: [r1, { ...r2, hash: "3".repeat(64) }] as [typeof r1, typeof r2] };
    expect(verifyEquivocationProof(forged, keys)).toBe(false);
    // a single witness contradicting itself is also a proof
    const self = makeEquivocationProof(r1, signReceipt(w1, "w1", "v", h2), "w2")!;
    expect(verifyEquivocationProof(self, keys)).toBe(true);
  });

  it("quorum: the witnessed time is the k-th latest receipt; fewer than k pinned witnesses on the head is no quorum", () => {
    const head = { seq: 9, hash: "9".repeat(64), ts: "" };
    const r1 = signReceipt(w1, "w1", "v", head, new Date("2026-09-20T12:00:10.000Z"));
    const r2 = signReceipt(w2, "w2", "v", head, new Date("2026-09-20T12:00:03.000Z"));
    const pub = { venueId: "v", witnessed: { head, receipts: [r1, r2] } };
    const one = witnessedAsOf(pub, keys, 1);
    expect(one.quorum).toBe(true);
    expect(one.at?.toISOString()).toBe("2026-09-20T12:00:10.000Z");
    const two = witnessedAsOf(pub, keys, 2);
    expect(two.quorum).toBe(true);
    expect(two.at?.toISOString()).toBe("2026-09-20T12:00:03.000Z"); // at least 2 vouch for this time
    const onlyW2 = witnessedAsOf({ venueId: "v", witnessed: { head, receipts: [r2] } }, keys, 2);
    expect(onlyW2.quorum).toBe(false);
    expect(onlyW2.at).toBeUndefined();
    expect(onlyW2.by).toEqual(["w2"]);
  });
});
