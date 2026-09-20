import { describe, it, expect } from "vitest";
import { generateKeyPair } from "../src/protocol/crypto";
import { findInclusion, noticeHash, signNotice, signPromise, verifyNotice, verifyPromise } from "../src/protocol/inclusion";
import { signReceipt } from "../src/protocol/witness";
import { verifyArtifact, buildArtifact, type CommitmentArtifact } from "../src/ledger/artifact";
import { signCert } from "../src/protocol/venue-keys";
import { buildMessage, signMessage } from "../src/protocol/envelope";
import { termsHash, type Terms } from "../src/protocol/freight";
import { signJws } from "../src/protocol/crypto";
import type { Credential } from "../src/protocol/types";
import { LOAD } from "../src/sim/fixtures";
import { Ledger } from "../src/ledger/chain";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const feed = generateKeyPair();
const venue = generateKeyPair();

describe("status notices and inclusion promises", () => {
  it("a notice verifies only against its source's key; a promise only against the venue key it names", () => {
    const n = signNotice(feed, "fmcsa-li-feed", { noticeId: "n1", subject: { credentialId: "cred_x" }, assertion: "INSURANCE_CANCELLED", effectiveAt: "2026-09-20T12:00:00.000Z", reason: "BMC-91X cancelled" });
    expect(verifyNotice(n, feed.publicJwk)).toBe(true);
    expect(verifyNotice(n, generateKeyPair().publicJwk)).toBe(false);
    expect(verifyNotice({ ...n, reason: "edited" }, feed.publicJwk)).toBe(false);
    const p = signPromise(venue, "v", n, 60_000, new Date("2026-09-20T12:00:01.000Z"));
    expect(p.noticeHash).toBe(noticeHash(n));
    expect(p.includeBy).toBe("2026-09-20T12:01:01.000Z");
    expect(verifyPromise(p, venue.publicJwk)).toBe(true);
    expect(verifyPromise(p, (kid) => (kid === venue.kid ? venue.publicJwk : undefined))).toBe(true);
    expect(verifyPromise(p, generateKeyPair().publicJwk)).toBe(false);
    expect(verifyPromise({ ...p, includeBy: "2026-12-31T00:00:00.000Z" }, venue.publicJwk)).toBe(false);
  });
  it("inclusion is by notice hash on the entry payload", () => {
    const n = signNotice(feed, "fmcsa-li-feed", { noticeId: "n2", subject: { usdot: "2751903" }, assertion: "AUTHORITY_REVOKED", effectiveAt: "2026-09-20T12:00:00.000Z", reason: "revoked" });
    const p = signPromise(venue, "v", n, 1000);
    const entries = [{ seq: 0, ts: "", type: "GENESIS", payload: {}, prevHash: "", hash: "" }, { seq: 1, ts: "", type: "CREDENTIAL_STATUS", payload: { status: null, noticeHash: noticeHash(n) }, prevHash: "", hash: "" }];
    expect(findInclusion(p, entries)?.seq).toBe(1);
    expect(findInclusion(p, entries.slice(0, 1))).toBeUndefined();
  });
});

describe("verifier: broken promises and pending notices", () => {
  function artifact() {
    const root = generateKeyPair();
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
  /** A real chain: GENESIS (with the venue's cert), one COMMITMENT; optionally a CREDENTIAL_STATUS carrying a notice hash. */
  function chain(root: ReturnType<typeof generateKeyPair>, withNotice?: string) {
    const cert = signCert(root, venue.publicJwk, 0, "INITIAL", new Date("2026-09-20T10:00:00.000Z"));
    const l = new Ledger(join(mkdtempSync(join(tmpdir(), "fv-incl-")), "l.jsonl"), venue, cert);
    l.append("COMMITMENT", { commitmentId: "a" });
    if (withNotice) l.append("CREDENTIAL_STATUS", { status: null, noticeHash: withNotice });
    const h = l.head;
    return { entries: l.all(), head: { seq: h.seq, hash: h.hash, ts: h.ts } };
  }
  const pubAt = (at: string, head: { seq: number; hash: string; ts: string }) => ({ venueId: "v", asOf: at, head, witnessed: { head, receipts: [signReceipt(w, "w1", "v", head, new Date(at))] }, entries: [] });

  it("a valid broken-promise proof voids the venue; a proof whose receipt predates the deadline does not count", () => {
    const { a, root } = artifact();
    const n = signNotice(feed, "fmcsa-li-feed", { noticeId: "n3", subject: { credentialId: "cred_carrier-1" }, assertion: "REVOKED", effectiveAt: "2026-09-20T12:00:00.000Z", reason: "r" });
    const promise = signPromise(venue, "v", n, 1000, new Date("2026-09-20T12:00:00.000Z")); // by 12:00:01
    const { entries: ledger, head } = chain(root);
    const late = signReceipt(w, "w1", "v", head, new Date("2026-09-20T12:05:00.000Z"));
    const early = signReceipt(w, "w1", "v", head, new Date("2026-09-20T12:00:00.500Z"));
    const list = pubAt("2026-09-20T12:05:00.000Z", head);
    const broken = verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, brokenPromises: [{ promise, headReceipt: late, checkedAt: "", detectedBy: "w1" }], ledger, asOf: new Date("2026-09-20T12:05:00.000Z"), maxStalenessMs: 0 });
    expect(broken).toMatchObject({ ok: false, reasonCode: "INCLUSION_PROMISE_BROKEN" });
    const notYet = verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, brokenPromises: [{ promise, headReceipt: early, checkedAt: "", detectedBy: "w1" }], ledger, asOf: new Date("2026-09-20T12:05:00.000Z"), maxStalenessMs: 0 });
    expect(notYet.ok).toBe(true);
    // the verifier's own promise, checked against the ledger and the witnessed time
    const own = verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, inclusionPromises: [promise], ledger, asOf: new Date("2026-09-20T12:05:00.000Z"), maxStalenessMs: 0 });
    expect(own).toMatchObject({ ok: false, reasonCode: "INCLUSION_PROMISE_BROKEN" });
    const withN = chain(root, noticeHash(n));
    const included = verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: pubAt("2026-09-20T12:05:00.000Z", withN.head), witnessKeys: wk, inclusionPromises: [promise], ledger: withN.entries, asOf: new Date("2026-09-20T12:05:00.000Z"), maxStalenessMs: 0 });
    expect(included.ok, JSON.stringify(included.checks.filter((c) => !c.ok))).toBe(true);
  });
  it("a pending notice from a registered source makes status uncertain; from an unknown source it is ignored; once on the ledger it clears", () => {
    const { a, root } = artifact();
    const n = signNotice(feed, "fmcsa-li-feed", { noticeId: "n4", subject: { credentialId: "cred_carrier-1" }, assertion: "REVOKED", effectiveAt: "2026-09-20T12:00:00.000Z", reason: "r" });
    const { entries: ledger, head } = chain(root);
    const list = pubAt("2026-09-20T12:05:00.000Z", head);
    const pending = [{ notice: n, lodgedAt: "", lodgedWith: "w1", submissionOutcome: "service unavailable" }];
    expect(verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, pendingNotices: pending, noticeSources: [{ witnessId: "fmcsa-li-feed", publicKey: feed.publicJwk }], ledger, asOf: new Date("2026-09-20T12:05:00.000Z"), maxStalenessMs: 0 })).toMatchObject({ ok: false, reasonCode: "NOTICE_PENDING" });
    expect(verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: list, witnessKeys: wk, pendingNotices: pending, noticeSources: [{ witnessId: "someone-else", publicKey: generateKeyPair().publicJwk }], ledger, asOf: new Date("2026-09-20T12:05:00.000Z"), maxStalenessMs: 0 }).ok).toBe(true);
    const withN = chain(root, noticeHash(n));
    expect(verifyArtifact(a, { pinnedRootKey: root.publicJwk, statusList: pubAt("2026-09-20T12:05:00.000Z", withN.head), witnessKeys: wk, pendingNotices: pending, noticeSources: [{ witnessId: "fmcsa-li-feed", publicKey: feed.publicJwk }], ledger: withN.entries, asOf: new Date("2026-09-20T12:05:00.000Z"), maxStalenessMs: 0 }).ok).toBe(true);
  });
});
