/**
 * Inclusion promises — Certificate Transparency's SCT, for status changes.
 *
 * Nothing forces a venue to write. What can be forced is EVIDENCE: a source
 * that submits a status change gets back, synchronously, a venue-signed
 * promise to include it within a bounded delay. Witnesses watch promises; a
 * promise past its deadline with no matching entry in the chain they verified
 * is proof of misbehaviour (INCLUSION_PROMISE_BROKEN). A venue can still
 * refuse to acknowledge at all — but then the source knows, and can lodge the
 * unanswered notice with witnesses, who publish it as PENDING. The floor is
 * an unanswered public claim, not silence.
 *
 * Notices are signed by their SOURCE (a registry feed, an insurer, the
 * principal of the affected agent), so a ledger entry's provenance is the
 * source's assertion, not the venue's.
 */
import { canonicalize, hashObject } from "./canonical";
import { importPublicKey, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";
import type { LedgerEntryLike } from "./ledger-hash";
import type { WitnessReceipt } from "./witness";

export interface StatusNotice {
  schema: "freight-venue/status-notice/v1";
  noticeId: string;
  sourceId: string;
  /** What the source asserts. */
  subject: { credentialId?: string; usdot?: string; agentId?: string };
  assertion: "REVOKED" | "INSURANCE_CANCELLED" | "AUTHORITY_REVOKED" | "KEY_COMPROMISED";
  effectiveAt: string;
  reason: string;
  issuedAt: string;
  /** Detached JWS by the source's key over the notice sans this field. */
  sourceSignature: string;
}

export interface InclusionPromise {
  schema: "freight-venue/inclusion-promise/v1";
  venueId: string;
  /** hashObject(notice) — what must appear on the ledger. */
  noticeHash: string;
  noticeId: string;
  receivedAt: string;
  /** The venue commits to a ledger entry carrying noticeHash no later than this time. */
  includeBy: string;
  kid: string;
  /** Detached JWS by the venue's operational key over the promise sans this field. */
  signature: string;
}

export function noticeHash(n: StatusNotice): string {
  return hashObject(n);
}

export function signNotice(source: KeyPair, sourceId: string, fields: Omit<StatusNotice, "schema" | "sourceId" | "issuedAt" | "sourceSignature">, now = new Date()): StatusNotice {
  const unsigned: Omit<StatusNotice, "sourceSignature"> = { schema: "freight-venue/status-notice/v1", sourceId, issuedAt: now.toISOString(), ...fields };
  return { ...unsigned, sourceSignature: signJws(unsigned, source, { typ: "status-notice+jws" }, true) };
}

export function verifyNotice(n: StatusNotice, sourceKey: OkpJwk): boolean {
  const { sourceSignature, ...unsigned } = n;
  return verifyJws(sourceSignature, importPublicKey(sourceKey), unsigned).ok;
}

export function signPromise(venue: KeyPair, venueId: string, n: StatusNotice, includeByMs: number, now = new Date()): InclusionPromise {
  const unsigned: Omit<InclusionPromise, "signature"> = { schema: "freight-venue/inclusion-promise/v1", venueId, noticeHash: noticeHash(n), noticeId: n.noticeId, receivedAt: now.toISOString(), includeBy: new Date(now.getTime() + includeByMs).toISOString(), kid: venue.kid };
  return { ...unsigned, signature: signJws(unsigned, venue, { typ: "inclusion-promise+jws" }, true) };
}

/** `venueKey` resolves the promise's kid (any certified venue key). */
export function verifyPromise(p: InclusionPromise, venueKey: OkpJwk | ((kid: string) => OkpJwk | undefined)): boolean {
  const { signature, ...unsigned } = p;
  const key = typeof venueKey === "function" ? venueKey(p.kid) : venueKey;
  if (!key) return false;
  return verifyJws(signature, importPublicKey(key), unsigned).ok;
}

/** Is the promised notice on this chain? Entries carry `payload.noticeHash`. */
export function findInclusion(p: InclusionPromise, entries: LedgerEntryLike[]): LedgerEntryLike | undefined {
  return entries.find((e) => (e.payload as { noticeHash?: string } | undefined)?.noticeHash === p.noticeHash);
}

/**
 * Proof that a promise was broken: the promise, and a witness receipt for a
 * head whose chain (verified by that witness) contains no entry with the
 * promised hash, at a time past the deadline. Re-checkable against the
 * ledger the venue serves for that head; if the venue serves a different
 * ledger for it, that is equivocation, caught by the other machinery.
 */
export interface BrokenPromiseProof {
  promise: InclusionPromise;
  headReceipt: WitnessReceipt;
  checkedAt: string;
  detectedBy: string;
}

/** A source's notice that the venue never acknowledged, lodged with a witness. */
export interface PendingNotice {
  notice: StatusNotice;
  lodgedAt: string;
  lodgedWith: string;
  /** How the source tried and failed (transport error, refusal, timeout). */
  submissionOutcome: string;
}

export function noticeSummary(n: StatusNotice): string {
  return `${n.assertion} ${n.subject.credentialId ?? n.subject.usdot ?? n.subject.agentId ?? "?"} as of ${n.effectiveAt} (source ${n.sourceId})`;
}

/** A canonical, signature-free view of a notice for logs. */
export function noticeFingerprint(n: StatusNotice): string {
  return canonicalize({ id: n.noticeId, s: n.sourceId, a: n.assertion, e: n.effectiveAt });
}
