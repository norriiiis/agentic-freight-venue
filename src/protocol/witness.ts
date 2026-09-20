/**
 * Witnessed ledger heads: third-party timestamps for the venue's append-only
 * log.
 *
 * The venue's published status list and key history are projections of its
 * ledger at some head (seq, hash). A WITNESS is an independent party with its
 * own key and its own clock that periodically fetches the head, verifies that
 * it EXTENDS the head it last cosigned (so the venue cannot roll back or fork
 * without the witness noticing), and signs { venueId, seq, hash, at }.
 *
 * A verifier who pins a witness key can then say: "everything the venue had
 * recorded by W (the witness's time) is in the chain ending at this head" —
 * which is what turns "no compromise in my copy" into "no compromise as of W",
 * and lets a verifier reject a copy that is not fresh enough for the moment it
 * cares about. Witness keys are learned out of band, like CT log keys; the
 * venue cannot mint them.
 */
import { importPublicKey, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";

export interface LedgerHead {
  seq: number;
  hash: string;
  ts: string; // the venue's clock; informational
}

export interface WitnessReceipt {
  witnessId: string;
  venueId: string;
  seq: number;
  hash: string;
  /** The WITNESS's clock. */
  at: string;
  /** Detached JWS by the witness key over { venueId, seq, hash, at }. */
  signature: string;
}

export interface WitnessKey {
  witnessId: string;
  publicKey: OkpJwk;
}

export function signReceipt(witness: KeyPair, witnessId: string, venueId: string, head: LedgerHead, now = new Date()): WitnessReceipt {
  const body = { venueId, seq: head.seq, hash: head.hash, at: now.toISOString() };
  return { witnessId, ...body, signature: signJws(body, witness, { typ: "ledger-witness+jws" }, true) };
}

export function verifyReceipt(r: WitnessReceipt, key: OkpJwk): boolean {
  return verifyJws(r.signature, importPublicKey(key), { venueId: r.venueId, seq: r.seq, hash: r.hash, at: r.at }).ok;
}

/** What every published projection of the ledger carries in addition to its content. */
export interface Witnessed {
  venueId: string;
  /** The venue's own clock at publication. Informational only; a verifier trusts `witnessed.receipts[].at`. */
  asOf: string;
  head: LedgerHead;
  /** The most recent head at or before `head` that at least one witness cosigned, with the receipts. Null if never witnessed. */
  witnessed: { head: LedgerHead; receipts: WitnessReceipt[] } | null;
}

/**
 * Proof that a venue showed two different ledgers: two receipts, each validly
 * signed by a witness, for the SAME seq of the SAME venue with DIFFERENT
 * hashes. Self-contained — verifying it needs only the witnesses' keys, not
 * the venue's cooperation. A verifier holding one trusts nothing that venue
 * publishes.
 */
export interface EquivocationProof {
  venueId: string;
  seq: number;
  receipts: [WitnessReceipt, WitnessReceipt];
  detectedBy: string;
  at: string;
}

export function makeEquivocationProof(a: WitnessReceipt, b: WitnessReceipt, detectedBy: string): EquivocationProof | undefined {
  if (a.venueId !== b.venueId || a.seq !== b.seq || a.hash === b.hash) return undefined;
  return { venueId: a.venueId, seq: a.seq, receipts: [a, b], detectedBy, at: new Date().toISOString() };
}

/** Both receipts verify against pinned keys (distinct witnesses or the same one contradicting itself), same venue and seq, different hashes. */
export function verifyEquivocationProof(p: EquivocationProof, witnessKeys: WitnessKey[]): boolean {
  const [a, b] = p.receipts;
  if (a.venueId !== p.venueId || b.venueId !== p.venueId || a.seq !== p.seq || b.seq !== p.seq || a.hash === b.hash) return false;
  const ka = witnessKeys.find((w) => w.witnessId === a.witnessId);
  const kb = witnessKeys.find((w) => w.witnessId === b.witnessId);
  return !!ka && !!kb && verifyReceipt(a, ka.publicKey) && verifyReceipt(b, kb.publicKey);
}

/**
 * From a publication and a set of pinned witness keys: which pinned witnesses
 * cosigned the witnessed head, and the time up to which the publication is
 * known complete. With `minWitnesses` = k, that time is the k-th latest
 * receipt time — at least k independent witnesses vouch for it — and `quorum`
 * says whether k was reached. Receipts by unknown or mismatching keys are
 * ignored.
 */
export function witnessedAsOf(pub: Pick<Witnessed, "witnessed" | "venueId">, witnessKeys: WitnessKey[], minWitnesses = 1): { at?: Date; by: string[]; head?: LedgerHead; quorum: boolean } {
  if (!pub.witnessed) return { by: [], quorum: false };
  const good = pub.witnessed.receipts.filter((r) => {
    const k = witnessKeys.find((w) => w.witnessId === r.witnessId);
    return !!k && r.venueId === pub.venueId && r.seq === pub.witnessed!.head.seq && r.hash === pub.witnessed!.head.hash && verifyReceipt(r, k.publicKey);
  });
  // one receipt per witness: its latest
  const latestBy = new Map<string, WitnessReceipt>();
  for (const r of good) if (!latestBy.has(r.witnessId) || new Date(r.at) > new Date(latestBy.get(r.witnessId)!.at)) latestBy.set(r.witnessId, r);
  const times = [...latestBy.values()].map((r) => new Date(r.at).getTime()).sort((x, y) => y - x);
  const k = Math.max(1, minWitnesses);
  if (times.length === 0) return { by: [], quorum: false, head: pub.witnessed.head };
  const quorum = times.length >= k;
  return { at: quorum ? new Date(times[k - 1]!) : undefined, by: [...latestBy.keys()], head: pub.witnessed.head, quorum };
}
