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
 * From a publication and a set of pinned witness keys: the latest witness time
 * up to which the publication is known to be complete, and which witnesses
 * vouched. Receipts by unknown or mismatching keys are ignored.
 */
export function witnessedAsOf(pub: Pick<Witnessed, "witnessed" | "venueId">, witnessKeys: WitnessKey[]): { at?: Date; by: string[]; head?: LedgerHead } {
  if (!pub.witnessed) return { by: [] };
  const good = pub.witnessed.receipts.filter((r) => {
    const k = witnessKeys.find((w) => w.witnessId === r.witnessId);
    return !!k && r.venueId === pub.venueId && r.seq === pub.witnessed!.head.seq && r.hash === pub.witnessed!.head.hash && verifyReceipt(r, k.publicKey);
  });
  if (good.length === 0) return { by: [] };
  return { at: new Date(Math.max(...good.map((r) => new Date(r.at).getTime()))), by: good.map((r) => r.witnessId), head: pub.witnessed.head };
}
