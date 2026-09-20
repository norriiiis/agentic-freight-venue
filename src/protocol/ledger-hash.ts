/** The ledger entry hash, kept in protocol/ so a witness (or an agent acting as one) can verify a chain without importing the ledger. */
import { canonicalize, sha256Hex } from "./canonical";

export interface LedgerEntryLike {
  seq: number;
  ts: string;
  type: string;
  payload: unknown;
  prevHash: string;
  hash: string;
}

export function entryHash(e: Omit<LedgerEntryLike, "hash">): string {
  return sha256Hex(canonicalize({ seq: e.seq, ts: e.ts, type: e.type, payload: e.payload, prevHash: e.prevHash }));
}
