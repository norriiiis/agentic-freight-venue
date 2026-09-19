/**
 * Tamper-evident, append-only ledger. Each entry hashes its predecessor and
 * is signed by the venue. Anyone holding the file and the venue's public key
 * can verify that nothing was altered, inserted, or removed.
 *
 * Storage is a JSONL file — sufficient for a prototype, and the first thing
 * to replace at scale (see README).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalize, sha256Hex } from "../protocol/canonical";
import { importPublicKey, signJws, verifyJws, type KeyPair, type OkpJwk } from "../protocol/crypto";

export type LedgerEntryType = "COMMITMENT" | "VOID" | "GUARANTEE_ATTACHED" | "GUARANTEE_RELEASED" | "GENESIS";

export interface LedgerEntry {
  seq: number;
  ts: string;
  type: LedgerEntryType;
  payload: Record<string, unknown>;
  prevHash: string;
  hash: string;
  venueSig: string;
}

export const GENESIS_HASH = "0".repeat(64);

export function entryHash(e: Omit<LedgerEntry, "hash" | "venueSig">): string {
  return sha256Hex(canonicalize({ seq: e.seq, ts: e.ts, type: e.type, payload: e.payload, prevHash: e.prevHash }));
}

export class Ledger {
  private entries: LedgerEntry[] = [];
  constructor(private readonly path: string, private readonly kp: KeyPair) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      this.entries = readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    }
    if (this.entries.length === 0) this.append("GENESIS", { venueKid: kp.kid });
  }
  get head(): LedgerEntry {
    return this.entries[this.entries.length - 1]!;
  }
  append(type: LedgerEntryType, payload: Record<string, unknown>): LedgerEntry {
    const prevHash = this.entries.length ? this.head.hash : GENESIS_HASH;
    const partial = { seq: this.entries.length, ts: new Date().toISOString(), type, payload, prevHash };
    const hash = entryHash(partial);
    const venueSig = signJws({ hash }, this.kp, { typ: "ledger-entry+jws" }, true);
    const entry: LedgerEntry = { ...partial, hash, venueSig };
    this.entries.push(entry);
    appendFileSync(this.path, JSON.stringify(entry) + "\n");
    return entry;
  }
  all(): LedgerEntry[] {
    return [...this.entries];
  }
  find(pred: (e: LedgerEntry) => boolean): LedgerEntry | undefined {
    return this.entries.find(pred);
  }
  filter(pred: (e: LedgerEntry) => boolean): LedgerEntry[] {
    return this.entries.filter(pred);
  }
}

export interface ChainVerification {
  ok: boolean;
  entries: number;
  firstBadSeq?: number;
  error?: string;
}

/** Verify a chain exported as entries, given the venue's public key. */
export function verifyChain(entries: LedgerEntry[], venueKey: OkpJwk): ChainVerification {
  const pub = importPublicKey(venueKey);
  let prev = GENESIS_HASH;
  for (const e of entries) {
    if (e.prevHash !== prev) return { ok: false, entries: entries.length, firstBadSeq: e.seq, error: "prevHash does not match previous entry" };
    const h = entryHash(e);
    if (h !== e.hash) return { ok: false, entries: entries.length, firstBadSeq: e.seq, error: "entry hash does not match content" };
    if (!verifyJws(e.venueSig, pub, { hash: e.hash }).ok) return { ok: false, entries: entries.length, firstBadSeq: e.seq, error: "venue signature invalid" };
    prev = e.hash;
  }
  return { ok: true, entries: entries.length };
}
