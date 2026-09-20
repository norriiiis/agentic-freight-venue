/**
 * Tamper-evident, append-only ledger. Each entry hashes its predecessor and
 * is signed by the venue. Anyone holding the file and the venue's public key
 * can verify that nothing was altered, inserted, or removed.
 *
 * Storage is a JSONL file — sufficient for a prototype, and the first thing
 * to replace at scale (see README).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { appendDurable } from "../protocol/fsatomic";
import { canonicalize, sha256Hex } from "../protocol/canonical";
import { entryHash as protocolEntryHash } from "../protocol/ledger-hash";
import { importPublicKey, jwsHeader, signJws, verifyJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { makeResolver, type RootEvent, type VenueKeyCert, type VenueKeyRevocation } from "../protocol/venue-keys";

/**
 * COMMITMENT and VOID each carry their guarantee effect (attach / release) in
 * the same entry: one append is the whole commit point, so there is no
 * window in which the ledger says "committed" but not whether it is guaranteed.
 */
export type LedgerEntryType =
  | "GENESIS"        // carries the root establishment event and the first operational key certificate
  | "ROOT_ROTATION"  // carries a root event (pre-rotation): the new root's authority is the previous root's commitment
  | "COMMITMENT"
  | "VOID"
  | "KEY_ROTATION"   // carries the successor's root-signed certificate (+ revocation of the predecessor); signed by the SUCCESSOR
  | "RESEAL"         // after a compromise: the new key affirms a range of earlier entries as genuine
  | "REATTESTATION"  // after a compromise: a commitment artifact re-attested under the new key
  | "CREDENTIAL_STATUS"; // an agent credential revoked or superseded: the status list is a projection of these

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
  return protocolEntryHash(e);
}

export class Ledger {
  private entries: LedgerEntry[] = [];
  private readonly signer: () => KeyPair;
  /** `signer` may change over time (key rotation); pass a function, or a KeyPair for a fixed key. */
  constructor(private readonly path: string, signer: KeyPair | (() => KeyPair), genesisCert?: VenueKeyCert, rootEvent?: RootEvent) {
    this.signer = typeof signer === "function" ? signer : () => signer;
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      this.entries = readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    }
    if (this.entries.length === 0) this.append("GENESIS", { venueKid: this.signer().kid, cert: genesisCert, rootEvent });
  }
  get head(): LedgerEntry {
    return this.entries[this.entries.length - 1]!;
  }
  /** Append signed by the current signer, or by `signWith` (a KEY_ROTATION entry is signed by the successor before it is active). */
  append(type: LedgerEntryType, payload: Record<string, unknown>, signWith?: KeyPair): LedgerEntry {
    const prevHash = this.entries.length ? this.head.hash : GENESIS_HASH;
    const partial = { seq: this.entries.length, ts: new Date().toISOString(), type, payload, prevHash };
    const hash = entryHash(partial);
    const venueSig = signJws({ hash }, signWith ?? this.signer(), { typ: "ledger-entry+jws" }, true);
    const entry: LedgerEntry = { ...partial, hash, venueSig };
    // Durable before visible: the line is fsynced before the in-memory chain advances.
    appendDurable(this.path, JSON.stringify(entry) + "\n");
    this.entries.push(entry);
    return entry;
  }
  all(): LedgerEntry[] {
    return [...this.entries];
  }
  /** Entries from `fromSeq` (inclusive) — what a witness fetches to check that a new head extends the last one it saw. */
  slice(fromSeq: number): LedgerEntry[] {
    return this.entries.filter((e) => e.seq >= fromSeq);
  }
  /**
   * SIM-ONLY: an alternate chain that shares history up to `fromSeq` and then re-signs the later entries
   * with `exclude`d ones removed. Models a venue keeping two books to show different parties. Deterministic
   * for a given real chain (Ed25519 signatures are deterministic), so it looks like a stable ledger to whoever
   * is shown it.
   */
  forkView(fromSeq: number, exclude: (e: LedgerEntry) => boolean): LedgerEntry[] {
    const out: LedgerEntry[] = this.entries.filter((e) => e.seq <= fromSeq);
    let prev = out.at(-1)?.hash ?? GENESIS_HASH;
    let seq = (out.at(-1)?.seq ?? -1) + 1;
    for (const e of this.entries.filter((x) => x.seq > fromSeq && !exclude(x))) {
      const partial = { seq, ts: e.ts, type: e.type, payload: e.payload, prevHash: prev };
      const hash = entryHash(partial);
      const venueSig = signJws({ hash }, this.signer(), { typ: "ledger-entry+jws" }, true);
      out.push({ ...partial, hash, venueSig });
      prev = hash;
      seq += 1;
    }
    return out;
  }
  /** SIM-ONLY: rewrite history by dropping every entry after `seq`. Models a compromised venue rolling back its log. */
  truncate(seq: number) {
    this.entries = this.entries.filter((e) => e.seq <= seq);
    writeFileSync(this.path, this.entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
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
  /** Entries whose signature is by a key that was compromised at that time and not later resealed. */
  untrustedSeqs?: number[];
  keysSeen?: string[];
  rootsSeen?: string[];
}

/**
 * Verify a chain. Two trust modes:
 *   - a single venue public key (legacy / single-key deployments)
 *   - `{ rootPublicKey }`: walk the chain from a pinned root — ANY root the
 *     verifier pinned, founding or later. GENESIS and ROOT_ROTATION entries carry
 *     root events (pre-rotation proves each successor); GENESIS and KEY_ROTATION
 *     carry root-signed operational certificates; each entry's signature is
 *     checked against the certificate for the kid in its JWS header; a
 *     KEY_ROTATION entry is signed by the successor it introduces. Entries
 *     signed by a key after its declared compromise are untrusted unless a
 *     later RESEAL (by a trusted key) covers them.
 */
export type ChainTrust = OkpJwk | { rootPublicKey: OkpJwk; revocations?: VenueKeyRevocation[] };
function isRootTrust(t: ChainTrust): t is { rootPublicKey: OkpJwk; revocations?: VenueKeyRevocation[] } {
  return typeof (t as { rootPublicKey?: unknown }).rootPublicKey === "object" && (t as { kty?: unknown }).kty === undefined;
}

export function verifyChain(entries: LedgerEntry[], trust: ChainTrust): ChainVerification {
  let prev = GENESIS_HASH;
  const n = entries.length;
  if (isRootTrust(trust)) {
    // Pass 1: collect root events first (they extend which roots are trusted), then every root-signed certificate
    // and revocation the chain carries. Their validity comes from the roots, not from their position, and a
    // revocation may appear AFTER the entries it casts doubt on.
    const resolver = makeResolver(trust.rootPublicKey, { certs: [], revocations: trust.revocations ?? [], rootLog: [] });
    const rootEvents: RootEvent[] = [];
    for (const e of entries) {
      const pl = e.payload as { rootEvent?: RootEvent };
      if ((e.type === "GENESIS" || e.type === "ROOT_ROTATION") && pl.rootEvent) rootEvents.push(pl.rootEvent);
    }
    resolver.extendRoots(rootEvents);
    for (const e of entries) {
      const pl = e.payload as { cert?: VenueKeyCert; revocation?: VenueKeyRevocation | null };
      if ((e.type === "GENESIS" || e.type === "KEY_ROTATION") && pl.cert && !resolver.add(pl.cert)) {
        return { ok: false, entries: n, firstBadSeq: e.seq, error: `${e.type} certificate is not signed by the venue root` };
      }
      if (e.type === "KEY_ROTATION" && pl.revocation && !resolver.revoke(pl.revocation)) {
        return { ok: false, entries: n, firstBadSeq: e.seq, error: "KEY_ROTATION revocation is not signed by the venue root" };
      }
    }
    // Pass 2: hash links, signatures by certified keys, and trust at signing time (with RESEALs).
    const untrusted = new Set<number>();
    const resealed = new Set<number>();
    for (const e of entries) {
      if (e.prevHash !== prev) return { ok: false, entries: n, firstBadSeq: e.seq, error: "prevHash does not match previous entry" };
      if (entryHash(e) !== e.hash) return { ok: false, entries: n, firstBadSeq: e.seq, error: "entry hash does not match content" };
      const pl = e.payload as { fromSeq?: number; toSeq?: number };
      const kid = jwsHeader(e.venueSig)?.kid ?? "";
      const key = resolver.key(kid);
      if (!key) return { ok: false, entries: n, firstBadSeq: e.seq, error: `entry signed by unknown venue key ${kid.slice(0, 12)}…` };
      if (!verifyJws(e.venueSig, importPublicKey(key), { hash: e.hash }).ok) return { ok: false, entries: n, firstBadSeq: e.seq, error: "venue signature invalid" };
      const why = resolver.untrustedAt(kid, new Date(e.ts));
      if (why && e.type !== "KEY_ROTATION") untrusted.add(e.seq);
      if (e.type === "RESEAL" && !why && typeof pl.fromSeq === "number" && typeof pl.toSeq === "number") {
        for (let i = pl.fromSeq; i <= pl.toSeq; i++) resealed.add(i);
      }
      prev = e.hash;
    }
    const untrustedSeqs = [...untrusted].filter((x) => !resealed.has(x));
    return { ok: untrustedSeqs.length === 0, entries: n, untrustedSeqs, keysSeen: resolver.kids(), rootsSeen: resolver.rootKids(), error: untrustedSeqs.length ? `entries ${untrustedSeqs.join(",")} signed by a compromised key and not resealed` : undefined };
  }
  const pub = importPublicKey(trust as OkpJwk);
  for (const e of entries) {
    if (e.prevHash !== prev) return { ok: false, entries: n, firstBadSeq: e.seq, error: "prevHash does not match previous entry" };
    const h = entryHash(e);
    if (h !== e.hash) return { ok: false, entries: n, firstBadSeq: e.seq, error: "entry hash does not match content" };
    if (!verifyJws(e.venueSig, pub, { hash: e.hash }).ok) return { ok: false, entries: n, firstBadSeq: e.seq, error: "venue signature invalid" };
    prev = e.hash;
  }
  return { ok: true, entries: n };
}
