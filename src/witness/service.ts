/**
 * An independent ledger witness. Runs as its own process with its own key and
 * clock; the venue cannot forge its receipts and cannot make it cosign a head
 * that does not extend the last head it cosigned.
 *
 * Protocol, each poll:
 *   1. fetch the venue's current head
 *   2. fetch the entries from the last cosigned seq onward; verify the hash
 *      chain links from the last cosigned hash to the new head — a venue that
 *      rolled back or forked cannot produce that (LEDGER_FORK_DETECTED);
 *      remember every (seq, hash) verified
 *   3. sign { venueId, seq, hash, at } with the witness key and the witness
 *      clock, and hand the receipt back to the venue for publication
 *   4. GOSSIP: exchange latest receipts with peer witnesses. A peer's receipt
 *      for a seq this witness verified with a DIFFERENT hash is, paired with
 *      this witness's own receipt for that seq, a self-contained proof that
 *      the venue showed two ledgers (EQUIVOCATION). On proof: halt — never
 *      cosign this venue again — and push the proof to every peer.
 * A witness that is shown a fork but never gossips is a witness the venue
 * can fool forever; gossip is what makes one honest peer enough to catch it.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { exportPrivateJwk, generateKeyPair, importKeyPair, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { writeFileAtomic } from "../protocol/fsatomic";
import { rpcCall } from "../protocol/rpc";
import { makeEquivocationProof, signReceipt, verifyEquivocationProof, verifyReceipt, type EquivocationProof, type LedgerHead, type WitnessReceipt } from "../protocol/witness";
import { entryHash, type LedgerEntry } from "../ledger/chain";
import { AuditLog } from "../protocol/audit";

export interface WitnessPeer {
  witnessId: string;
  url: string;
  publicKey: OkpJwk;
}

interface WitnessState {
  lastCosigned?: LedgerHead;
  receipts: WitnessReceipt[];
  /** Every (seq -> hash) this witness has verified as part of a chain it cosigned. */
  seen: Record<string, string>;
  forks: { at: string; expected: LedgerHead; observed: LedgerHead; why: string }[];
  equivocations: EquivocationProof[];
  /** Once set, this witness never cosigns the venue again. */
  halted?: { at: string; reason: string };
  peerReceipts: Record<string, WitnessReceipt>;
}

export class WitnessService {
  readonly kp: KeyPair;
  readonly audit: AuditLog;
  private state: WitnessState = { receipts: [], seen: {}, forks: [], equivocations: [], peerReceipts: {} };
  private readonly statePath: string;

  constructor(readonly witnessId: string, readonly dataDir: string, readonly venueUrl: string, public peers: WitnessPeer[] = []) {
    const keyPath = join(dataDir, "witness-key.jwk.json");
    if (existsSync(keyPath)) this.kp = importKeyPair(JSON.parse(readFileSync(keyPath, "utf8")));
    else {
      this.kp = generateKeyPair();
      writeFileAtomic(keyPath, JSON.stringify(exportPrivateJwk(this.kp)));
    }
    writeFileAtomic(join(dataDir, "witness-public.jwk.json"), JSON.stringify(this.kp.publicJwk, null, 2));
    this.statePath = join(dataDir, "witness-state.json");
    if (existsSync(this.statePath)) this.state = { seen: {}, equivocations: [], peerReceipts: {}, ...JSON.parse(readFileSync(this.statePath, "utf8")) };
    this.audit = new AuditLog(join(dataDir, "audit.jsonl"));
  }
  private persist() {
    writeFileAtomic(this.statePath, JSON.stringify(this.state, null, 2));
  }
  /** Every request to the venue carries this witness's id. A real venue can fingerprint clients anyway; the header only makes the simulator's equivocation fault deterministic. */
  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.venueUrl}${path}`, { headers: { "x-witness-id": this.witnessId } });
    return (await res.json()) as T;
  }

  /** Operator action: add peers to gossip with (their keys come from out of band, never from the venue). */
  addPeers(peers: WitnessPeer[]) {
    for (const p of peers) if (!this.peers.some((x) => x.witnessId === p.witnessId)) this.peers.push(p);
  }
  status() {
    return { witnessId: this.witnessId, publicKey: this.kp.publicJwk, lastCosigned: this.state.lastCosigned ?? null, receipts: this.state.receipts.length, forks: this.state.forks.length, equivocations: this.state.equivocations.length, halted: this.state.halted ?? null, peers: this.peers.map((p) => p.witnessId) };
  }
  receipts(): WitnessReceipt[] {
    return [...this.state.receipts];
  }
  latestReceipt(): WitnessReceipt | undefined {
    return this.state.receipts.at(-1);
  }
  forks() {
    return [...this.state.forks];
  }
  equivocations(): EquivocationProof[] {
    return [...this.state.equivocations];
  }

  /** One witnessing round. Returns the receipt issued, or the reason none was. */
  async poll(): Promise<{ receipt?: WitnessReceipt; skipped?: string; fork?: string; halted?: string }> {
    if (this.state.halted) return { halted: this.state.halted.reason };
    let head: LedgerHead & { venueId: string };
    try {
      head = await this.get<LedgerHead & { venueId: string }>("/.well-known/ledger-head.json");
    } catch (e) {
      return { skipped: `venue unreachable: ${String(e).slice(0, 80)}` };
    }
    const last = this.state.lastCosigned;
    if (last && head.seq === last.seq && head.hash === last.hash) return { skipped: "head unchanged" };

    // Consistency: the new head must EXTEND the last one this witness cosigned. Remember every hash on the way.
    const verified: Record<string, string> = {};
    let why: string | undefined;
    if (head.seq < (last?.seq ?? -1)) why = `head went backwards: cosigned seq ${last!.seq}, venue now reports seq ${head.seq}`;
    else {
      const from = last?.seq ?? 0;
      const entries = (await this.get<LedgerEntry[]>(`/ledger.jsonl?from=${from}`)).sort((a, b) => a.seq - b.seq);
      const first = entries.find((e) => e.seq === from);
      if (!first) why = `venue no longer serves seq ${from}`;
      else if (last && first.hash !== last.hash) why = `seq ${last.seq} now has hash ${first.hash.slice(0, 12)}…, cosigned ${last.hash.slice(0, 12)}…`;
      else {
        let prev = last ? last.hash : undefined;
        for (const e of entries) {
          if (e.seq === from && !last) { if (entryHash(e) !== e.hash) { why = "genesis hash mismatch"; break; } verified[e.seq] = e.hash; prev = e.hash; continue; }
          if (e.seq === from) { prev = e.hash; continue; }
          if (e.prevHash !== prev || entryHash(e) !== e.hash) { why = `chain broken at seq ${e.seq}`; break; }
          verified[e.seq] = e.hash;
          prev = e.hash;
        }
        if (!why && prev !== head.hash) why = `served entries do not reach the reported head`;
      }
    }
    if (why) {
      const fork = { at: new Date().toISOString(), expected: last ?? { seq: -1, hash: "", ts: "" }, observed: { seq: head.seq, hash: head.hash, ts: head.ts }, why };
      this.state.forks.push(fork);
      this.persist();
      this.audit.write({ component: "witness", event: "cosign", outcome: "REFUSED", reasonCode: "LEDGER_FORK_DETECTED", evidence: fork });
      return { fork: why };
    }
    const receipt = signReceipt(this.kp, this.witnessId, head.venueId, head);
    const res = await rpcCall<{ ok: boolean }>(`${this.venueUrl}/a2a`, "venue/witness", { receipt });
    if (res.error) {
      this.audit.write({ component: "witness", event: "cosign", outcome: "INFO", evidence: { error: res.error, seq: head.seq } });
      return { skipped: `venue refused receipt: ${res.error.message}` };
    }
    Object.assign(this.state.seen, verified, { [head.seq]: head.hash });
    this.state.lastCosigned = { seq: head.seq, hash: head.hash, ts: head.ts };
    this.state.receipts.push(receipt);
    this.persist();
    this.audit.write({ component: "witness", event: "cosign", outcome: "ALLOWED", evidence: { seq: head.seq, hash: head.hash.slice(0, 12), at: receipt.at } });
    return { receipt };
  }

  // ---------------------------------------------------------------- gossip

  /** Exchange latest receipts with every peer; compare against what this witness verified. */
  async gossip(): Promise<{ checked: string[]; proofs: EquivocationProof[]; unreachable: string[] }> {
    const checked: string[] = [];
    const proofs: EquivocationProof[] = [];
    const unreachable: string[] = [];
    for (const peer of this.peers) {
      let latest: WitnessReceipt | null;
      try {
        latest = await (await fetch(`${peer.url}/latest`)).json() as WitnessReceipt | null;
      } catch {
        unreachable.push(peer.witnessId);
        continue;
      }
      // Push mine to them too (they run the same comparison from their side).
      const mine = this.latestReceipt();
      if (mine) { try { await fetch(`${peer.url}/gossip`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ receipt: mine }) }); } catch { /* peer down */ } }
      if (!latest) continue;
      checked.push(peer.witnessId);
      const proof = this.receiveGossip(latest);
      if (proof) proofs.push(proof);
    }
    return { checked, proofs, unreachable };
  }

  /**
   * A peer's receipt arrived. If it names a seq this witness verified with a
   * different hash, pair it with this witness's own receipt for that seq
   * (signing one now if needed — the hash was verified as part of a cosigned
   * chain) and that is proof of equivocation.
   */
  receiveGossip(r: WitnessReceipt): EquivocationProof | undefined {
    const peer = this.peers.find((p) => p.witnessId === r.witnessId);
    if (!peer || !verifyReceipt(r, peer.publicKey)) {
      this.audit.write({ component: "witness", event: "gossip", outcome: "REFUSED", evidence: { from: r.witnessId, error: "unknown peer or bad signature" } });
      return undefined;
    }
    this.state.peerReceipts[r.witnessId] = r;
    const mineHash = this.state.seen[r.seq];
    if (!mineHash) {
      // Beyond what this witness has verified: it will check on its next poll (the venue must serve a chain reaching it).
      this.persist();
      return undefined;
    }
    if (mineHash === r.hash) {
      this.persist();
      this.audit.write({ component: "witness", event: "gossip", outcome: "ALLOWED", evidence: { from: r.witnessId, seq: r.seq, agree: true } });
      return undefined;
    }
    let mine = this.state.receipts.find((x) => x.seq === r.seq);
    if (!mine) {
      mine = signReceipt(this.kp, this.witnessId, r.venueId, { seq: r.seq, hash: mineHash, ts: "" });
      this.state.receipts.push(mine);
    }
    const proof = makeEquivocationProof(mine, r, this.witnessId)!;
    this.recordProof(proof, "detected");
    return proof;
  }

  /** A proof arrived (from a peer, or made here). Verify against pinned peers + self; record; halt; propagate. */
  receiveProof(p: EquivocationProof): boolean {
    const keys = [...this.peers.map((x) => ({ witnessId: x.witnessId, publicKey: x.publicKey })), { witnessId: this.witnessId, publicKey: this.kp.publicJwk }];
    if (!verifyEquivocationProof(p, keys)) {
      this.audit.write({ component: "witness", event: "equivocation", outcome: "REFUSED", evidence: { error: "proof does not verify", from: p.detectedBy } });
      return false;
    }
    this.recordProof(p, "received");
    return true;
  }

  private recordProof(p: EquivocationProof, how: "detected" | "received") {
    if (!this.state.equivocations.some((x) => x.seq === p.seq && x.receipts[0]!.hash === p.receipts[0]!.hash && x.receipts[1]!.hash === p.receipts[1]!.hash)) this.state.equivocations.push(p);
    if (!this.state.halted) this.state.halted = { at: new Date().toISOString(), reason: `equivocation at seq ${p.seq} (${p.receipts[0]!.witnessId}: ${p.receipts[0]!.hash.slice(0, 10)}… vs ${p.receipts[1]!.witnessId}: ${p.receipts[1]!.hash.slice(0, 10)}…)` };
    this.persist();
    this.audit.write({ component: "witness", event: "equivocation", outcome: "REFUSED", reasonCode: "VENUE_EQUIVOCATION", evidence: { how, seq: p.seq, witnesses: p.receipts.map((r) => `${r.witnessId}:${r.hash.slice(0, 10)}`), halted: true } });
    if (how === "detected") {
      for (const peer of this.peers) {
        fetch(`${peer.url}/equivocation`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ proof: p }) }).catch(() => {});
      }
    }
  }
}
