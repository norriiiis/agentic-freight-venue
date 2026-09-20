/**
 * The witnessing core, shared by the standalone witness process and by agents
 * witnessing their own transactions. Stateless except for what the injected
 * store holds, so the same rules apply to a party as to a third party:
 *   cosign only a head that extends the last one cosigned; remember every hash
 *   verified; gossip with peers; a disagreement at a verified position is a
 *   proof; on proof, halt.
 */
import type { KeyPair, OkpJwk } from "./crypto";
import { entryHash, type LedgerEntryLike } from "./ledger-hash";
import { rpcCall } from "./rpc";
import { makeEquivocationProof, signReceipt, verifyEquivocationProof, verifyReceipt, type EquivocationProof, type LedgerHead, type WitnessReceipt } from "./witness";

export interface WitnessPeer {
  witnessId: string;
  url: string;
  publicKey: OkpJwk;
}

export interface WitnessCoreState {
  lastCosigned?: LedgerHead;
  receipts: WitnessReceipt[];
  seen: Record<string, string>;
  forks: { at: string; expected: LedgerHead; observed: LedgerHead; why: string }[];
  equivocations: EquivocationProof[];
  halted?: { at: string; reason: string };
  peerReceipts: Record<string, WitnessReceipt>;
}

export function emptyWitnessState(): WitnessCoreState {
  return { receipts: [], seen: {}, forks: [], equivocations: [], peerReceipts: {} };
}

export interface WitnessCoreDeps {
  witnessId: string;
  kp: KeyPair;
  venueUrl: string;
  peers: () => WitnessPeer[];
  state: () => WitnessCoreState;
  persist: () => void;
  log: (event: string, outcome: "ALLOWED" | "REFUSED" | "INFO", evidence: Record<string, unknown>, reasonCode?: string) => void;
  /** Extra headers for venue requests (the simulator's equivocation fault keys on x-witness-id). */
  headers?: () => Record<string, string>;
  /** SIM fault: a malicious witness that signs any head it is asked to. */
  signAnything?: () => boolean;
}

export class WitnessCore {
  constructor(private readonly d: WitnessCoreDeps) {}

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.d.venueUrl}${path}`, { headers: { "x-witness-id": this.d.witnessId, ...(this.d.headers?.() ?? {}) } });
    return (await res.json()) as T;
  }
  latestReceipt(): WitnessReceipt | undefined {
    return this.d.state().receipts.at(-1);
  }

  /** One witnessing round. Returns the receipt issued, or the reason none was. */
  async poll(): Promise<{ receipt?: WitnessReceipt; skipped?: string; fork?: string; halted?: string }> {
    const s = this.d.state();
    if (s.halted) return { halted: s.halted.reason };
    let head: LedgerHead & { venueId: string };
    try {
      head = await this.get<LedgerHead & { venueId: string }>("/.well-known/ledger-head.json");
    } catch (e) {
      return { skipped: `venue unreachable: ${String(e).slice(0, 80)}` };
    }
    const last = s.lastCosigned;
    if (last && head.seq === last.seq && head.hash === last.hash) return { skipped: "head unchanged" };
    const verified: Record<string, string> = {};
    let why: string | undefined;
    if (head.seq < (last?.seq ?? -1)) why = `head went backwards: cosigned seq ${last!.seq}, venue now reports seq ${head.seq}`;
    else {
      const from = last?.seq ?? 0;
      const entries = (await this.get<LedgerEntryLike[]>(`/ledger.jsonl?from=${from}`)).sort((a, b) => a.seq - b.seq);
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
      s.forks.push(fork);
      this.d.persist();
      this.d.log("cosign", "REFUSED", fork, "LEDGER_FORK_DETECTED");
      return { fork: why };
    }
    const receipt = signReceipt(this.d.kp, this.d.witnessId, head.venueId, head);
    const res = await rpcCall<{ ok: boolean }>(`${this.d.venueUrl}/a2a`, "venue/witness", { receipt });
    if (res.error) {
      this.d.log("cosign", "INFO", { error: res.error, seq: head.seq });
      return { skipped: `venue refused receipt: ${res.error.message}` };
    }
    Object.assign(s.seen, verified, { [head.seq]: head.hash });
    s.lastCosigned = { seq: head.seq, hash: head.hash, ts: head.ts };
    s.receipts.push(receipt);
    this.d.persist();
    this.d.log("cosign", "ALLOWED", { seq: head.seq, hash: head.hash.slice(0, 12), at: receipt.at });
    return { receipt };
  }

  /** SIM fault for a malicious witness: sign whatever head it is handed, without verifying anything. */
  signBlindly(venueId: string, head: LedgerHead): WitnessReceipt | undefined {
    if (!this.d.signAnything?.()) return undefined;
    const r = signReceipt(this.d.kp, this.d.witnessId, venueId, head);
    this.d.state().receipts.push(r);
    this.d.persist();
    this.d.log("cosign", "INFO", { seq: head.seq, hash: head.hash.slice(0, 12), note: "SIM: signed blindly (colluding witness)" });
    return r;
  }

  /** A receipt for a position this witness has verified — signed on demand, so peers can compare at a common seq. */
  receiptFor(seq: number): WitnessReceipt | undefined {
    const s = this.d.state();
    const hash = s.seen[seq];
    if (!hash) return undefined;
    const existing = s.receipts.find((r) => r.seq === seq && r.hash === hash);
    if (existing) return existing;
    const venueId = s.receipts[0]?.venueId;
    if (!venueId) return undefined;
    const r = signReceipt(this.d.kp, this.d.witnessId, venueId, { seq, hash, ts: "" });
    s.receipts.push(r);
    this.d.persist();
    return r;
  }

  /**
   * Gossip is a question about a position BOTH have verified. If the peer is
   * ahead, ask it for a receipt at my head; if it is behind or level, compare
   * its latest against what I verified at that position.
   */
  async gossip(): Promise<{ checked: string[]; proofs: EquivocationProof[]; unreachable: string[] }> {
    const checked: string[] = [];
    const proofs: EquivocationProof[] = [];
    const unreachable: string[] = [];
    const mine = this.latestReceipt();
    for (const peer of this.d.peers()) {
      let latest: WitnessReceipt | null;
      try {
        latest = await (await fetch(`${peer.url}/latest`)).json() as WitnessReceipt | null;
      } catch {
        unreachable.push(peer.witnessId);
        continue;
      }
      if (mine) { try { await fetch(`${peer.url}/gossip`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ receipt: mine }) }); } catch { /* peer down */ } }
      if (!latest) continue;
      checked.push(peer.witnessId);
      let toCompare: WitnessReceipt | null = latest;
      if (mine && latest.seq > mine.seq) {
        try {
          toCompare = await (await fetch(`${peer.url}/receipt-for?seq=${mine.seq}`)).json() as WitnessReceipt | null;
        } catch {
          toCompare = null;
        }
      }
      if (!toCompare) continue;
      const proof = this.receiveGossip(toCompare);
      if (proof) proofs.push(proof);
    }
    return { checked, proofs, unreachable };
  }

  receiveGossip(r: WitnessReceipt): EquivocationProof | undefined {
    const s = this.d.state();
    const peer = this.d.peers().find((p) => p.witnessId === r.witnessId);
    if (!peer || !verifyReceipt(r, peer.publicKey)) {
      this.d.log("gossip", "REFUSED", { from: r.witnessId, error: "unknown peer or bad signature" });
      return undefined;
    }
    s.peerReceipts[r.witnessId] = r;
    const mineHash = s.seen[r.seq];
    if (!mineHash) { this.d.persist(); return undefined; }
    if (mineHash === r.hash) { this.d.persist(); this.d.log("gossip", "ALLOWED", { from: r.witnessId, seq: r.seq, agree: true }); return undefined; }
    let mine = s.receipts.find((x) => x.seq === r.seq);
    if (!mine) {
      mine = signReceipt(this.d.kp, this.d.witnessId, r.venueId, { seq: r.seq, hash: mineHash, ts: "" });
      s.receipts.push(mine);
    }
    const proof = makeEquivocationProof(mine, r, this.d.witnessId)!;
    this.recordProof(proof, "detected");
    return proof;
  }

  receiveProof(p: EquivocationProof): boolean {
    const keys = [...this.d.peers().map((x) => ({ witnessId: x.witnessId, publicKey: x.publicKey })), { witnessId: this.d.witnessId, publicKey: this.d.kp.publicJwk }];
    if (!verifyEquivocationProof(p, keys)) {
      this.d.log("equivocation", "REFUSED", { error: "proof does not verify", from: p.detectedBy });
      return false;
    }
    this.recordProof(p, "received");
    return true;
  }

  private recordProof(p: EquivocationProof, how: "detected" | "received") {
    const s = this.d.state();
    if (!s.equivocations.some((x) => x.seq === p.seq && x.receipts[0]!.hash === p.receipts[0]!.hash && x.receipts[1]!.hash === p.receipts[1]!.hash)) s.equivocations.push(p);
    if (!s.halted) s.halted = { at: new Date().toISOString(), reason: `equivocation at seq ${p.seq} (${p.receipts[0]!.witnessId}: ${p.receipts[0]!.hash.slice(0, 10)}… vs ${p.receipts[1]!.witnessId}: ${p.receipts[1]!.hash.slice(0, 10)}…)` };
    this.d.persist();
    this.d.log("equivocation", "REFUSED", { how, seq: p.seq, witnesses: p.receipts.map((r) => `${r.witnessId}:${r.hash.slice(0, 10)}`), halted: true }, "VENUE_EQUIVOCATION");
    if (how === "detected") {
      for (const peer of this.d.peers()) {
        fetch(`${peer.url}/equivocation`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ proof: p }) }).catch(() => {});
      }
    }
  }
}
