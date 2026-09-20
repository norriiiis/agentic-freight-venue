/**
 * An independent ledger witness. Runs as its own process with its own key and
 * clock; the venue cannot forge its receipts and cannot make it cosign a head
 * that does not extend the last head it cosigned.
 *
 * Protocol, each poll:
 *   1. fetch the venue's current head
 *   2. fetch the entries from the last cosigned seq onward; verify the hash
 *      chain links from the last cosigned hash to the new head — a venue that
 *      rolled back or forked cannot produce that (LEDGER_FORK_DETECTED)
 *   3. sign { venueId, seq, hash, at } with the witness key and the witness
 *      clock, and hand the receipt back to the venue for publication
 * The witness keeps every receipt it ever issued: that history is the
 * evidence in a dispute about what the venue had recorded when.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { exportPrivateJwk, generateKeyPair, importKeyPair, type KeyPair } from "../protocol/crypto";
import { writeFileAtomic } from "../protocol/fsatomic";
import { httpGet, rpcCall } from "../protocol/rpc";
import { signReceipt, type LedgerHead, type WitnessReceipt } from "../protocol/witness";
import { entryHash, type LedgerEntry } from "../ledger/chain";
import { AuditLog } from "../protocol/audit";

interface WitnessState {
  lastCosigned?: LedgerHead;
  receipts: WitnessReceipt[];
  forks: { at: string; expected: LedgerHead; observed: LedgerHead; why: string }[];
}

export class WitnessService {
  readonly kp: KeyPair;
  readonly audit: AuditLog;
  private state: WitnessState = { receipts: [], forks: [] };
  private readonly statePath: string;

  constructor(readonly witnessId: string, readonly dataDir: string, readonly venueUrl: string) {
    const keyPath = join(dataDir, "witness-key.jwk.json");
    if (existsSync(keyPath)) this.kp = importKeyPair(JSON.parse(readFileSync(keyPath, "utf8")));
    else {
      this.kp = generateKeyPair();
      writeFileAtomic(keyPath, JSON.stringify(exportPrivateJwk(this.kp)));
    }
    writeFileAtomic(join(dataDir, "witness-public.jwk.json"), JSON.stringify(this.kp.publicJwk, null, 2));
    this.statePath = join(dataDir, "witness-state.json");
    if (existsSync(this.statePath)) this.state = JSON.parse(readFileSync(this.statePath, "utf8"));
    this.audit = new AuditLog(join(dataDir, "audit.jsonl"));
  }
  private persist() {
    writeFileAtomic(this.statePath, JSON.stringify(this.state, null, 2));
  }
  status() {
    return { witnessId: this.witnessId, publicKey: this.kp.publicJwk, lastCosigned: this.state.lastCosigned ?? null, receipts: this.state.receipts.length, forks: this.state.forks.length };
  }
  receipts(): WitnessReceipt[] {
    return [...this.state.receipts];
  }
  forks() {
    return [...this.state.forks];
  }

  /** One witnessing round. Returns the receipt issued, or the reason none was. */
  async poll(): Promise<{ receipt?: WitnessReceipt; skipped?: string; fork?: string }> {
    let head: LedgerHead & { venueId: string };
    try {
      head = await httpGet<LedgerHead & { venueId: string }>(`${this.venueUrl}/.well-known/ledger-head.json`);
    } catch (e) {
      return { skipped: `venue unreachable: ${String(e).slice(0, 80)}` };
    }
    const last = this.state.lastCosigned;
    if (last && head.seq === last.seq && head.hash === last.hash) return { skipped: "head unchanged" };

    // Consistency: the new head must EXTEND the last one this witness cosigned.
    if (last) {
      let why: string | undefined;
      if (head.seq < last.seq) why = `head went backwards: cosigned seq ${last.seq}, venue now reports seq ${head.seq}`;
      else {
        const entries = await httpGet<LedgerEntry[]>(`${this.venueUrl}/ledger.jsonl?from=${last.seq}`);
        const first = entries.find((e) => e.seq === last.seq);
        if (!first) why = `venue no longer serves seq ${last.seq}`;
        else if (first.hash !== last.hash) why = `seq ${last.seq} now has hash ${first.hash.slice(0, 12)}…, cosigned ${last.hash.slice(0, 12)}…`;
        else {
          let prev = first.hash;
          for (const e of entries.filter((x) => x.seq > last.seq).sort((a, b) => a.seq - b.seq)) {
            if (e.prevHash !== prev || entryHash(e) !== e.hash) { why = `chain broken at seq ${e.seq}`; break; }
            prev = e.hash;
          }
          if (!why && prev !== head.hash) why = `served entries do not reach the reported head`;
        }
      }
      if (why) {
        const fork = { at: new Date().toISOString(), expected: last, observed: { seq: head.seq, hash: head.hash, ts: head.ts }, why };
        this.state.forks.push(fork);
        this.persist();
        this.audit.write({ component: "witness", event: "cosign", outcome: "REFUSED", reasonCode: "LEDGER_FORK_DETECTED", evidence: fork });
        return { fork: why };
      }
    }
    const receipt = signReceipt(this.kp, this.witnessId, head.venueId, head);
    const res = await rpcCall<{ ok: boolean }>(`${this.venueUrl}/a2a`, "venue/witness", { receipt });
    if (res.error) {
      this.audit.write({ component: "witness", event: "cosign", outcome: "INFO", evidence: { error: res.error, seq: head.seq } });
      return { skipped: `venue refused receipt: ${res.error.message}` };
    }
    this.state.lastCosigned = { seq: head.seq, hash: head.hash, ts: head.ts };
    this.state.receipts.push(receipt);
    this.persist();
    this.audit.write({ component: "witness", event: "cosign", outcome: "ALLOWED", evidence: { seq: head.seq, hash: head.hash.slice(0, 12), at: receipt.at } });
    return { receipt };
  }
}
