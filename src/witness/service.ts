/**
 * The standalone witness process: the shared witnessing core (protocol/witness-core.ts)
 * with a file-backed store and its own key. See that file for the rules.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { KeyPair } from "../protocol/crypto";
import { keyProviderFromEnv, loadOrCreate } from "../protocol/keys";
import { writeFileAtomic } from "../protocol/fsatomic";
import type { EquivocationProof, LedgerHead, WitnessReceipt } from "../protocol/witness";
import type { BrokenPromiseProof, InclusionPromise, StatusNotice } from "../protocol/inclusion";
import { WitnessCore, emptyWitnessState, type WitnessCoreState, type WitnessPeer } from "../protocol/witness-core";
import { AuditLog, type Component } from "../protocol/audit";

export type { WitnessPeer } from "../protocol/witness-core";

export class WitnessService {
  readonly kp: KeyPair;
  readonly audit: AuditLog;
  private state: WitnessCoreState = emptyWitnessState();
  private readonly statePath: string;
  private readonly core: WitnessCore;
  /** SIM fault: collude — sign any head handed to it. */
  signAnything = false;

  constructor(readonly witnessId: string, readonly dataDir: string, readonly venueUrl: string, public peers: WitnessPeer[] = []) {
    this.kp = loadOrCreate(keyProviderFromEnv((name) => join(dataDir, `${name}.jwk.json`)), "witness-key");
    writeFileAtomic(join(dataDir, "witness-public.jwk.json"), JSON.stringify(this.kp.publicJwk, null, 2));
    this.statePath = join(dataDir, "witness-state.json");
    if (existsSync(this.statePath)) this.state = { ...emptyWitnessState(), ...JSON.parse(readFileSync(this.statePath, "utf8")) };
    this.audit = new AuditLog(join(dataDir, "audit.jsonl"));
    this.core = new WitnessCore({
      witnessId,
      kp: this.kp,
      venueUrl,
      peers: () => this.peers,
      state: () => this.state,
      persist: () => writeFileAtomic(this.statePath, JSON.stringify(this.state, null, 2)),
      log: (event, outcome, evidence, reasonCode) => this.audit.write({ component: "witness" as Component, event, outcome, evidence, reasonCode: reasonCode as never }),
      signAnything: () => this.signAnything,
    });
  }
  addPeers(peers: WitnessPeer[]) {
    for (const p of peers) if (!this.peers.some((x) => x.witnessId === p.witnessId)) this.peers.push(p);
  }
  status() {
    return { witnessId: this.witnessId, publicKey: this.kp.publicJwk, lastCosigned: this.state.lastCosigned ?? null, receipts: this.state.receipts.length, forks: this.state.forks.length, equivocations: this.state.equivocations.length, halted: this.state.halted ?? null, peers: this.peers.map((p) => p.witnessId), colluding: this.signAnything, watching: this.state.watching.length, pending: this.state.pending.length, broken: this.state.broken.length };
  }
  receipts(): WitnessReceipt[] { return [...this.state.receipts]; }
  latestReceipt(): WitnessReceipt | undefined { return this.core.latestReceipt(); }
  receiptFor(seq: number): WitnessReceipt | undefined { return this.core.receiptFor(seq); }
  forks() { return [...this.state.forks]; }
  equivocations(): EquivocationProof[] { return [...this.state.equivocations]; }
  poll() { return this.core.poll(); }
  gossip() { return this.core.gossip(); }
  receiveGossip(r: WitnessReceipt) { return this.core.receiveGossip(r); }
  receiveProof(p: EquivocationProof) { return this.core.receiveProof(p); }
  signBlindly(venueId: string, head: LedgerHead) { return this.core.signBlindly(venueId, head); }
  watch(item: { promise: InclusionPromise } | { notice: StatusNotice; submissionOutcome: string }) { return this.core.watch(item); }
  receiveBroken(p: BrokenPromiseProof) { return this.core.receiveBroken(p); }
  pending() { return [...this.state.pending]; }
  broken() { return [...this.state.broken]; }
  resolved() { return [...this.state.resolved]; }
}
