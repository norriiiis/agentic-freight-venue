/**
 * Venue persistence.
 *
 *   state/venue.sqlite    agents, tasks, commitments, outbox, dead letter, nonces
 *                         and the small kv (heartbeat, witnesses, receipts,
 *                         sources) — one SQLite database (node:sqlite, WAL,
 *                         synchronous=FULL). persist() commits only what
 *                         changed, in ONE transaction, so every persisted
 *                         view is internally consistent. Nonces live in
 *                         their own table with a TTL sweep.
 *   state/journal/<id>    write-ahead intent for a commit or void in progress;
 *                         written before the ledger append, deleted after all
 *                         side effects are applied and persisted. Recovery on
 *                         startup replays or discards these.
 *   state/messages.jsonl  raw wire log (forensics only; append-only).
 */
import type { InsurerAttestation } from "../protocol/registry";
import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { appendDurable, writeFileAtomic } from "../protocol/fsatomic";
import { VenueDb } from "./db";
import type { AgentCard, Message, Task } from "../protocol/a2a";
import type { LoadSpec, Terms } from "../protocol/freight";
import type { MandateEnvelope } from "../protocol/types";
import type { ReasonCode } from "../protocol/reasons";
import type { CommitmentArtifact } from "../ledger/artifact";
import type { RootEvent, VenueKeyCert, VenueKeyRevocation } from "../protocol/venue-keys";
import type { WitnessKey, WitnessReceipt } from "../protocol/witness";
import type { OkpJwk } from "../protocol/crypto";

export interface RegisteredAgent {
  agentId: string;
  /** The credential that currently represents this agent. */
  credentialId: string;
  /** Superseded credentials in this agent's lineage (still accepted inside their grace window; needed to read old signatures). */
  previousCredentialIds: string[];
  url: string;
  card: AgentCard;
  envelope?: MandateEnvelope;
  /** The insurer's own signed word about this party's filing (the COI on file), presented at onboarding or renewed since. */
  insurerAttestation?: InsurerAttestation;
  registeredAt: string;
  rotatedAt?: string;
}

export interface Offer {
  rateUsd: number;
  pickup: Terms["pickup"];
  delivery: Terms["delivery"];
  paymentTermsDays: number;
}

export interface NegotiationTask {
  task: Task;
  loadRef: string;
  load: LoadSpec;
  brokerAgentId: string;
  carrierAgentId: string;
  round: number;
  createdAt: string;
  /** Whose message the venue is waiting for, and since when (drives the reply timeout). */
  awaiting: string;
  awaitingSince: string;
  onTable?: { offer: Offer; by: string; round: number };
  acceptances: Record<string, Message>;
  status: "NEGOTIATING" | "COUNTERSIGN" | "COMMITTED" | "FAILED" | "REJECTED" | "CANCELED";
  outcome?: { reasonCode: ReasonCode; refusedBy: string; evidence: Record<string, unknown>; guaranteeWouldHavePaid?: string };
  commitmentId?: string;
}

export interface CommitmentRecord {
  commitmentId: string;
  taskId: string;
  loadRef: string;
  loadFingerprint: string;
  brokerAgentId: string;
  carrierAgentId: string;
  brokerUsdot: string;
  carrierUsdot: string;
  rateUsd: number;
  pickupWindowStart: string;
  status: "ACTIVE" | "VOIDED" | "COMPLETED";
  guaranteeId?: string;
  artifact: CommitmentArtifact;
  voided?: { at: string; reasonCode: ReasonCode; evidence: Record<string, unknown> };
  /** A conditional commitment: the carrier's insurer must re-attest coverage through delivery, signed within the window, by pickup. */
  renewal?: { earliestSignedAt: string; dueBy: string; satisfied?: { attestation: InsurerAttestation; assuredThrough: string; ledgerSeq: number; at: string } };
}

/** A notice the venue owes an agent. Persisted until delivered (at-least-once); agents dedupe by messageId. */
export interface PendingNotice {
  id: string;
  toAgentId: string;
  message: Message;
  enqueuedAt: string;
  attempts: number;
  nextAttemptAt: string;
  note?: string;
}

/** Write-ahead intent for a commit: everything needed to (re)apply its side effects. */
export interface CommitJournal {
  kind: "COMMIT";
  commitmentId: string;
  taskId: string;
  writtenAt: string;
  artifact: CommitmentArtifact;
  guarantee?: { guaranteeId: string; counterpartyUsdot: string; beneficiaryUsdot: string; coveredAmountUsd: number; premiumUsd: number; day: string; probabilityOfLoss: number; factors: unknown };
  declined?: { reasonCode: ReasonCode; evidence: Record<string, unknown> };
  ledger: { seq: number; prevHash: string };
}
export interface VoidJournal {
  kind: "VOID";
  commitmentId: string;
  writtenAt: string;
  reasonCode: ReasonCode;
  evidence: Record<string, unknown>;
  /** What triggered the void (audit event name). */
  origin?: "pre-pickup-check" | "compromise-void" | "renewal-check";
}
export interface KeyRotationJournal {
  kind: "KEY_ROTATION";
  /** journal file name; not a commitment */
  commitmentId: string;
  writtenAt: string;
  previousKid: string;
  cert: VenueKeyCert;
  revocation?: VenueKeyRevocation;
}
export interface RootRotationJournal {
  kind: "ROOT_ROTATION";
  commitmentId: string; // journal file name
  writtenAt: string;
  event: RootEvent;
  recert?: VenueKeyCert;
}
export type Journal = CommitJournal | VoidJournal | KeyRotationJournal | RootRotationJournal;

interface Snapshot {
  agents: Record<string, RegisteredAgent>;
  tasks: Record<string, NegotiationTask>;
  commitments: Record<string, CommitmentRecord>;
  nonces: Record<string, { messageId: string; ts: string; senderAgentId: string }>;
  outbox: PendingNotice[];
  deadLetter: PendingNotice[];
  /** Last moment this venue was known to be alive; recovery measures downtime from it. */
  lastAliveAt?: string;
  /** Independent witnesses whose receipts this venue accepts (configured out of band; the venue cannot mint them). */
  witnesses: WitnessKey[];
  /** Receipts by ledger head hash. */
  witnessReceipts: Record<string, WitnessReceipt[]>;
  /** Sources whose signed status notices are accepted. */
  noticeSources: { sourceId: string; publicKey: OkpJwk; insurerName?: string }[];
}

export class VenueState {
  agents = new Map<string, RegisteredAgent>();
  tasks = new Map<string, NegotiationTask>();
  commitments = new Map<string, CommitmentRecord>();
  /** Nonces are read and written through the database (their own table, TTL-swept); this map-like shim keeps the call sites. */
  readonly nonces: { get(nonce: string): { messageId: string; ts: string; senderAgentId: string } | undefined; set(nonce: string, v: { messageId: string; ts: string; senderAgentId: string }): void; get size(): number };
  outbox: PendingNotice[] = [];
  deadLetter: PendingNotice[] = [];
  lastAliveAt?: string;
  witnesses: WitnessKey[] = [];
  witnessReceipts: Record<string, WitnessReceipt[]> = {};
  /** Registered sources (registry feeds, insurers, …). An insurer's `insurerName` is the name it files under — what makes its word "of record". */
  noticeSources: { sourceId: string; publicKey: OkpJwk; insurerName?: string }[] = [];
  private readonly dir: string;
  private readonly journalDir: string;
  readonly db: VenueDb;
  private readonly written = { agents: new Map<string, string>(), tasks: new Map<string, string>(), commitments: new Map<string, string>(), outbox: new Map<string, string>(), dead_letter: new Map<string, string>(), kv: new Map<string, string>() };

  constructor(dataDir: string) {
    this.dir = join(dataDir, "state");
    this.journalDir = join(this.dir, "journal");
    mkdirSync(this.journalDir, { recursive: true });
    this.db = new VenueDb(this.file("venue.sqlite"));
    const db = this.db;
    this.nonces = { get: (n) => db.nonceSeen(n), set: (n, v) => db.nonceInsert(n, v), get size() { return db.nonceCount(); } };
    this.load();
  }
  private file(name: string) {
    return join(this.dir, name);
  }
  private load() {
    // One-time migration from the JSON snapshot this store replaced.
    const legacy = this.file("snapshot.json");
    if (existsSync(legacy) && this.db.readAll("kv").length === 0) {
      const s = JSON.parse(readFileSync(legacy, "utf8")) as Snapshot;
      this.agents = new Map(Object.entries(s.agents)); this.tasks = new Map(Object.entries(s.tasks)); this.commitments = new Map(Object.entries(s.commitments));
      this.outbox = s.outbox ?? []; this.deadLetter = s.deadLetter ?? []; this.lastAliveAt = s.lastAliveAt; this.witnesses = s.witnesses ?? []; this.witnessReceipts = s.witnessReceipts ?? {}; this.noticeSources = s.noticeSources ?? [];
      for (const [k, v] of Object.entries(s.nonces)) this.db.nonceInsert(k, v);
      this.persist();
      unlinkSync(legacy);
      return;
    }
    const rows = <T>(t: string, w: Map<string, string>) => this.db.readAll<T>(t).map((r) => { w.set(r.k, JSON.stringify(r.v)); return r; });
    this.agents = new Map(rows<RegisteredAgent>("agents", this.written.agents).map((r) => [r.k, r.v]));
    this.tasks = new Map(rows<NegotiationTask>("tasks", this.written.tasks).map((r) => [r.k, r.v]));
    this.commitments = new Map(rows<CommitmentRecord>("commitments", this.written.commitments).map((r) => [r.k, r.v]));
    this.outbox = rows<PendingNotice>("outbox", this.written.outbox).map((r) => r.v);
    this.deadLetter = rows<PendingNotice>("dead_letter", this.written.dead_letter).map((r) => r.v);
    const kv = Object.fromEntries(rows<unknown>("kv", this.written.kv).map((r) => [r.k, r.v])) as Partial<Pick<Snapshot, "lastAliveAt" | "witnesses" | "witnessReceipts" | "noticeSources">>;
    this.lastAliveAt = kv.lastAliveAt; this.witnesses = kv.witnesses ?? []; this.witnessReceipts = kv.witnessReceipts ?? {}; this.noticeSources = kv.noticeSources ?? [];
  }
  /** One transaction: only what changed is written, and all of it or none. Doubles as a heartbeat. */
  persist() {
    this.lastAliveAt = new Date().toISOString();
    this.db.commit([
      { table: "agents", rows: [...this.agents].map(([k, v]) => ({ k, v })), written: this.written.agents },
      { table: "tasks", rows: [...this.tasks].map(([k, v]) => ({ k, v })), written: this.written.tasks },
      { table: "commitments", rows: [...this.commitments].map(([k, v]) => ({ k, v })), written: this.written.commitments },
      { table: "outbox", rows: this.outbox.map((n, i) => ({ k: n.id, v: n, seq: i })), written: this.written.outbox },
      { table: "dead_letter", rows: this.deadLetter.map((n, i) => ({ k: n.id, v: n, seq: i })), written: this.written.dead_letter },
      { table: "kv", rows: [{ k: "lastAliveAt", v: this.lastAliveAt }, { k: "witnesses", v: this.witnesses }, { k: "witnessReceipts", v: this.witnessReceipts }, { k: "noticeSources", v: this.noticeSources }], written: this.written.kv },
    ]);
  }
  /** Forget nonces older than the message acceptance window: a replay outside the window is refused as stale anyway. */
  sweepNonces(maxAgeMs: number, now = new Date()): number {
    return this.db.nonceSweep(new Date(now.getTime() - maxAgeMs));
  }

  // ---- write-ahead journal ----
  writeJournal(j: Journal) {
    writeFileAtomic(join(this.journalDir, `${j.commitmentId}.json`), JSON.stringify(j));
  }
  readJournals(): Journal[] {
    return readdirSync(this.journalDir).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(readFileSync(join(this.journalDir, f), "utf8")) as Journal);
  }
  deleteJournal(commitmentId: string) {
    const p = join(this.journalDir, `${commitmentId}.json`);
    if (existsSync(p)) unlinkSync(p);
  }

  logMessage(direction: "IN" | "OUT", m: Message, note?: string) {
    appendDurable(this.file("messages.jsonl"), JSON.stringify({ ts: new Date().toISOString(), direction, note, message: m }) + "\n");
  }
  messageLog(): { ts: string; direction: "IN" | "OUT"; note?: string; message: Message }[] {
    if (!existsSync(this.file("messages.jsonl"))) return [];
    return readFileSync(this.file("messages.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }
  /** Find the agent a credential belongs to — current or anywhere in its rotation lineage. */
  agentByCredential(credentialId: string): RegisteredAgent | undefined {
    return [...this.agents.values()].find((a) => a.credentialId === credentialId || (a.previousCredentialIds ?? []).includes(credentialId));
  }
}
