/**
 * Venue persistence.
 *
 *   state/snapshot.json   agents, tasks, commitments, nonces, outbox — ONE file,
 *                         written atomically (temp + fsync + rename), so every
 *                         persisted view of the venue is internally consistent.
 *   state/journal/<id>    write-ahead intent for a commit or void in progress;
 *                         written before the ledger append, deleted after all
 *                         side effects are applied and persisted. Recovery on
 *                         startup replays or discards these.
 *   state/messages.jsonl  raw wire log (forensics only; append-only).
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { appendDurable, writeFileAtomic } from "../protocol/fsatomic";
import type { AgentCard, Message, Task } from "../protocol/a2a";
import type { LoadSpec, Terms } from "../protocol/freight";
import type { MandateEnvelope } from "../protocol/types";
import type { ReasonCode } from "../protocol/reasons";
import type { CommitmentArtifact } from "../ledger/artifact";

export interface RegisteredAgent {
  agentId: string;
  credentialId: string;
  url: string;
  card: AgentCard;
  envelope?: MandateEnvelope;
  registeredAt: string;
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
}
export type Journal = CommitJournal | VoidJournal;

interface Snapshot {
  agents: Record<string, RegisteredAgent>;
  tasks: Record<string, NegotiationTask>;
  commitments: Record<string, CommitmentRecord>;
  nonces: Record<string, { messageId: string; ts: string; senderAgentId: string }>;
  outbox: PendingNotice[];
}

export class VenueState {
  agents = new Map<string, RegisteredAgent>();
  tasks = new Map<string, NegotiationTask>();
  commitments = new Map<string, CommitmentRecord>();
  nonces = new Map<string, { messageId: string; ts: string; senderAgentId: string }>();
  outbox: PendingNotice[] = [];
  private readonly dir: string;
  private readonly journalDir: string;

  constructor(dataDir: string) {
    this.dir = join(dataDir, "state");
    this.journalDir = join(this.dir, "journal");
    mkdirSync(this.journalDir, { recursive: true });
    this.load();
  }
  private file(name: string) {
    return join(this.dir, name);
  }
  private load() {
    const p = this.file("snapshot.json");
    if (!existsSync(p)) return;
    const s = JSON.parse(readFileSync(p, "utf8")) as Snapshot;
    this.agents = new Map(Object.entries(s.agents));
    this.tasks = new Map(Object.entries(s.tasks));
    this.commitments = new Map(Object.entries(s.commitments));
    this.nonces = new Map(Object.entries(s.nonces));
    this.outbox = s.outbox ?? [];
  }
  /** One atomic write. Either the whole new state is on disk or none of it. */
  persist() {
    const s: Snapshot = { agents: Object.fromEntries(this.agents), tasks: Object.fromEntries(this.tasks), commitments: Object.fromEntries(this.commitments), nonces: Object.fromEntries(this.nonces), outbox: this.outbox };
    writeFileAtomic(this.file("snapshot.json"), JSON.stringify(s));
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
  agentByCredential(credentialId: string): RegisteredAgent | undefined {
    return [...this.agents.values()].find((a) => a.credentialId === credentialId);
  }
}
