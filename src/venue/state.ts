/**
 * Venue persistence: registered agents, negotiation tasks, commitments, seen
 * nonces, and the raw message log. JSON files in the venue's own data dir.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
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
  /** Whose message the venue is waiting for. */
  awaiting: string;
  onTable?: { offer: Offer; by: string; round: number };
  acceptances: Record<string, Message>;
  status: "NEGOTIATING" | "COUNTERSIGN" | "COMMITTED" | "FAILED" | "REJECTED";
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

export class VenueState {
  agents = new Map<string, RegisteredAgent>();
  tasks = new Map<string, NegotiationTask>();
  commitments = new Map<string, CommitmentRecord>();
  nonces = new Map<string, { messageId: string; ts: string; senderAgentId: string }>();
  private readonly dir: string;

  constructor(dataDir: string) {
    this.dir = join(dataDir, "state");
    mkdirSync(this.dir, { recursive: true });
    this.load();
  }
  private file(name: string) {
    return join(this.dir, name);
  }
  private load() {
    const rd = <T>(name: string, fallback: T): T => (existsSync(this.file(name)) ? JSON.parse(readFileSync(this.file(name), "utf8")) : fallback);
    this.agents = new Map(Object.entries(rd<Record<string, RegisteredAgent>>("agents.json", {})));
    this.tasks = new Map(Object.entries(rd<Record<string, NegotiationTask>>("tasks.json", {})));
    this.commitments = new Map(Object.entries(rd<Record<string, CommitmentRecord>>("commitments.json", {})));
    this.nonces = new Map(Object.entries(rd<Record<string, { messageId: string; ts: string; senderAgentId: string }>>("nonces.json", {})));
  }
  persist() {
    writeFileSync(this.file("agents.json"), JSON.stringify(Object.fromEntries(this.agents), null, 2));
    writeFileSync(this.file("tasks.json"), JSON.stringify(Object.fromEntries(this.tasks), null, 2));
    writeFileSync(this.file("commitments.json"), JSON.stringify(Object.fromEntries(this.commitments), null, 2));
    writeFileSync(this.file("nonces.json"), JSON.stringify(Object.fromEntries(this.nonces), null, 2));
  }
  logMessage(direction: "IN" | "OUT", m: Message, note?: string) {
    appendFileSync(this.file("messages.jsonl"), JSON.stringify({ ts: new Date().toISOString(), direction, note, message: m }) + "\n");
  }
  messageLog(): { ts: string; direction: "IN" | "OUT"; note?: string; message: Message }[] {
    if (!existsSync(this.file("messages.jsonl"))) return [];
    return readFileSync(this.file("messages.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }
  agentByCredential(credentialId: string): RegisteredAgent | undefined {
    return [...this.agents.values()].find((a) => a.credentialId === credentialId);
  }
}
