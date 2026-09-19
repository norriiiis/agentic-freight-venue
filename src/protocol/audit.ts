/**
 * Audit entries. Every component that refuses something writes one of these,
 * naming itself, the reason code, and the evidence it relied on.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { ReasonCode } from "./reasons";

export type Component =
  | "venue.identity"
  | "venue.protocol"
  | "venue.mandate"
  | "venue.routing"
  | "venue.commitment"
  | "underwriting"
  | "ledger"
  | "agent.broker.mandate"
  | "agent.broker.strategy"
  | "agent.broker.runtime"
  | "agent.carrier.mandate"
  | "agent.carrier.strategy"
  | "agent.carrier.runtime"
  | "sim";

export interface AuditEntry {
  ts: string;
  seq: number;
  component: Component;
  event: string;
  outcome: "ALLOWED" | "REFUSED" | "INFO" | "VOIDED";
  reasonCode?: ReasonCode;
  taskId?: string;
  contextId?: string;
  subject?: string;
  evidence?: Record<string, unknown>;
}

export class AuditLog {
  private seq = 0;
  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      this.seq = readFileSync(path, "utf8").split("\n").filter(Boolean).length;
    }
  }
  write(e: Omit<AuditEntry, "ts" | "seq">): AuditEntry {
    const entry: AuditEntry = { ts: new Date().toISOString(), seq: ++this.seq, ...e };
    appendFileSync(this.path, JSON.stringify(entry) + "\n");
    return entry;
  }
  readAll(): AuditEntry[] {
    if (!existsSync(this.path)) return [];
    return readFileSync(this.path, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  }
}
