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
  | "witness"
  | "sim";

export interface AuditEntry {
  ts: string;
  seq: number;
  /** Idempotency key: writeOnce() skips an entry whose key is already on file (crash-safe re-application). */
  key?: string;
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
  private keys = new Set<string>();
  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
      this.seq = lines.length;
      for (const l of lines) {
        const k = (JSON.parse(l) as AuditEntry).key;
        if (k) this.keys.add(k);
      }
    }
  }
  /** Write unless an entry with this key already exists. Returns the entry, or undefined if skipped. */
  writeOnce(key: string, e: Omit<AuditEntry, "ts" | "seq" | "key">): AuditEntry | undefined {
    if (this.keys.has(key)) return undefined;
    this.keys.add(key);
    return this.write({ ...e, key } as Omit<AuditEntry, "ts" | "seq">);
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
