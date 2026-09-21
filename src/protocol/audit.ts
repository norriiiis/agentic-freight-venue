/**
 * Audit entries. Every component that refuses something writes one of these,
 * naming itself, the reason code, and the evidence it relied on.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { ReasonCode } from "./reasons";
import { canonicalize, sha256Hex } from "./canonical";

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
  /** Hash chain: sha256 of the previous entry's `hash` and this entry's content. A removed or edited line breaks the chain. */
  prevHash?: string;
  hash?: string;
}

export function auditEntryHash(prevHash: string, e: Omit<AuditEntry, "hash" | "prevHash">): string {
  return sha256Hex(prevHash + "\n" + canonicalize(e));
}

/** Verify an audit log's chain: every entry links to the one before it. */
export function verifyAuditChain(entries: AuditEntry[]): { ok: boolean; firstBadSeq?: number; error?: string } {
  let prev = "0".repeat(64);
  for (const e of entries) {
    const { hash, prevHash, ...content } = e;
    if (prevHash === undefined && hash === undefined) { prev = ""; continue; } // pre-chain entries (older logs)
    if (prevHash !== prev) return { ok: false, firstBadSeq: e.seq, error: "prevHash does not match the previous entry" };
    if (hash !== auditEntryHash(prev, content)) return { ok: false, firstBadSeq: e.seq, error: "entry hash does not match its content" };
    prev = hash;
  }
  return { ok: true };
}

export class AuditLog {
  private seq = 0;
  private keys = new Set<string>();
  private prevHash = "0".repeat(64);
  /** Observers (metrics, alerts) see every entry as it is written. */
  private listeners: ((e: AuditEntry) => void)[] = [];
  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
      this.seq = lines.length;
      for (const l of lines) {
        const e = JSON.parse(l) as AuditEntry;
        if (e.key) this.keys.add(e.key);
        if (e.hash) this.prevHash = e.hash;
      }
    }
  }
  onWrite(fn: (e: AuditEntry) => void) {
    this.listeners.push(fn);
  }
  /** Write unless an entry with this key already exists. Returns the entry, or undefined if skipped. */
  writeOnce(key: string, e: Omit<AuditEntry, "ts" | "seq" | "key">): AuditEntry | undefined {
    if (this.keys.has(key)) return undefined;
    this.keys.add(key);
    return this.write({ ...e, key } as Omit<AuditEntry, "ts" | "seq">);
  }
  write(e: Omit<AuditEntry, "ts" | "seq" | "hash" | "prevHash">): AuditEntry {
    const content: Omit<AuditEntry, "hash" | "prevHash"> = { ts: new Date().toISOString(), seq: ++this.seq, ...e };
    const entry: AuditEntry = { ...content, prevHash: this.prevHash, hash: auditEntryHash(this.prevHash, content) };
    this.prevHash = entry.hash!;
    appendFileSync(this.path, JSON.stringify(entry) + "\n");
    for (const l of this.listeners) { try { l(entry); } catch { /* an observer never breaks the audit */ } }
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
