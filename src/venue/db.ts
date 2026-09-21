/**
 * The venue's transactional store: SQLite via node:sqlite (no dependency).
 *
 * The in-memory maps in VenueState stay the working set; `commit()` writes
 * only what changed since the last commit, inside ONE transaction, so every
 * persisted view is internally consistent and a crash mid-write leaves the
 * previous state. WAL + synchronous=FULL: durable at commit. This replaces
 * the one-big-JSON-snapshot-per-message design, which was the first thing
 * the README said would break; the commit protocol (journal → ledger append
 * → idempotent apply) is untouched.
 */
import { DatabaseSync } from "node:sqlite";

export interface Table<T> {
  name: string;
  /** key → last JSON written, to write only what changed */
  written: Map<string, string>;
  serialize?: (v: T) => Record<string, unknown>;
}

export class VenueDb {
  readonly db: DatabaseSync;
  constructor(readonly path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
    for (const t of ["agents", "tasks", "commitments", "outbox", "dead_letter", "kv"]) this.db.exec(`CREATE TABLE IF NOT EXISTS ${t} (k TEXT PRIMARY KEY, v TEXT NOT NULL, seq INTEGER)`);
    this.db.exec("CREATE TABLE IF NOT EXISTS nonces (k TEXT PRIMARY KEY, v TEXT NOT NULL, ts TEXT NOT NULL)");
    this.db.exec("CREATE INDEX IF NOT EXISTS nonces_ts ON nonces (ts)");
  }

  readAll<T>(table: string): { k: string; v: T; seq: number | null }[] {
    return (this.db.prepare(`SELECT k, v, seq FROM ${table} ORDER BY seq, k`).all() as { k: string; v: string; seq: number | null }[]).map((r) => ({ k: r.k, v: JSON.parse(r.v) as T, seq: r.seq }));
  }

  /** Upsert changed rows and delete missing ones, for several tables, in one transaction. */
  commit(batches: { table: string; rows: { k: string; v: unknown; seq?: number }[]; written: Map<string, string> }[]) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const b of batches) {
        const up = this.db.prepare(`INSERT INTO ${b.table} (k, v, seq) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, seq = excluded.seq`);
        const del = this.db.prepare(`DELETE FROM ${b.table} WHERE k = ?`);
        const seen = new Set<string>();
        for (const r of b.rows) {
          seen.add(r.k);
          const json = JSON.stringify(r.v);
          if (b.written.get(r.k) !== json) { up.run(r.k, json, r.seq ?? null); b.written.set(r.k, json); }
        }
        for (const k of [...b.written.keys()]) if (!seen.has(k)) { del.run(k); b.written.delete(k); }
      }
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  /** Nonces have their own life: inserted as seen, swept by age. */
  nonceSeen(nonce: string): { messageId: string; ts: string; senderAgentId: string } | undefined {
    const r = this.db.prepare("SELECT v FROM nonces WHERE k = ?").get(nonce) as { v: string } | undefined;
    return r ? JSON.parse(r.v) : undefined;
  }
  nonceInsert(nonce: string, v: { messageId: string; ts: string; senderAgentId: string }) {
    this.db.prepare("INSERT OR IGNORE INTO nonces (k, v, ts) VALUES (?, ?, ?)").run(nonce, JSON.stringify(v), v.ts);
  }
  nonceSweep(olderThan: Date): number {
    return Number(this.db.prepare("DELETE FROM nonces WHERE ts < ?").run(olderThan.toISOString()).changes);
  }
  nonceCount(): number {
    return Number((this.db.prepare("SELECT count(*) c FROM nonces").get() as { c: number }).c);
  }
  close() {
    this.db.close();
  }
}

/** Read a venue's persisted state without the venue process (tests, the simulator after a crash). */
export function readVenueDb(path: string): { agents: Record<string, unknown>; tasks: Record<string, unknown>; commitments: Record<string, unknown>; outbox: unknown[]; deadLetter: unknown[]; kv: Record<string, unknown>; nonces: number } {
  const db = new DatabaseSync(path, { readOnly: true });
  const table = (t: string) => Object.fromEntries((db.prepare(`SELECT k, v FROM ${t} ORDER BY seq, k`).all() as { k: string; v: string }[]).map((r) => [r.k, JSON.parse(r.v)]));
  const list = (t: string) => (db.prepare(`SELECT v FROM ${t} ORDER BY seq, k`).all() as { v: string }[]).map((r) => JSON.parse(r.v));
  const out = { agents: table("agents"), tasks: table("tasks"), commitments: table("commitments"), outbox: list("outbox"), deadLetter: list("dead_letter"), kv: table("kv"), nonces: Number((db.prepare("SELECT count(*) c FROM nonces").get() as { c: number }).c) };
  db.close();
  return out;
}
