/**
 * The primitives that make a venue commit crash-safe: idempotent side effects
 * keyed by commitment id, atomic snapshot writes, and a journal that survives
 * a process death.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, readdirSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ExposureBook } from "../src/mandate/exposure";
import { UnderwritingEngine } from "../src/underwriting/engine";
import { readVenueDb } from "../src/venue/db";
import { VenueState, type CommitJournal } from "../src/venue/state";
import { writeFileAtomic, appendDurable } from "../src/protocol/fsatomic";
import { Ledger, verifyChain } from "../src/ledger/chain";
import { generateKeyPair } from "../src/protocol/crypto";

const tmp = () => mkdtempSync(join(tmpdir(), "fv-txn-"));

describe("idempotent side effects", () => {
  it("exposure book applies an add/release with a ref exactly once, even across a reload", () => {
    const path = join(tmp(), "exposure.json");
    const b = new ExposureBook(path);
    b.add("2751903", 2215, "2026-09-23", "cmt_1");
    b.add("2751903", 2215, "2026-09-23", "cmt_1"); // re-apply: no-op
    expect(b.outstanding("2751903")).toBe(2215);
    const reloaded = new ExposureBook(path); // a restarted process re-applying the same commit
    reloaded.add("2751903", 2215, "2026-09-23", "cmt_1");
    expect(reloaded.outstanding("2751903")).toBe(2215);
    reloaded.release("2751903", 2215, "2026-09-23", "cmt_1");
    reloaded.release("2751903", 2215, "2026-09-23", "cmt_1");
    expect(reloaded.outstanding("2751903")).toBe(0);
    // refs are per operation: a fresh commitment still counts
    reloaded.add("2751903", 1000, "2026-09-23", "cmt_2");
    expect(reloaded.outstanding("2751903")).toBe(1000);
  });

  it("underwriting quote is pure; attach is idempotent by commitment; release is idempotent", () => {
    const dir = tmp();
    const u = new UnderwritingEngine(dir);
    const inputs = { usdot: "2751903", authorityAgeDays: 3000, safetyRating: "SATISFACTORY" as const, powerUnits: 42, bipdUsd: 1_000_000, requiredBipdUsd: 1_000_000, vettingFlags: [], credentialAgeDays: 10, registrySnapshotChangedSinceIssuance: false, history: u.historyFor("2751903"), amountUsd: 2215 };
    const q1 = u.quote(inputs, "3312874", "2026-09-23");
    const q2 = u.quote(inputs, "3312874", "2026-09-23");
    expect(q1.decision).toBe("GUARANTEED");
    expect(u.allGuarantees()).toEqual([]); // quoting wrote nothing
    expect(u.exposure("2751903", "3312874").counterpartyOutstandingUsd).toBe(0);
    if (q1.decision !== "GUARANTEED" || q2.decision !== "GUARANTEED") throw new Error("expected quotes");
    const spec = { guaranteeId: q1.guarantee.guaranteeId, counterpartyUsdot: "2751903", beneficiaryUsdot: "3312874", coveredAmountUsd: 2215, premiumUsd: q1.guarantee.premiumUsd, day: "2026-09-23" };
    const a1 = u.attach(spec, "cmt_1");
    const a2 = u.attach({ ...spec, guaranteeId: q2.guarantee.guaranteeId }, "cmt_1"); // recovery re-applies with the journal's id
    expect(a2.guaranteeId).toBe(a1.guaranteeId);
    expect(u.allGuarantees().filter((g) => g.status === "ATTACHED")).toHaveLength(1);
    expect(u.exposure("2751903", "3312874").counterpartyOutstandingUsd).toBe(2215);
    expect(u.historyFor("2751903").loadsCommitted).toBe(1);
    // reload from disk and re-apply again
    const u2 = new UnderwritingEngine(dir);
    u2.attach(spec, "cmt_1");
    expect(u2.exposure("2751903", "3312874").counterpartyOutstandingUsd).toBe(2215);
    u2.release(a1.guaranteeId, "test");
    u2.release(a1.guaranteeId, "test");
    expect(u2.exposure("2751903", "3312874").counterpartyOutstandingUsd).toBe(0);
    expect(u2.allGuarantees().filter((g) => g.status === "RELEASED")).toHaveLength(1);
  });
});

describe("atomic persistence and journal", () => {
  it("writeFileAtomic leaves no temp files and the previous content survives until rename", () => {
    const dir = tmp();
    const p = join(dir, "snapshot.json");
    writeFileAtomic(p, '{"v":1}');
    writeFileAtomic(p, '{"v":2}');
    expect(JSON.parse(readFileSync(p, "utf8"))).toEqual({ v: 2 });
    expect(readdirSync(dir)).toEqual(["snapshot.json"]);
  });
  it("appendDurable produces whole lines", () => {
    const p = join(tmp(), "log.jsonl");
    appendDurable(p, "a\n");
    appendDurable(p, "b\n");
    expect(readFileSync(p, "utf8")).toBe("a\nb\n");
  });
  it("venue state round-trips through SQLite in one transaction; journal survives a 'restart'; nonces sweep by age", () => {
    const dir = tmp();
    const s = new VenueState(dir);
    s.nonces.set("n1", { messageId: "m1", ts: new Date(Date.now() - 3_600_000).toISOString(), senderAgentId: "a" });
    s.nonces.set("n2", { messageId: "m2", ts: new Date().toISOString(), senderAgentId: "a" });
    s.outbox.push({ id: "o1", toAgentId: "a", message: { kind: "message", role: "agent", parts: [], messageId: "m2" }, enqueuedAt: "t", attempts: 0, nextAttemptAt: "t" });
    s.persist();
    const j: CommitJournal = { kind: "COMMIT", commitmentId: "cmt_x", taskId: "task_x", writtenAt: "t", artifact: {} as never, ledger: { seq: 1, prevHash: "0".repeat(64) } };
    s.writeJournal(j);
    s.db.close();
    const s2 = new VenueState(dir); // the restarted process
    expect(s2.nonces.get("n1")?.messageId).toBe("m1");
    expect(s2.outbox).toHaveLength(1);
    expect(s2.readJournals().map((x) => x.commitmentId)).toEqual(["cmt_x"]);
    s2.deleteJournal("cmt_x");
    expect(s2.readJournals()).toEqual([]);
    expect(existsSync(join(dir, "state", "venue.sqlite"))).toBe(true);
    // Nonces older than the acceptance window are swept; the fresh one stays.
    expect(s2.sweepNonces(5 * 60_000)).toBe(1);
    expect(s2.nonces.get("n1")).toBeUndefined();
    expect(s2.nonces.get("n2")?.messageId).toBe("m2");
    // Only changed rows are written: a second persist with nothing changed touches nothing (the written cache agrees).
    s2.outbox = [];
    s2.persist();
    s2.db.close();
    const s3 = new VenueState(dir);
    expect(s3.outbox).toEqual([]);
    expect(readVenueDb(join(dir, "state", "venue.sqlite")).nonces).toBe(1);
    s3.db.close();
  });
  it("ledger append is durable-before-visible and the chain verifies after reload", () => {
    const dir = tmp();
    const kp = generateKeyPair();
    const l = new Ledger(join(dir, "ledger.jsonl"), kp);
    l.append("COMMITMENT", { commitmentId: "cmt_1", guarantee: { guaranteeId: "g1", coveredAmountUsd: 2215 } });
    const l2 = new Ledger(join(dir, "ledger.jsonl"), kp);
    expect(l2.all()).toHaveLength(2);
    expect(verifyChain(l2.all(), kp.publicJwk).ok).toBe(true);
    expect((l2.head.payload as { guarantee: { guaranteeId: string } }).guarantee.guaranteeId).toBe("g1"); // guarantee rides in the same entry
  });
});
