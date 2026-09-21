import { describe, it, expect } from "vitest";
import { RateLimiter, startServer } from "../src/protocol/rpc";

describe("transport hardening (shared by every process)", () => {
  it("token bucket: bursts to capacity, then refills at the sustained rate", () => {
    const l = new RateLimiter(2, 1);
    const t0 = 1_000_000;
    expect(l.allow("a", t0)).toBe(true);
    expect(l.allow("a", t0)).toBe(true);
    expect(l.allow("a", t0)).toBe(false);
    expect(l.allow("b", t0)).toBe(true); // another caller, another bucket
    expect(l.allow("a", t0 + 1000)).toBe(true); // one token back after a second
    expect(l.allow("a", t0 + 1000)).toBe(false);
  });

  it("serves 429 past the limit, 401 on /ops without the token, and the ops route with it", async () => {
    const server = await startServer(0, {
      rpcPath: "/rpc",
      rpc: async () => ({ ok: true }),
      routes: { "GET /ops/health": async () => ({ status: 200, body: { ok: true } }), "GET /open": async () => ({ status: 200, body: { ok: true } }) },
      rateLimit: { perSecond: 2 },
      opsToken: "s3cret",
    });
    const port = (server.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    const codes: number[] = [];
    for (let i = 0; i < 6; i++) codes.push((await fetch(`${base}/open`)).status);
    expect(codes.slice(0, 4)).toEqual([200, 200, 200, 200]); // burst = 2× rps
    expect(codes.slice(4)).toEqual([429, 429]);
    // A different caller (bearer) has its own bucket.
    expect((await fetch(`${base}/open`, { headers: { authorization: "Bearer someone-else" } })).status).toBe(200);
    expect((await fetch(`${base}/ops/health`, { headers: { authorization: "Bearer other" } })).status).toBe(401);
    expect((await fetch(`${base}/ops/health`, { headers: { authorization: "Bearer s3cret" } })).status).toBe(200);
    server.close();
  });

  it("refuses /ops entirely when no token is configured", async () => {
    const server = await startServer(0, { rpcPath: "/rpc", rpc: async () => ({}), routes: { "GET /ops/health": async () => ({ status: 200, body: {} }) } });
    const port = (server.address() as { port: number }).port;
    expect((await fetch(`http://127.0.0.1:${port}/ops/health`, { headers: { authorization: "Bearer anything" } })).status).toBe(401);
    server.close();
  });
});

import { AuditLog, verifyAuditChain } from "../src/protocol/audit";
import { Metrics, Alerts } from "../src/venue/observe";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("observability", () => {
  it("the audit log is hash-chained: an edited or removed line breaks the chain", () => {
    const p = join(mkdtempSync(join(tmpdir(), "fv-audit-")), "audit.jsonl");
    const log = new AuditLog(p);
    log.write({ component: "venue.identity", event: "onboard", outcome: "ALLOWED", subject: "a" });
    log.write({ component: "venue.identity", event: "onboard", outcome: "REFUSED", reasonCode: "CREDENTIAL_UNKNOWN", subject: "b" });
    const reopened = new AuditLog(p); // the chain continues across restarts
    reopened.write({ component: "sim", event: "x", outcome: "INFO" });
    const entries = reopened.readAll();
    expect(verifyAuditChain(entries).ok).toBe(true);
    const edited = structuredClone(entries); edited[1]!.outcome = "ALLOWED";
    expect(verifyAuditChain(edited)).toMatchObject({ ok: false, firstBadSeq: 2 });
    expect(verifyAuditChain([entries[0]!, entries[2]!])).toMatchObject({ ok: false, firstBadSeq: 3 });
  });

  it("metrics count what the audit records, and alerts fire only for the events that need a human", async () => {
    const p = join(mkdtempSync(join(tmpdir(), "fv-audit-")), "audit.jsonl");
    const log = new AuditLog(p);
    const m = new Metrics();
    const received: unknown[] = [];
    const server = await startServer(0, { rpcPath: "/rpc", rpc: async () => ({}), routes: { "POST /hook": async (_r, b) => { received.push(b); return { status: 200, body: {} }; } } });
    const port = (server.address() as { port: number }).port;
    const a = new Alerts(`http://127.0.0.1:${port}/hook`, "venue-test");
    log.onWrite((e) => { m.observe(e); a.observe(e); });
    log.write({ component: "venue.identity", event: "registry-false-attestation", outcome: "INFO", reasonCode: "REGISTRY_FALSE_ATTESTATION", subject: "mirror-b" });
    log.write({ component: "venue.commitment", event: "commit", outcome: "ALLOWED" });
    log.write({ component: "venue.mandate", event: "envelope-check", outcome: "REFUSED", reasonCode: "MANDATE_RATE_ABOVE_CEILING" });
    await new Promise((r) => setTimeout(r, 150));
    const text = m.render();
    expect(text).toContain('venue_refusals_total{reasonCode="MANDATE_RATE_ABOVE_CEILING",component="venue.mandate"} 1');
    expect(text).toContain("venue_commitments_total 1");
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ venueId: "venue-test", alert: "registry-false-attestation", subject: "mirror-b" });
    server.close();
  });
});
