/**
 * Proves the two agent environments share no state.
 *
 *   static   — broker code cannot import carrier code (or venue/identity/underwriting/ledger), and vice versa
 *   runtime  — separate OS processes, separate data dirs, each configured with only its own dir + the venue URL;
 *              a per-agent secret canary never appears in the other agent's dir, the venue's dir, or on the wire;
 *              the wire carries only the negotiation vocabulary; a message sent directly from one agent to the
 *              other (bypassing the venue) is refused as ENVELOPE_NOT_FROM_VENUE.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { checkBoundaries } from "./boundaries";
import { Harness, type AgentHandle } from "../src/sim/harness";
import { LOAD, CARRIER_HISTORY, brokerSpec, carrierSpec } from "../src/sim/fixtures";
import { importKeyPair } from "../src/protocol/crypto";
import { buildMessage, signMessage } from "../src/protocol/envelope";
import { rpcCall } from "../src/protocol/rpc";

function grepDir(dir: string, needle: string): string[] {
  const hits: string[] = [];
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) hits.push(...grepDir(p, needle));
    else if (readFileSync(p, "utf8").includes(needle)) hits.push(p);
  }
  return hits;
}

describe("static: import boundaries", () => {
  it("agents import nothing from each other, the venue, identity, underwriting, or ledger", () => {
    const v = checkBoundaries();
    expect(v, v.map((x) => `${x.file} -> ${x.resolvedTo}`).join("\n")).toEqual([]);
  });
});

describe("runtime: separate processes, no shared state", () => {
  const workspace = resolve(import.meta.dirname, "../.sim/isolation-test");
  const h = new Harness({ workspace, quiet: true });
  let broker: AgentHandle;
  let carrier: AgentHandle;
  let taskId: string;

  beforeAll(async () => {
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    broker = await h.startAgent(brokerSpec({ thinkMs: 20 }));
    carrier = await h.startAgent(carrierSpec({ thinkMs: 20 }));
    const r = await broker.tender(LOAD, { agentId: carrier.spec.agentId });
    taskId = r.taskId!;
    await h.venue.waitTerminal(taskId);
    await Promise.all([broker.waitStatus(taskId, ["COMMITTED"]), carrier.waitStatus(taskId, ["COMMITTED"])]);
  }, 60_000);
  afterAll(async () => { await h.stop(); });

  it("negotiation reached a commitment (so there was real state to leak)", async () => {
    const t = (await h.venue.tasks()).find((x) => x.task.id === taskId)!;
    expect(t.status).toBe("COMMITTED");
  });

  it("three distinct OS processes, each given only its own data directory", () => {
    const pids = new Set([h.venue.proc.pid, broker.proc.pid, carrier.proc.pid]);
    expect(pids.size).toBe(3);
    expect(broker.dir).not.toBe(carrier.dir);
    expect(broker.dir.startsWith(carrier.dir)).toBe(false);
    expect(carrier.dir.startsWith(broker.dir)).toBe(false);
    const bc = readFileSync(join(broker.dir, "config.json"), "utf8");
    const cc = readFileSync(join(carrier.dir, "config.json"), "utf8");
    expect(bc).not.toContain(carrier.dir);
    expect(bc).not.toContain(carrier.url);
    expect(cc).not.toContain(broker.dir);
    expect(cc).not.toContain(broker.url);
  });

  it("each agent knows exactly one URL: the venue's", async () => {
    expect((await broker.stateDigest()).knownAgentUrls).toEqual([h.venue.url]);
    expect((await carrier.stateDigest()).knownAgentUrls).toEqual([h.venue.url]);
  });

  it("private canaries never cross: not in the other agent's dir, not in the venue's dir, not on the wire", async () => {
    const bCanary = (await broker.canary()).canary;
    const cCanary = (await carrier.canary()).canary;
    expect(bCanary).not.toBe(cCanary);
    // sanity: each canary IS in its own dir
    expect(grepDir(broker.dir, bCanary).length).toBeGreaterThan(0);
    expect(grepDir(carrier.dir, cCanary).length).toBeGreaterThan(0);
    // and nowhere else
    expect(grepDir(carrier.dir, bCanary)).toEqual([]);
    expect(grepDir(broker.dir, cCanary)).toEqual([]);
    expect(grepDir(h.venue.dir, bCanary)).toEqual([]);
    expect(grepDir(h.venue.dir, cCanary)).toEqual([]);
    const wire = JSON.stringify(await h.venue.messages());
    expect(wire).not.toContain(bCanary);
    expect(wire).not.toContain(cCanary);
  });

  it("the wire carries only the negotiation vocabulary — no private-context fields", async () => {
    const allowed: Record<string, string[]> = {
      TENDER: ["type", "load", "offer", "from", "to"],
      COUNTER: ["type", "loadRef", "round", "offer", "from", "note"],
      ACCEPT: ["type", "loadRef", "round", "terms", "termsHash", "from"],
      REJECT: ["type", "loadRef", "round", "reason", "from"],
    };
    const privateFields = ["customerRateUsd", "targetMarginPct", "minMarginPct", "costPerMileUsd", "deadheadMiles", "fixedCostPerLoadUsd", "concessionPct", "canary"];
    const log = await h.venue.messages();
    const inbound = log.filter((m) => m.direction === "IN");
    expect(inbound.length).toBeGreaterThan(3);
    for (const m of inbound) {
      const data = (m.message.parts[0] as { data: Record<string, unknown> }).data;
      const keys = Object.keys(data);
      expect(keys.every((k) => allowed[String(data.type)]!.includes(k)), `unexpected key in ${data.type}: ${keys}`).toBe(true);
      const s = JSON.stringify(m.message);
      for (const f of privateFields) expect(s).not.toContain(f);
    }
  });

  it("direct agent-to-agent contact is refused: ENVELOPE_NOT_FROM_VENUE", async () => {
    // The test is privileged: it reads the broker's key from disk to forge a broker-signed message.
    const brokerKey = importKeyPair(JSON.parse(readFileSync(join(broker.dir, "agent-key.jwk.json"), "utf8")));
    const cred = JSON.parse(readFileSync(join(broker.dir, "credential.json"), "utf8"));
    const m = signMessage(buildMessage({ role: "user", data: { type: "TENDER", load: LOAD, offer: { rateUsd: 1 } }, senderAgentId: broker.spec.agentId, credentialId: cred.credentialId }), brokerKey);
    const res = await rpcCall(`${carrier.url}/a2a`, "message/send", { message: m });
    expect(res.error?.message).toBe("ENVELOPE_NOT_FROM_VENUE");
    const audit = await carrier.audit();
    expect(audit.some((e) => e.reasonCode === "ENVELOPE_NOT_FROM_VENUE")).toBe(true);
  });

  it("the venue's data dir contains no agent private keys", () => {
    const brokerPriv = JSON.parse(readFileSync(join(broker.dir, "agent-key.jwk.json"), "utf8")).d as string;
    const carrierPriv = JSON.parse(readFileSync(join(carrier.dir, "agent-key.jwk.json"), "utf8")).d as string;
    expect(grepDir(h.venue.dir, brokerPriv)).toEqual([]);
    expect(grepDir(h.venue.dir, carrierPriv)).toEqual([]);
    expect(grepDir(carrier.dir, brokerPriv)).toEqual([]);
    expect(grepDir(broker.dir, carrierPriv)).toEqual([]);
  });
});
