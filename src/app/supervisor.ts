/**
 * The agents this service runs on its clients' behalf: one OS process each,
 * with its own data directory, its own key, and its own mandate on disk.
 *
 * The supervisor's whole job is lifecycle — provision the directory, start
 * the process, watch it, restart it, stop it. It never reaches inside: an
 * agent is driven through its token-gated `/ops/*` surface like any other
 * client, so nothing here can make an agent exceed its mandate, and an agent
 * whose process this supervisor loses is still a complete, recoverable thing
 * on disk.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import { httpGet, httpPost, waitForHealth } from "../protocol/rpc";
import type { AgentConfig } from "../agentkit/types";
import type { AppDb, AgentRow, OrgRole } from "./db";

const ROOT = resolve(import.meta.dirname, "../..");

export async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.on("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => res(p));
    });
  });
}

export interface SupervisorOptions {
  dataRoot: string;
  venueUrl: string;
  /** Passed to each agent so it can reach a model; absent means the rule strategies alone. */
  llm?: { url: string; model?: string; key?: string; flavor?: string };
  log?: (line: string) => void;
}

export class Supervisor {
  private readonly procs = new Map<string, ChildProcess>();
  private timer?: NodeJS.Timeout;
  constructor(private readonly db: AppDb, private readonly o: SupervisorOptions) {}
  private log(s: string) { (this.o.log ?? console.log)(`[supervisor] ${s}`); }

  dirFor(agentId: string) { return join(this.o.dataRoot, "agents", agentId); }

  /** Write everything an agent needs to exist, without starting it. Idempotent. */
  provision(input: {
    agentId: string; role: OrgRole; port: number; controlToken: string;
    entity: { usdot: string; mc?: string; legalName: string };
    principalName: string; principalPublicKey: AgentConfig["principal"]["publicKey"];
    proofOfControl: { method: string; token: string };
    mandate: unknown; envelope: unknown; privateContext: Record<string, unknown>;
  }) {
    const dir = this.dirFor(input.agentId);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "mandate.json"), JSON.stringify(input.mandate, null, 2));
    writeFileSync(join(dir, "envelope.json"), JSON.stringify(input.envelope, null, 2));
    writeFileSync(join(dir, "private.json"), JSON.stringify(input.privateContext, null, 2));
    const config: AgentConfig = {
      agentId: input.agentId,
      role: input.role,
      dataDir: dir,
      port: input.port,
      venueUrl: this.o.venueUrl,
      entity: input.entity,
      proofOfControl: input.proofOfControl,
      principal: { name: input.principalName, publicKey: input.principalPublicKey },
      controlToken: input.controlToken,
      thinkMs: 0,
    };
    writeFileSync(join(dir, "config.json"), JSON.stringify(config, null, 2));
    return { dir, config };
  }

  async start(row: AgentRow): Promise<{ ok: boolean; error?: string }> {
    if (this.procs.has(row.agentId)) return { ok: true };
    const entry = row.role === "broker" ? "src/agents/broker/index.ts" : "src/agents/carrier/index.ts";
    const env: Record<string, string> = { ...process.env as Record<string, string>, AGENT_CONFIG: join(row.dataDir, "config.json") };
    delete env.SIM_MODE;
    if (this.o.llm?.url) {
      env.AGENT_LLM_URL = this.o.llm.url;
      if (this.o.llm.model) env.AGENT_LLM_MODEL = this.o.llm.model;
      if (this.o.llm.key) env.AGENT_LLM_KEY = this.o.llm.key;
      if (this.o.llm.flavor) env.AGENT_LLM_FLAVOR = this.o.llm.flavor;
    }
    const child = spawn(process.execPath, ["--import", "tsx", join(ROOT, entry)], { env, stdio: ["ignore", "pipe", "pipe"], cwd: ROOT });
    child.stdout?.on("data", (d) => this.log(`${row.agentId}| ${String(d).trimEnd()}`));
    child.stderr?.on("data", (d) => this.log(`${row.agentId}! ${String(d).trimEnd()}`));
    child.on("exit", (code) => {
      this.procs.delete(row.agentId);
      this.db.run("UPDATE agents SET status = ?, pid = NULL, last_error = ? WHERE id = ?", code === 0 ? "STOPPED" : "FAILED", code === 0 ? null : `exited with code ${code}`, row.id);
      this.db.audit({ orgId: row.orgId, event: "agent.exit", outcome: code === 0 ? "INFO" : "FAILED", detail: { agentId: row.agentId, code } });
    });
    this.procs.set(row.agentId, child);
    this.db.run("UPDATE agents SET status = ?, pid = ?, started_at = ?, last_error = NULL WHERE id = ?", "STARTING", child.pid ?? null, new Date().toISOString(), row.id);
    try {
      await waitForHealth(`http://127.0.0.1:${row.port}/health`, 20_000);
      this.db.run("UPDATE agents SET status = ?, last_health_at = ? WHERE id = ?", "LIVE", new Date().toISOString(), row.id);
      this.db.audit({ orgId: row.orgId, event: "agent.start", outcome: "ALLOWED", detail: { agentId: row.agentId, port: row.port, pid: child.pid } });
      return { ok: true };
    } catch (e) {
      const error = (e as Error).message;
      this.db.run("UPDATE agents SET status = ?, last_error = ? WHERE id = ?", "FAILED", error, row.id);
      this.db.audit({ orgId: row.orgId, event: "agent.start", outcome: "FAILED", detail: { agentId: row.agentId, error } });
      return { ok: false, error };
    }
  }

  stop(agentId: string) {
    const p = this.procs.get(agentId);
    if (p) { p.kill("SIGTERM"); this.procs.delete(agentId); }
  }

  /** Bring every agent the database says should be running back up, after a restart of this service. */
  async recover() {
    for (const row of this.db.allAgents()) {
      if (row.status === "STOPPED") continue;
      await this.start(row);
    }
  }

  /** Health poll: marks agents that stopped answering, and restarts ones whose process died. */
  watch(everyMs = 15_000) {
    this.timer = setInterval(() => void this.sweep(), everyMs);
    this.timer.unref();
  }
  async sweep() {
    for (const row of this.db.allAgents()) {
      if (row.status === "STOPPED") continue;
      try {
        await httpGet<{ ok: boolean }>(`http://127.0.0.1:${row.port}/health`);
        this.db.run("UPDATE agents SET status = 'LIVE', last_health_at = ? WHERE id = ?", new Date().toISOString(), row.id);
      } catch {
        if (!this.procs.has(row.agentId)) await this.start(row);
      }
    }
  }
  stopAll() { if (this.timer) clearInterval(this.timer); for (const id of [...this.procs.keys()]) this.stop(id); }

  // --------------------------------------------------------- driving one agent
  private auth(row: AgentRow): Record<string, string> { return { authorization: `Bearer ${row.controlToken}` }; }
  private base(row: AgentRow) { return `http://127.0.0.1:${row.port}`; }

  onboard(row: AgentRow) { return httpPost<{ ok: boolean; credential?: { credentialId: string }; reasonCode?: string; evidence?: unknown }>(`${this.base(row)}/ops/onboard`, {}, this.auth(row)); }
  identity(row: AgentRow) { return httpGet<Record<string, unknown>>(`${this.base(row)}/ops/identity`, this.auth(row)); }
  tasks(row: AgentRow) { return httpGet<Record<string, unknown>[]>(`${this.base(row)}/ops/tasks`, this.auth(row)); }
  audit(row: AgentRow) { return httpGet<Record<string, unknown>[]>(`${this.base(row)}/ops/audit`, this.auth(row)); }
  commitments(row: AgentRow) { return httpGet<Record<string, unknown>[]>(`${this.base(row)}/ops/commitments`, this.auth(row)); }
  tender(row: AgentRow, load: unknown, to: { agentId: string }) { return httpPost<Record<string, unknown>>(`${this.base(row)}/ops/tender`, { load, to }, this.auth(row)); }
  setContext(row: AgentRow, patch: Record<string, unknown>) { return httpPost<{ ok: boolean }>(`${this.base(row)}/ops/context`, patch, this.auth(row)); }
  reportEvent(row: AgentRow, p: unknown) { return httpPost<Record<string, unknown>>(`${this.base(row)}/ops/event`, p, this.auth(row)); }
  presentInsurance(row: AgentRow, att: unknown) { return httpPost<Record<string, unknown>>(`${this.base(row)}/ops/present-insurance`, att, this.auth(row)); }
}
