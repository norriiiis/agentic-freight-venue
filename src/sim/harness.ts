/**
 * Process harness. Every scenario gets a fresh workspace with SEPARATE
 * directories for the venue and each agent, and each component is a separate
 * OS process that receives ONLY its own directory. Nothing here hands one
 * agent a path, key, or URL belonging to the other.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { copyFileSync, mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { exportPrivateJwk, generateKeyPair, signJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import type { Credential, CredentialStatusEntry, RotationAuthorization, RotationClaims, RotationReason } from "../protocol/types";
import { buildAgentCard } from "../agentkit/runtime";
import { importKeyPair as importKp } from "../protocol/crypto";
import { signCert, signRevocation, type VenueKeyCert, type VenueKeyHistory, type VenueKeyRevocation } from "../protocol/venue-keys";
import { rpcCall } from "../protocol/rpc";
import type { AgentConfig } from "../agentkit/types";
import type { Mandate, MandateLimits } from "../mandate/types";
import { issueEnvelope, issueMandate } from "../mandate/sign";
import type { MandateEnvelope } from "../protocol/types";
import { httpGet, httpPost, waitForHealth } from "../protocol/rpc";
import type { AuditEntry } from "../protocol/audit";
import type { NegotiationTask, CommitmentRecord } from "../venue/state";
import type { LedgerEntry } from "../ledger/chain";
import type { Message, Task } from "../protocol/a2a";
import type { LoadSpec, NegotiationPayload } from "../protocol/freight";
import type { LocalTask } from "../agentkit/types";

const ROOT = resolve(import.meta.dirname, "../..");
const REGISTRY_FIXTURE = join(ROOT, "src/identity/fixtures/registry.json");

export async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => res(p));
    });
  });
}

function spawnTs(entry: string, env: Record<string, string>, label: string, quiet: boolean): ChildProcess {
  const child = spawn(process.execPath, ["--import", "tsx", join(ROOT, entry)], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], cwd: ROOT });
  child.stdout?.on("data", (d) => { if (!quiet) process.stdout.write(`    ${label}| ${String(d).trimEnd()}\n`); });
  child.stderr?.on("data", (d) => process.stderr.write(`    ${label}! ${String(d).trimEnd()}\n`));
  return child;
}

export interface AgentSpec {
  agentId: string;
  role: "broker" | "carrier";
  entity: { usdot: string; mc?: string; legalName: string };
  proofOfControlToken: string;
  principalName: string;
  limits: MandateLimits;
  privateContext: Record<string, unknown> & { canary: string };
  thinkMs?: number;
  rogue?: AgentConfig["rogue"];
  /** Override which envelope limits are disclosed to the venue. */
  envelopeDisclose?: Partial<MandateEnvelope["limits"]>;
  registerEnvelope?: boolean;
}

export class AgentHandle {
  constructor(readonly spec: AgentSpec, readonly dir: string, readonly url: string, readonly proc: ChildProcess, readonly principal: KeyPair, readonly mandate: Mandate) {}
  onboard() { return httpPost<{ ok: boolean; reasonCode?: string; evidence?: unknown; credential?: { credentialId: string } }>(`${this.url}/control/onboard`, {}); }
  tender(load: LoadSpec, to: { agentId: string }) { return httpPost<{ taskId?: string; task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown }; localRefusal?: boolean }>(`${this.url}/control/tender`, { load, to }); }
  send(data: NegotiationPayload, taskId?: string, contextId?: string) { return httpPost<{ task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown } }>(`${this.url}/control/send`, { data, taskId, contextId }); }
  reconcile() { return httpPost<{ resolved: string[] }>(`${this.url}/control/reconcile`, {}); }
  identity() { return httpGet<{ agentId: string; kid: string; credentialId?: string; supersedes?: string; expiresAt?: string; issuerKid?: string; venueRootKid?: string; venueKidsKnown: string[] }>(`${this.url}/control/identity`); }
  rotatePrepare() { return httpPost<{ credentialId: string; newKid: string; newPublicKey: OkpJwk }>(`${this.url}/control/rotate/prepare`, {}); }
  rotateSubmit(input: { authorization: RotationAuthorization | { kind: "CURRENT_KEY_ONLY" }; claims?: RotationClaims; reason: RotationReason; compromisedAt?: string }) {
    return httpPost<{ ok: true; credential: Credential; superseded: CredentialStatusEntry } | { ok: false; reasonCode: string; evidence: unknown }>(`${this.url}/control/rotate/submit`, input);
  }
  /** The PRINCIPAL's authorization for a rotation: signed with the key the harness generated for the human, which the agent never held. */
  authorizeRotation(claims: RotationClaims): RotationAuthorization {
    return { kind: "PRINCIPAL", jws: signJws(claims, this.principal, { typ: "rotation+jws" }, true) };
  }
  /** Convenience: agent-cooperative rotation, authorized by the principal. */
  async rotate(reason: RotationReason = "ROTATION") {
    const prep = await this.rotatePrepare();
    const claims: RotationClaims = { credentialId: prep.credentialId, newKid: prep.newKid, ts: new Date().toISOString(), reason };
    return this.rotateSubmit({ authorization: this.authorizeRotation(claims), claims, reason });
  }
  setRogue(rogue: AgentConfig["rogue"] | undefined) { return httpPost<{ ok: boolean }>(`${this.url}/control/rogue`, { rogue }); }
  sendRaw(message: Message) { return httpPost<{ task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown } }>(`${this.url}/control/send-raw`, { message }); }
  tasks() { return httpGet<LocalTask[]>(`${this.url}/control/tasks`); }
  audit() { return httpGet<AuditEntry[]>(`${this.url}/control/audit`); }
  commitments() { return httpGet<Record<string, unknown>[]>(`${this.url}/control/commitments`); }
  stateDigest() { return httpGet<{ agentId: string; dataDir: string; files: string[]; privateContextHash: string; knownAgentUrls: string[] }>(`${this.url}/control/state-digest`); }
  canary() { return httpGet<{ canary: string }>(`${this.url}/control/private-canary`); }
  /** Wait until this agent's own record of the task reaches a status (the venue's terminal state arrives asynchronously). */
  async waitStatus(taskId: string, statuses: LocalTask["status"][], timeoutMs = 8000): Promise<LocalTask | undefined> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const t = (await this.tasks()).find((x) => x.taskId === taskId);
      if (t && statuses.includes(t.status)) return t;
      await new Promise((r) => setTimeout(r, 40));
    }
    return undefined;
  }
}

export class VenueHandle {
  constructor(readonly dir: string, readonly url: string, public proc: ChildProcess) {}
  /** Arm a crash at a named point inside the next commit (SIM-ONLY). */
  fault(f: { crashAt?: string; holdOutbox?: boolean } | null) { return httpPost<{ ok: boolean }>(`${this.url}/admin/fault`, f ?? {}); }
  flushOutbox() { return httpPost<{ pending: number; deadLetter: number }>(`${this.url}/admin/flush-outbox`, {}); }
  deadLetter() { return httpGet<{ toAgentId: string; attempts: number; note?: string }[]>(`${this.url}/admin/dead-letter`); }
  journal() { return httpGet<unknown[]>(`${this.url}/admin/journal`); }
  outbox() { return httpGet<{ toAgentId: string; attempts: number; note?: string }[]>(`${this.url}/admin/outbox`); }
  exposure(counterparty: string, beneficiary: string) { return httpGet<{ counterpartyOutstandingUsd: number; pairOutstandingUsd: number; portfolioOutstandingUsd: number }>(`${this.url}/admin/exposure?counterparty=${counterparty}&beneficiary=${beneficiary}`); }
  /** Wait for the venue process to exit (e.g. after an armed crash). */
  async waitExit(timeoutMs = 10_000): Promise<number | null> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (this.proc.exitCode !== null) return this.proc.exitCode;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error("venue did not exit");
  }
  registryUpdate(usdot: string, patch: Record<string, unknown>) { return httpPost(`${this.url}/admin/registry/update`, { usdot, patch }); }
  revoke(agentId: string, reason: string, evidence?: Record<string, unknown>) { return httpPost<{ revocation: unknown }>(`${this.url}/admin/credential/revoke`, { agentId, reason, evidence }); }
  seedExposure(counterpartyUsdot: string, beneficiaryUsdot: string, amountUsd: number, day: string, note: string) { return httpPost<{ exposure: unknown }>(`${this.url}/admin/underwriting/seed-exposure`, { counterpartyUsdot, beneficiaryUsdot, amountUsd, day, note }); }
  seedHistory(usdot: string, history: Record<string, unknown>) { return httpPost(`${this.url}/admin/underwriting/seed-history`, { usdot, history }); }
  expireStaleTasks() { return httpPost<{ expired: { taskId: string; outcome: unknown }[] }>(`${this.url}/admin/expire-stale-tasks`, {}); }
  prePickupChecks() { return httpPost<{ voided: { commitmentId: string; voided: unknown }[] }>(`${this.url}/admin/pre-pickup-checks`, {}); }
  audit() { return httpGet<AuditEntry[]>(`${this.url}/admin/audit`); }
  ledger() { return httpGet<LedgerEntry[]>(`${this.url}/admin/ledger`); }
  tasks() { return httpGet<NegotiationTask[]>(`${this.url}/admin/tasks`); }
  commitments() { return httpGet<CommitmentRecord[]>(`${this.url}/admin/commitments`); }
  messages() { return httpGet<{ ts: string; direction: "IN" | "OUT"; note?: string; message: Message }[]>(`${this.url}/admin/messages`); }
  agents() { return httpGet<{ agentId: string; credentialId: string; url: string }[]>(`${this.url}/admin/agents`); }
  guarantees() { return httpGet<{ guaranteeId: string; commitmentId?: string; status: string; coveredAmountUsd: number }[]>(`${this.url}/admin/guarantees`); }
  publicKey() { return httpGet<Record<string, unknown>>(`${this.url}/admin/public-key`); }
  credentialStatus() { return httpGet<CredentialStatusEntry[]>(`${this.url}/admin/credential-status`); }
  venueKeys() { return httpGet<VenueKeyHistory>(`${this.url}/.well-known/venue-keys.json`); }
  /** The OPERATOR's root key. The venue process wrote it once and never reads it back; the harness is the operator's HSM. */
  operatorRoot(): KeyPair { return importKp(JSON.parse(readFileSync(join(this.dir, "venue-root.jwk.json"), "utf8"))); }
  /** Operator-driven venue key rotation: prepare (root-signed request) → certify the pending key with the root → commit. */
  async rotateVenueKey(reason: "ROTATION" | "COMPROMISE", compromisedAt?: string) {
    const root = this.operatorRoot();
    const authorization = signJws({ action: "key-rotation/prepare", ts: new Date().toISOString() }, root, { typ: "operator-request+jws" });
    const prep = await rpcCall<{ kid: string; publicKey: OkpJwk; seq: number }>(`${this.url}/a2a`, "venue/key-rotation/prepare", { authorization });
    if (prep.error) throw new Error(`prepare refused: ${JSON.stringify(prep.error.data)}`);
    const cert = signCert(root, prep.result!.publicKey, prep.result!.seq, reason);
    const activeKid = (await httpGet<{ kid: string }>(`${this.url}/health`)).kid;
    const revocation = reason === "COMPROMISE" ? signRevocation(root, activeKid, "COMPROMISE", compromisedAt) : undefined;
    return rpcCall<{ previousKid: string; kid: string; seq: number; credentialsReissued: string[]; commitmentsReattested: string[]; resealed?: { fromSeq: number; toSeq: number } }>(`${this.url}/a2a`, "venue/key-rotation/commit", { cert, revocation });
  }
  /** A commit whose certificate was NOT signed by the root (an impostor operator, or the venue process trying to certify itself). */
  async rotateVenueKeyUnauthorized() {
    const root = this.operatorRoot();
    const authorization = signJws({ action: "key-rotation/prepare", ts: new Date().toISOString() }, root, { typ: "operator-request+jws" });
    const prep = await rpcCall<{ kid: string; publicKey: OkpJwk; seq: number }>(`${this.url}/a2a`, "venue/key-rotation/prepare", { authorization });
    const impostor = generateKeyPair();
    const cert: VenueKeyCert = signCert(impostor, prep.result!.publicKey, prep.result!.seq, "ROTATION");
    return rpcCall(`${this.url}/a2a`, "venue/key-rotation/commit", { cert });
  }
  registry() { return JSON.parse(readFileSync(join(this.dir, "registry.json"), "utf8")) as Record<string, unknown>[]; }

  async waitTerminal(taskId: string, timeoutMs = 20_000): Promise<NegotiationTask> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const t = (await this.tasks()).find((x) => x.task.id === taskId);
      if (t && ["completed", "failed", "rejected", "canceled"].includes(t.task.status.state)) return t;
      await new Promise((r) => setTimeout(r, 40));
    }
    throw new Error(`task ${taskId} did not reach a terminal state in ${timeoutMs}ms`);
  }
  async waitRound(taskId: string, round: number, timeoutMs = 10_000): Promise<NegotiationTask> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const t = (await this.tasks()).find((x) => x.task.id === taskId);
      if (t && (t.round >= round || ["completed", "failed", "rejected", "canceled"].includes(t.task.status.state))) return t;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error(`task ${taskId} did not reach round ${round}`);
  }
}

export interface HarnessOptions {
  workspace: string;
  quiet?: boolean;
  venue?: { maxRounds?: number; replyTimeoutMs?: number; sweepMs?: number; outboxMaxAttempts?: number; underwriting?: Record<string, unknown> };
}

export class Harness {
  private procs: ChildProcess[] = [];
  private venueEnv?: Record<string, string>;
  venue!: VenueHandle;
  readonly agents = new Map<string, AgentHandle>();
  constructor(readonly opts: HarnessOptions) {
    rmSync(opts.workspace, { recursive: true, force: true });
    mkdirSync(opts.workspace, { recursive: true });
  }

  async startVenue(): Promise<VenueHandle> {
    const dir = join(this.opts.workspace, "venue");
    mkdirSync(dir, { recursive: true });
    copyFileSync(REGISTRY_FIXTURE, join(dir, "registry.json"));
    const port = await freePort();
    this.venueEnv = {
      VENUE_DATA_DIR: dir,
      VENUE_REGISTRY_PATH: join(dir, "registry.json"),
      VENUE_PORT: String(port),
      VENUE_ID: "venue-sim",
      VENUE_MAX_ROUNDS: String(this.opts.venue?.maxRounds ?? 8),
      VENUE_REPLY_TIMEOUT_MS: String(this.opts.venue?.replyTimeoutMs ?? 120_000),
      VENUE_SWEEP_MS: String(this.opts.venue?.sweepMs ?? 5_000),
      VENUE_OUTBOX_MAX_ATTEMPTS: String(this.opts.venue?.outboxMaxAttempts ?? 40),
      VENUE_UW_PARAMS: this.opts.venue?.underwriting ? JSON.stringify(this.opts.venue.underwriting) : "",
      SIM_MODE: "1",
    };
    const proc = spawnTs("src/venue/server.ts", this.venueEnv, "venue  ", !!this.opts.quiet);
    this.procs.push(proc);
    const url = `http://127.0.0.1:${port}`;
    await waitForHealth(`${url}/health`);
    this.venue = new VenueHandle(dir, url, proc);
    return this.venue;
  }

  /**
   * Principal-driven rotation WITHOUT the agent's cooperation (the running agent may be compromised):
   * the principal's key management generates the new key, gets the venue to rotate, then re-provisions
   * the agent process with the new key + credential. The old process never sees the new key.
   */
  async principalRotate(handle: AgentHandle, reason: RotationReason, compromisedAt?: string): Promise<{ ok: true; credential: Credential; superseded: CredentialStatusEntry; voidedCommitments: string[]; newKp: KeyPair } | { ok: false; reasonCode: string; evidence: unknown }> {
    const config = JSON.parse(readFileSync(join(handle.dir, "config.json"), "utf8")) as AgentConfig;
    const id = await handle.identity();
    const newKp = generateKeyPair();
    const claims: RotationClaims = { credentialId: id.credentialId!, newKid: newKp.kid, ts: new Date().toISOString(), reason, compromisedAt };
    const res = await rpcCall<{ credential: Credential; superseded: CredentialStatusEntry; voidedCommitments: string[] }>(`${this.venue.url}/a2a`, "venue/rotate", {
      credentialId: id.credentialId,
      newCard: buildAgentCard(config, newKp, handle.url),
      authorization: handle.authorizeRotation(claims),
      claims,
    });
    if (res.error) {
      const d = (res.error.data ?? {}) as { reasonCode?: string; evidence?: unknown };
      return { ok: false, reasonCode: d.reasonCode ?? String(res.error.code), evidence: d.evidence };
    }
    return { ok: true, ...res.result!, newKp };
  }

  /** Re-provision an agent: stop it, install the key + credential the principal obtained, start it on the same dir/port. */
  async reprovisionAgent(handle: AgentHandle, newKp: KeyPair, credential: Credential): Promise<AgentHandle> {
    if (handle.proc.exitCode === null) {
      handle.proc.kill("SIGKILL");
      await new Promise((r) => setTimeout(r, 50));
    }
    writeFileSync(join(handle.dir, "agent-key.jwk.json"), JSON.stringify(exportPrivateJwk(newKp)));
    writeFileSync(join(handle.dir, "credential.json"), JSON.stringify(credential, null, 2));
    const next = join(handle.dir, "agent-key.next.jwk.json");
    if (existsSync(next)) rmSync(next);
    const entry = handle.spec.role === "broker" ? "src/agents/broker/index.ts" : "src/agents/carrier/index.ts";
    const proc = spawnTs(entry, { AGENT_CONFIG: join(handle.dir, "config.json"), SIM_MODE: "1" }, handle.spec.agentId.padEnd(7).slice(0, 7), !!this.opts.quiet);
    this.procs.push(proc);
    await waitForHealth(`${handle.url}/health`, 15_000);
    const start = Date.now();
    while (Date.now() - start < 4000 && !existsSync(join(handle.dir, "venue-root.pinned.json"))) await new Promise((r) => setTimeout(r, 40));
    const h2 = new AgentHandle(handle.spec, handle.dir, handle.url, proc, handle.principal, handle.mandate);
    this.agents.set(handle.spec.agentId, h2);
    return h2;
  }

  /** Restart the venue on the SAME data dir and port — what an operator (or supervisor) does after a crash. Recovery runs before it serves. */
  async restartVenue(): Promise<VenueHandle> {
    if (this.venue.proc.exitCode === null) {
      this.venue.proc.kill("SIGKILL");
      await new Promise((r) => setTimeout(r, 50));
    }
    const proc = spawnTs("src/venue/server.ts", this.venueEnv!, "venue  ", !!this.opts.quiet);
    this.procs.push(proc);
    this.venue.proc = proc;
    await waitForHealth(`${this.venue.url}/health`, 15_000);
    return this.venue;
  }

  /**
   * Build an agent's environment. The principal's private key is generated
   * here (the "human"), used to sign the mandate/envelope, and then DROPPED —
   * only its public half goes into the agent's config.
   */
  async startAgent(spec: AgentSpec): Promise<AgentHandle> {
    const dir = join(this.opts.workspace, spec.agentId);
    mkdirSync(dir, { recursive: true });
    const principal = generateKeyPair();
    const mandate = issueMandate(principal, spec.principalName, spec.agentId, spec.limits);
    writeFileSync(join(dir, "mandate.json"), JSON.stringify(mandate, null, 2));
    if (spec.registerEnvelope !== false) writeFileSync(join(dir, "envelope.json"), JSON.stringify(issueEnvelope(principal, mandate, spec.envelopeDisclose), null, 2));
    writeFileSync(join(dir, "private.json"), JSON.stringify(spec.privateContext, null, 2));
    const port = await freePort();
    const config: AgentConfig = {
      agentId: spec.agentId,
      role: spec.role,
      dataDir: dir,
      port,
      venueUrl: this.venue.url,
      entity: spec.entity,
      proofOfControl: { method: "stub:fmcsa-registered-email-challenge", token: spec.proofOfControlToken },
      principal: { name: spec.principalName, publicKey: principal.publicJwk },
      thinkMs: spec.thinkMs ?? 120,
      rogue: spec.rogue,
    };
    writeFileSync(join(dir, "config.json"), JSON.stringify(config, null, 2));
    const entry = spec.role === "broker" ? "src/agents/broker/index.ts" : "src/agents/carrier/index.ts";
    const proc = spawnTs(entry, { AGENT_CONFIG: join(dir, "config.json"), SIM_MODE: "1" }, spec.agentId.padEnd(7).slice(0, 7), !!this.opts.quiet);
    this.procs.push(proc);
    const url = `http://127.0.0.1:${port}`;
    await waitForHealth(`${url}/health`);
    // give the process a moment to pin the venue + onboard
    if (!spec.rogue?.skipOnboarding) {
      const start = Date.now();
      while (Date.now() - start < 8000 && !existsSync(join(dir, "credential.json"))) {
        const a = await httpGet<AuditEntry[]>(`${url}/control/audit`);
        if (a.some((e) => e.event === "onboard" && e.outcome === "REFUSED")) break;
        await new Promise((r) => setTimeout(r, 40));
      }
    } else {
      const start = Date.now();
      while (Date.now() - start < 4000 && !existsSync(join(dir, "venue-root.pinned.json"))) await new Promise((r) => setTimeout(r, 40));
    }
    const h = new AgentHandle(spec, dir, url, proc, principal, mandate);
    this.agents.set(spec.agentId, h);
    return h;
  }

  async stop() {
    for (const p of this.procs) {
      try { p.kill("SIGTERM"); } catch { /* already gone */ }
    }
    await new Promise((r) => setTimeout(r, 60));
    for (const p of this.procs) {
      try { if (p.exitCode === null) p.kill("SIGKILL"); } catch { /* ignore */ }
    }
    this.procs = [];
  }
}
