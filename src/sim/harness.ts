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
import { rootCommitment, signCert, signRevocation, signRootEvent, type RootEvent, type VenueKeyCert, type VenueKeyHistory, type VenueKeyRevocation } from "../protocol/venue-keys";
import type { EquivocationProof, LedgerHead, WitnessReceipt, Witnessed } from "../protocol/witness";
import { signNotice, type BrokenPromiseProof, type InclusionPromise, type PendingNotice, type StatusNotice } from "../protocol/inclusion";
import type { CredentialStatusEntry as CSE } from "../protocol/types";
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
import { signInsurerAttestation, type InsurerAttestation, type InsurerKey, type RegistryAttestation, type RegistryKey, type RegistryRecord } from "../protocol/registry";
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
  /** The COI on file: the principal's insurer's signed word, written into the agent's dir as insurance.json. */
  insurerAttestation?: InsurerAttestation;
}

export class AgentHandle {
  constructor(readonly spec: AgentSpec, readonly dir: string, readonly url: string, readonly proc: ChildProcess, readonly principal: KeyPair, readonly mandate: Mandate) {}
  onboard() { return httpPost<{ ok: boolean; reasonCode?: string; evidence?: unknown; credential?: { credentialId: string } }>(`${this.url}/control/onboard`, {}); }
  tender(load: LoadSpec, to: { agentId: string }) { return httpPost<{ taskId?: string; task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown }; localRefusal?: boolean }>(`${this.url}/control/tender`, { load, to }); }
  send(data: NegotiationPayload, taskId?: string, contextId?: string) { return httpPost<{ task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown } }>(`${this.url}/control/send`, { data, taskId, contextId }); }
  reconcile() { return httpPost<{ resolved: string[] }>(`${this.url}/control/reconcile`, {}); }
  witnessNow() { return httpPost<{ poll: { receipt?: WitnessReceipt; skipped?: string; fork?: string; halted?: string }; gossip: { checked: string[]; proofs: EquivocationProof[]; unreachable: string[] } }>(`${this.url}/control/witness/now`, {}); }
  witnessStatus() { return httpGet<{ witnessId: string; lastCosigned: LedgerHead | null; receipts: number; forks: number; equivocations: number; halted: { at: string; reason: string } | null; peers: string[] }>(`${this.url}/control/witness/status`); }
  witnessReceipts() { return httpGet<WitnessReceipt[]>(`${this.url}/control/witness/receipts`); }
  witnessReceiptFor(seq: number) { return httpGet<WitnessReceipt | null>(`${this.url}/control/witness/receipt-for?seq=${seq}`); }
  witnessEquivocations() { return httpGet<EquivocationProof[]>(`${this.url}/control/witness/equivocations`); }
  async addWitnessPeers(peers: WitnessHandle[]) { return httpPost<{ peers: string[] }>(`${this.url}/control/witness/peers`, { peers: await Promise.all(peers.map(async (p) => ({ witnessId: p.witnessId, url: p.url, publicKey: (await p.status()).publicKey }))) }); }
  identity() { return httpGet<{ agentId: string; kid: string; credentialId?: string; supersedes?: string; expiresAt?: string; issuerKid?: string; venueRootKid?: string; venueRootsKnown: string[]; venueKidsKnown: string[] }>(`${this.url}/control/identity`); }
  refreshVenueKeys() { return httpPost<{ kids: string[]; root?: string; roots?: string[] }>(`${this.url}/control/refresh-venue-keys`, {}); }
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
  /** The principal obtained a renewed COI from its insurer and hands it to its agent. */
  presentInsurance(att: InsurerAttestation) { return httpPost<{ ok: boolean; reasonCode?: string; evidence?: unknown; satisfied?: string[]; voided?: string[] }>(`${this.url}/control/present-insurance`, att); }
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
  fault(f: { crashAt?: string; holdOutbox?: boolean; registryStale?: boolean; ignoreRegistry?: boolean; hideRegistries?: string[] } | null) { return httpPost<{ ok: boolean }>(`${this.url}/admin/fault`, f ?? {}); }
  /** What the venue holds of the registries' word. */
  registryMirror() { return httpGet<{ pinned: RegistryKey[]; quorum: number; stale: boolean; hidden: string[]; attestations: { registryId: string; usdot: string; asOf: string; recordHash: string; kid: string }[] }>(`${this.url}/admin/registry-mirror`); }
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
  revoke(agentId: string, reason: string, evidence?: Record<string, unknown>) { return httpPost<{ revocation: unknown }>(`${this.url}/admin/credential/revoke`, { agentId, reason, evidence }); }
  seedExposure(counterpartyUsdot: string, beneficiaryUsdot: string, amountUsd: number, day: string, note: string) { return httpPost<{ exposure: unknown }>(`${this.url}/admin/underwriting/seed-exposure`, { counterpartyUsdot, beneficiaryUsdot, amountUsd, day, note }); }
  seedHistory(usdot: string, history: Record<string, unknown>) { return httpPost(`${this.url}/admin/underwriting/seed-history`, { usdot, history }); }
  expireStaleTasks() { return httpPost<{ expired: { taskId: string; outcome: unknown }[] }>(`${this.url}/admin/expire-stale-tasks`, {}); }
  prePickupChecks(now?: Date) { return httpPost<{ voided: { commitmentId: string; voided: unknown }[] }>(`${this.url}/admin/pre-pickup-checks`, now ? { now: now.toISOString() } : {}); }
  audit() { return httpGet<AuditEntry[]>(`${this.url}/admin/audit`); }
  ledger() { return httpGet<LedgerEntry[]>(`${this.url}/admin/ledger`); }
  tasks() { return httpGet<NegotiationTask[]>(`${this.url}/admin/tasks`); }
  commitments() { return httpGet<CommitmentRecord[]>(`${this.url}/admin/commitments`); }
  messages() { return httpGet<{ ts: string; direction: "IN" | "OUT"; note?: string; message: Message }[]>(`${this.url}/admin/messages`); }
  agents() { return httpGet<{ agentId: string; credentialId: string; url: string }[]>(`${this.url}/admin/agents`); }
  guarantees() { return httpGet<{ guaranteeId: string; commitmentId?: string; status: string; coveredAmountUsd: number }[]>(`${this.url}/admin/guarantees`); }
  publicKey() { return httpGet<Record<string, unknown>>(`${this.url}/admin/public-key`); }
  credentialStatus() { return httpGet<CredentialStatusEntry[]>(`${this.url}/admin/credential-status`); }
  venueKeys() { return httpGet<VenueKeyHistory & Witnessed>(`${this.url}/.well-known/venue-keys.json`); }
  statusList() { return httpGet<Witnessed & { entries: CSE[] }>(`${this.url}/.well-known/credential-status.json`); }
  /** The status list as the venue shows it to a particular requester (SIM: the equivocation fault keys on this id). */
  async statusListAs(requester: string) { return (await (await fetch(`${this.url}/.well-known/credential-status.json`, { headers: { "x-witness-id": requester } })).json()) as Witnessed & { entries: CSE[] }; }
  async venueKeysAs(requester: string) { return (await (await fetch(`${this.url}/.well-known/venue-keys.json`, { headers: { "x-witness-id": requester } })).json()) as VenueKeyHistory & Witnessed; }
  registerNoticeSource(sourceId: string, publicKey: OkpJwk, insurerName?: string) { return httpPost<{ ok: boolean }>(`${this.url}/admin/notice-sources`, { sourceId, publicKey, insurerName }); }
  /** Submit a source-signed status notice; returns the venue's inclusion promise, or the failure the source saw. */
  async submitNotice(notice: StatusNotice): Promise<{ promise?: InclusionPromise; recorded?: boolean; failure?: string }> {
    try {
      const res = await rpcCall<{ promise: InclusionPromise; recorded: boolean }>(`${this.url}/a2a`, "venue/notice", { notice });
      if (res.error) return { failure: `${res.error.message}${(res.error.data as { reasonCode?: string } | undefined)?.reasonCode ? ` (${(res.error.data as { reasonCode: string }).reasonCode})` : ""}` };
      return res.result!;
    } catch (e) {
      return { failure: `transport: ${String(e).slice(0, 60)}` };
    }
  }
  /** Notice faults: acknowledge-then-suppress, or refuse to acknowledge at all. */
  noticeFault(f: { suppressNotices?: boolean; dropNotices?: boolean } | null) { return httpPost<{ ok: boolean }>(`${this.url}/admin/fault`, f ?? {}); }
  /** Equivocation fault: show these requesters a chain that shares history up to `fromSeq` and then omits every CREDENTIAL_STATUS entry. */
  equivocate(witnessIds: string | string[], fromSeq: number) { return httpPost<{ ok: boolean }>(`${this.url}/admin/fault`, { equivocate: { witnessIds: Array.isArray(witnessIds) ? witnessIds : [witnessIds], fromSeq } }); }
  ledgerHead() { return httpGet<LedgerHead & { venueId: string }>(`${this.url}/.well-known/ledger-head.json`); }
  registerWitness(w: { witnessId: string; publicKey: OkpJwk }) { return httpPost<{ ok: boolean }>(`${this.url}/admin/witnesses`, w); }
  /** Rollback fault: drop every ledger entry after `seq` (a compromised venue rewriting its history). */
  truncateLedger(seq: number) { return httpPost<{ head: LedgerHead; witnessed: LedgerHead | null }>(`${this.url}/admin/ledger/truncate`, { seq }); }
  /** The OPERATOR's current root key. The venue process wrote it once and never reads it back; the harness is the operator's HSM. */
  operatorRoot(): KeyPair { return importKp(JSON.parse(readFileSync(join(this.dir, "venue-root.jwk.json"), "utf8"))); }
  /** The PRE-COMMITTED next root, held even more offline. Only its hash is known to the venue process. */
  operatorNextRoot(): KeyPair { return importKp(JSON.parse(readFileSync(join(this.dir, "venue-root-next.jwk.json"), "utf8"))); }
  /**
   * Root rotation ceremony: reveal the pre-committed root, commit to a fresh next one, sign the event with the
   * new root (countersigned by the old one when it is still trusted), and re-certify the venue's genuine
   * operational key under the new root on a compromise. Then rotate the operator's own custody files.
   */
  async rotateRoot(reason: "ROTATION" | "COMPROMISE", compromisedAt?: string) {
    const old = this.operatorRoot();
    const next = this.operatorNextRoot();
    const afterNext = generateKeyPair();
    const cur = (await this.venueKeys()).rootLog.sort((a, b) => b.seq - a.seq)[0]!;
    const event = signRootEvent(next, { seq: cur.seq + 1, previousRootKid: cur.rootKid, nextRootCommitment: rootCommitment(afterNext.publicJwk), at: new Date().toISOString(), reason, compromisedAt }, reason === "ROTATION" ? old : undefined);
    let recert: VenueKeyCert | undefined;
    if (reason === "COMPROMISE") {
      const h = await this.venueKeys();
      const activeKid = (await httpGet<{ kid: string }>(`${this.url}/health`)).kid;
      const original = h.certs.filter((c) => c.kid === activeKid).sort((a, b) => a.seq - b.seq)[0]!;
      recert = signCert(next, original.publicKey, Math.max(...h.certs.map((c) => c.seq)) + 1, "RECERTIFICATION", new Date(), new Date(original.validFrom));
    }
    const res = await rpcCall<{ previousRootKid: string; rootKid: string; seq: number; recertified?: string }>(`${this.url}/a2a`, "venue/root-rotation/commit", { event, recert });
    if (!res.error) {
      writeFileSync(join(this.dir, "venue-root.jwk.json"), JSON.stringify(exportPrivateJwk(next)));
      writeFileSync(join(this.dir, "venue-root-next.jwk.json"), JSON.stringify(exportPrivateJwk(afterNext)));
    }
    return res;
  }
  /** A thief holding the CURRENT root tries to rotate to a key of their own, countersigned by the stolen root. */
  async rotateRootUnauthorized() {
    const stolen = this.operatorRoot();
    const thief = generateKeyPair();
    const cur = (await this.venueKeys()).rootLog.sort((a, b) => b.seq - a.seq)[0]!;
    const event: RootEvent = signRootEvent(thief, { seq: cur.seq + 1, previousRootKid: cur.rootKid, nextRootCommitment: rootCommitment(generateKeyPair().publicJwk), at: new Date().toISOString(), reason: "ROTATION" }, stolen);
    return rpcCall(`${this.url}/a2a`, "venue/root-rotation/commit", { event });
  }
  /** A thief holding the current root certifies an operational key of their own (off-venue). Returns the key and its certificate. */
  certifyThiefOperationalKey(): { kp: KeyPair; cert: VenueKeyCert } {
    const stolen = this.operatorRoot();
    const kp = generateKeyPair();
    return { kp, cert: signCert(stolen, kp.publicJwk, 99, "ROTATION") };
  }
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

/** The registry process: the mock FMCSA L&I authority, with its own key and clock. Neither the venue nor the harness can sign for it. */
export class RegistryHandle {
  constructor(readonly registryId: string, readonly dir: string, readonly url: string, readonly proc: ChildProcess) {}
  status() { return httpGet<{ registryId: string; kid: string; records: number; attestationsServed: number; unavailable: boolean; frozen: boolean; claimsCurrent: boolean }>(`${this.url}/health`); }
  async key(): Promise<RegistryKey> { return httpGet<RegistryKey>(`${this.url}/.well-known/registry.json`); }
  records() { return httpGet<RegistryRecord[]>(`${this.url}/records`); }
  record(usdot: string) { return this.records().then((rs) => rs.find((r) => r.usdot === usdot)!); }
  /** The registry's signed word, as any verifier can fetch it today. */
  attest(usdot: string) { return httpGet<RegistryAttestation>(`${this.url}/attest?usdot=${usdot}`); }
  /** SIM: an insurer files a cancellation / FMCSA revokes — with the REGISTRY. Nobody tells the venue. */
  update(usdot: string, patch: Partial<RegistryRecord>) { return httpPost<{ ok: boolean; recordHash: string }>(`${this.url}/admin/update`, { usdot, patch }); }
  /** SIM: the registry goes dark, or freezes — keeps signing the records it has. Honest: its sync claim stops advancing. `claimsCurrent`: it lies about its sync. */
  fault(f: { unavailable?: boolean; freeze?: boolean; claimsCurrent?: boolean }) { return httpPost<{ unavailable: boolean; frozen: boolean; claimsCurrent: boolean }>(`${this.url}/admin/fault`, f); }
}

export class WitnessHandle {
  constructor(readonly witnessId: string, readonly dir: string, readonly url: string, readonly proc: ChildProcess) {}
  status() { return httpGet<{ witnessId: string; publicKey: OkpJwk; lastCosigned: LedgerHead | null; receipts: number; forks: number; equivocations: number; halted: { at: string; reason: string } | null; peers: string[] }>(`${this.url}/health`); }
  poll() { return httpPost<{ receipt?: WitnessReceipt; skipped?: string; fork?: string; halted?: string }>(`${this.url}/poll`, {}); }
  gossip() { return httpPost<{ checked: string[]; proofs: EquivocationProof[]; unreachable: string[] }>(`${this.url}/gossip-now`, {}); }
  async addPeers(peers: WitnessHandle[]) { return httpPost<{ peers: string[] }>(`${this.url}/peers`, { peers: await Promise.all(peers.map(async (p) => ({ witnessId: p.witnessId, url: p.url, publicKey: (await p.status()).publicKey }))) }); }
  latest() { return httpGet<WitnessReceipt | null>(`${this.url}/latest`); }
  equivocations() { return httpGet<EquivocationProof[]>(`${this.url}/equivocations`); }
  watch(item: { promise: InclusionPromise } | { notice: StatusNotice; submissionOutcome: string }) { return httpPost<{ watching: number; pending: number }>(`${this.url}/watch`, item); }
  pending() { return httpGet<PendingNotice[]>(`${this.url}/pending`); }
  broken() { return httpGet<BrokenPromiseProof[]>(`${this.url}/broken`); }
  resolved() { return httpGet<{ noticeHash: string; seq: number; at: string }[]>(`${this.url}/resolved`); }
  /** SIM: make this witness collude — sign any head it is handed. */
  collude(on = true) { return httpPost<{ colluding: boolean }>(`${this.url}/fault`, { signAnything: on }); }
  signBlindly(venueId: string, head: LedgerHead) { return httpPost<{ receipt: WitnessReceipt | null }>(`${this.url}/sign`, { venueId, head }); }
  receipts() { return httpGet<WitnessReceipt[]>(`${this.url}/receipts`); }
  forks() { return httpGet<{ at: string; expected: LedgerHead; observed: LedgerHead; why: string }[]>(`${this.url}/forks`); }
  publicKeyPath() { return join(this.dir, "witness-public.jwk.json"); }
}

export interface HarnessOptions {
  workspace: string;
  quiet?: boolean;
  venue?: { maxRounds?: number; replyTimeoutMs?: number; sweepMs?: number; outboxMaxAttempts?: number; inclusionDelayMs?: number; registryMaxAgeMs?: number; registryQuorum?: number; underwriting?: Record<string, unknown> };
}

export class Harness {
  private procs: ChildProcess[] = [];
  private venueEnv?: Record<string, string>;
  venue!: VenueHandle;
  /** The first registry (most scenarios need one); `registries` has them all. */
  registry!: RegistryHandle;
  readonly registries: RegistryHandle[] = [];
  readonly agents = new Map<string, AgentHandle>();
  constructor(readonly opts: HarnessOptions) {
    rmSync(opts.workspace, { recursive: true, force: true });
    mkdirSync(opts.workspace, { recursive: true });
  }

  /**
   * A registry as its own process, started before the venue: the venue pins its key and holds only what it signs.
   * Several are independent mirrors of one upstream (the harness plays the upstream: see registryUpdate).
   */
  async startRegistry(registryId = "fmcsa-li-mock"): Promise<RegistryHandle> {
    const dir = join(this.opts.workspace, this.registries.length ? registryId : "registry");
    mkdirSync(dir, { recursive: true });
    copyFileSync(REGISTRY_FIXTURE, join(dir, "records.json"));
    const port = await freePort();
    const proc = spawnTs("src/registry/server.ts", { REGISTRY_ID: registryId, REGISTRY_DATA_DIR: dir, REGISTRY_STORE: join(dir, "records.json"), REGISTRY_PORT: String(port), SIM_MODE: "1" }, registryId.padEnd(8).slice(0, 8), !!this.opts.quiet);
    this.procs.push(proc);
    const url = `http://127.0.0.1:${port}`;
    await waitForHealth(`${url}/health`);
    const h = new RegistryHandle(registryId, dir, url, proc);
    this.registries.push(h);
    if (!this.registry) this.registry = h;
    return h;
  }
  async startRegistries(ids: string[]): Promise<RegistryHandle[]> {
    for (const id of ids) await this.startRegistry(id);
    return this.registries;
  }
  /** An insurer files with FMCSA; FMCSA revokes: the upstream changes and every mirror that is still syncing reflects it. */
  async registryUpdate(usdot: string, patch: Partial<RegistryRecord>) {
    for (const r of this.registries) await r.update(usdot, patch);
  }

  async startVenue(): Promise<VenueHandle> {
    if (this.registries.length === 0) await this.startRegistry();
    const dir = join(this.opts.workspace, "venue");
    mkdirSync(dir, { recursive: true });
    const port = await freePort();
    this.venueEnv = {
      VENUE_DATA_DIR: dir,
      // The operator pins every registry's key by configuration; the harness plays the operator.
      VENUE_REGISTRIES: JSON.stringify(await Promise.all(this.registries.map(async (r) => ({ registryId: r.registryId, url: r.url, publicKey: (await r.key()).publicKey })))),
      VENUE_REGISTRY_QUORUM: String(this.opts.venue?.registryQuorum ?? 1),
      VENUE_REGISTRY_MAX_AGE_MS: String(this.opts.venue?.registryMaxAgeMs ?? 1000),
      VENUE_PORT: String(port),
      VENUE_ID: "venue-sim",
      VENUE_MAX_ROUNDS: String(this.opts.venue?.maxRounds ?? 8),
      VENUE_REPLY_TIMEOUT_MS: String(this.opts.venue?.replyTimeoutMs ?? 120_000),
      VENUE_SWEEP_MS: String(this.opts.venue?.sweepMs ?? 5_000),
      VENUE_OUTBOX_MAX_ATTEMPTS: String(this.opts.venue?.outboxMaxAttempts ?? 40),
      VENUE_INCLUSION_DELAY_MS: String(this.opts.venue?.inclusionDelayMs ?? 60_000),
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

  /** A status-notice SOURCE (the registry feed, an insurer): its own key, registered with the venue by the operator. */
  async startNoticeSource(sourceId: string): Promise<{ sourceId: string; kp: KeyPair; sign: (fields: Parameters<typeof signNotice>[2]) => StatusNotice }> {
    const kp = generateKeyPair();
    await this.venue.registerNoticeSource(sourceId, kp.publicJwk);
    return { sourceId, kp, sign: (fields) => signNotice(kp, sourceId, fields) };
  }

  /**
   * An INSURER: the origin of the filing every registry mirrors. Registered with the venue like any source; signs
   * coverage attestations (a COI) that the insured presents. The harness plays the insurer's signing desk.
   */
  async startInsurer(insurerId: string, insurerName?: string): Promise<{ insurerId: string; insurerName?: string; kp: KeyPair; key: InsurerKey; attest: (fields: Parameters<typeof signInsurerAttestation>[2], now?: Date) => InsurerAttestation }> {
    const kp = generateKeyPair();
    await this.venue.registerNoticeSource(insurerId, kp.publicJwk, insurerName);
    return { insurerId, insurerName, kp, key: { insurerId, publicKey: kp.publicJwk, insurerName }, attest: (fields, now) => signInsurerAttestation(kp, insurerId, fields, now, insurerName) };
  }

  /**
   * Start an independent witness process and register its key with the venue (in production: operator
   * configuration). `peers` are other witnesses it gossips with — their ids, URLs and keys are distributed out
   * of band, exactly like CT monitor keys; neither the venue nor the peers can add themselves.
   */
  async startWitness(witnessId = "witness-1", pollMs = 400, peers: WitnessHandle[] = []): Promise<WitnessHandle> {
    const dir = join(this.opts.workspace, witnessId);
    mkdirSync(dir, { recursive: true });
    const port = await freePort();
    const peerSpecs = await Promise.all(peers.map(async (p) => ({ witnessId: p.witnessId, url: p.url, publicKey: (await p.status()).publicKey })));
    const proc = spawnTs("src/witness/server.ts", { WITNESS_ID: witnessId, WITNESS_DATA_DIR: dir, WITNESS_PORT: String(port), WITNESS_VENUE_URL: this.venue.url, WITNESS_POLL_MS: String(pollMs), WITNESS_PEERS: JSON.stringify(peerSpecs) }, witnessId.padEnd(7).slice(0, 7), !!this.opts.quiet);
    this.procs.push(proc);
    const url = `http://127.0.0.1:${port}`;
    await waitForHealth(`${url}/health`);
    const h = new WitnessHandle(witnessId, dir, url, proc);
    const st = await h.status();
    await this.venue.registerWitness({ witnessId, publicKey: st.publicKey });
    return h;
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
    if (spec.insurerAttestation) writeFileSync(join(dir, "insurance.json"), JSON.stringify(spec.insurerAttestation, null, 2));
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
