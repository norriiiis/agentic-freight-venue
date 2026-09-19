/**
 * The venue. Routes messages between agents that never learn each other's
 * addresses, verifies credentials on EVERY exchange, enforces the negotiation
 * protocol, enforces registered mandate envelopes, decides on guarantees,
 * and records commitments to a tamper-evident ledger.
 *
 * What the venue sees: the negotiation TERMS (rate, lane, dates, equipment)
 * on every message. What it does not see: either agent's private context
 * (costs, margins, strategy). See DECISIONS.md Q5.
 */
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { A2A_PROTOCOL_VERSION, FREIGHT_EXTENSION_URI, RPC_ERR, TERMINAL_STATES, dataPart, signAgentCard, verifyAgentCard, type AgentCard, type Message, type Task } from "../protocol/a2a";
import { canonicalize, hashObject } from "../protocol/canonical";
import { exportPrivateJwk, generateKeyPair, importKeyPair, importPublicKey, verifyJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { buildMessage, venueSignMessage, type SignedMeta, type VenueAttachment } from "../protocol/envelope";
import { loadFingerprint, termsHash, type AcceptPayload, type CounterPayload, type NegotiationPayload, type RejectPayload, type TenderPayload, type Terms } from "../protocol/freight";
import { REASONS, type ReasonCode } from "../protocol/reasons";
import { AuditLog, type Component } from "../protocol/audit";
import { rpcCall, RpcRefusal } from "../protocol/rpc";
import type { Credential, MandateEnvelope } from "../protocol/types";
import { MockRegistry } from "../identity/registry";
import { StubVettingProvider } from "../identity/vetting";
import { CredentialIssuer } from "../identity/issuer";
import { liveCheck, verifyCredential, verifyPresentation, type LiveCheckResult } from "../identity/verifier";
import { envelopeToLimits, evaluateMandate } from "../mandate/engine";
import { verifyEnvelope } from "../mandate/sign";
import { ExposureBook } from "../mandate/exposure";
import { Ledger } from "../ledger/chain";
import { artifactHash, buildArtifact, type CommitmentArtifact } from "../ledger/artifact";
import { UnderwritingEngine } from "../underwriting/engine";
import { DEFAULT_PARAMS, type RiskInputs, type UnderwritingParams } from "../underwriting/types";
import { VenueState, type CommitmentRecord, type NegotiationTask, type Offer, type RegisteredAgent } from "./state";
import { guaranteeWouldHavePaid } from "./guarantee-outcome";

export interface VenueConfig {
  venueId: string;
  dataDir: string;
  registryPath: string;
  port: number;
  maxRounds: number;
  messageMaxAgeMs: number;
  /** How long the venue waits for the awaited party's reply before canceling the negotiation. */
  replyTimeoutMs: number;
  underwriting?: Partial<UnderwritingParams>;
}

export class Refusal extends Error {
  constructor(public readonly reasonCode: ReasonCode, public readonly refusedBy: Component, public readonly evidence: Record<string, unknown>) {
    super(`${reasonCode}: ${REASONS[reasonCode]}`);
  }
}

export class VenueService {
  readonly kp: KeyPair;
  readonly registry: MockRegistry;
  readonly issuer: CredentialIssuer;
  readonly ledger: Ledger;
  readonly underwriting: UnderwritingEngine;
  readonly audit: AuditLog;
  readonly state: VenueState;
  readonly url: string;
  private exposure = new Map<string, ExposureBook>();

  constructor(readonly config: VenueConfig) {
    mkdirSync(config.dataDir, { recursive: true });
    const keyPath = join(config.dataDir, "venue-key.jwk.json");
    if (existsSync(keyPath)) this.kp = importKeyPair(JSON.parse(readFileSync(keyPath, "utf8")));
    else {
      this.kp = generateKeyPair();
      writeFileSync(keyPath, JSON.stringify(exportPrivateJwk(this.kp)));
    }
    writeFileSync(join(config.dataDir, "venue-public.jwk.json"), JSON.stringify(this.kp.publicJwk, null, 2));
    this.url = `http://127.0.0.1:${config.port}`;
    this.registry = new MockRegistry(config.registryPath);
    this.issuer = new CredentialIssuer(config.venueId, this.kp, this.registry, new StubVettingProvider(this.registry), config.dataDir);
    this.ledger = new Ledger(join(config.dataDir, "ledger.jsonl"), this.kp);
    this.underwriting = new UnderwritingEngine(config.dataDir, { ...DEFAULT_PARAMS, ...config.underwriting });
    this.audit = new AuditLog(join(config.dataDir, "audit.jsonl"));
    this.state = new VenueState(config.dataDir);
  }

  // ---------------------------------------------------------------- identity

  agentCard(): AgentCard {
    return signAgentCard(
      {
        protocolVersion: A2A_PROTOCOL_VERSION,
        name: this.config.venueId,
        description: "Freight transaction venue: identity, mandate enforcement, negotiation routing, commitment recording, guarantee underwriting.",
        url: `${this.url}/a2a`,
        preferredTransport: "JSONRPC",
        version: "0.1.0",
        provider: { organization: "Freight Venue (prototype)" },
        capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: true, extensions: [{ uri: FREIGHT_EXTENSION_URI, description: "Freight tender/counter/accept negotiation", required: true }] },
        securitySchemes: { agentJws: { type: "http", scheme: "bearer", bearerFormat: "JWS", description: "Detached JWS by a credentialed agent key over {credentialId, ts, method, taskId}" } },
        security: [{ agentJws: [] }],
        defaultInputModes: ["application/json"],
        defaultOutputModes: ["application/json"],
        skills: [
          { id: "onboard", name: "Onboard agent", description: "Bind an agent key to a registry entity and issue a credential", tags: ["identity"] },
          { id: "negotiate", name: "Route negotiation", description: "Route tender/counter/accept between credentialed agents", tags: ["negotiation"] },
        ],
        metadata: { venueId: this.config.venueId, issuerKid: this.kp.kid },
      },
      this.kp,
    );
  }

  private exposureFor(agentId: string): ExposureBook {
    let b = this.exposure.get(agentId);
    if (!b) {
      b = new ExposureBook(join(this.config.dataDir, "exposure", `${agentId}.json`));
      this.exposure.set(agentId, b);
    }
    return b;
  }

  async onboard(params: { card: AgentCard; claimed: { usdot: string; mc?: string }; proofOfControl: { method: string; token: string }; agentUrl: string; envelope?: MandateEnvelope }) {
    const cardCheck = verifyAgentCard(params.card);
    if (!cardCheck.ok || !cardCheck.jwk) throw new Refusal("IDENTITY_SIGNATURE_INVALID", "venue.identity", { error: cardCheck.error, stage: "agent-card" });
    const agentId = String(params.card.metadata?.agentId ?? params.card.name);
    const res = await this.issuer.issue({ agentId, publicKey: cardCheck.jwk, claimed: params.claimed, proofOfControl: params.proofOfControl });
    if (!res.ok) {
      this.audit.write({ component: "venue.identity", event: "onboard", outcome: "REFUSED", reasonCode: res.reasonCode, subject: agentId, evidence: res.evidence });
      throw new Refusal(res.reasonCode, "venue.identity", res.evidence);
    }
    let envelope: MandateEnvelope | undefined;
    if (params.envelope) {
      const ev = verifyEnvelope(params.envelope);
      if (!ev.ok || params.envelope.agentId !== agentId) {
        this.audit.write({ component: "venue.mandate", event: "register-envelope", outcome: "REFUSED", reasonCode: "MANDATE_SIGNATURE_INVALID", subject: agentId, evidence: { error: ev.error } });
        throw new Refusal("MANDATE_SIGNATURE_INVALID", "venue.mandate", { error: ev.error ?? "agentId mismatch" });
      }
      envelope = params.envelope;
    }
    const reg: RegisteredAgent = { agentId, credentialId: res.credential.credentialId, url: params.agentUrl, card: params.card, envelope, registeredAt: new Date().toISOString() };
    this.state.agents.set(agentId, reg);
    this.state.persist();
    this.audit.write({ component: "venue.identity", event: "onboard", outcome: "ALLOWED", subject: agentId, evidence: { credentialId: res.credential.credentialId, entity: res.credential.subject.entity, envelopeRegistered: !!envelope, vettingFlags: res.credential.evidence.vettingFlags } });
    return { credential: res.credential, venueCard: this.agentCard(), issuerPublicKey: this.kp.publicJwk };
  }

  // ------------------------------------------------------------- RPC surface

  async handleRpc(method: string, params: unknown, headers: Record<string, string | string[] | undefined>): Promise<unknown> {
    try {
      switch (method) {
        case "venue/onboard":
          return await this.onboard(params as Parameters<VenueService["onboard"]>[0]);
        case "message/send": {
          const m = (params as { message: Message }).message;
          return await this.ingest(m);
        }
        case "tasks/get": {
          const { id } = params as { id: string };
          const caller = this.authenticateBearer(headers.authorization, "tasks/get", id);
          const t = this.state.tasks.get(id);
          if (!t) throw new RpcRefusal(RPC_ERR.TASK_NOT_FOUND, "task not found");
          if (caller.agentId !== t.brokerAgentId && caller.agentId !== t.carrierAgentId) throw new RpcRefusal(RPC_ERR.TASK_NOT_FOUND, "task not found");
          return t.task;
        }
        default:
          throw new RpcRefusal(RPC_ERR.METHOD_NOT_FOUND, `method not found: ${method}`);
      }
    } catch (e) {
      if (e instanceof Refusal) throw new RpcRefusal(RPC_ERR.VENUE_REFUSED, e.message, { reasonCode: e.reasonCode, refusedBy: e.refusedBy, evidence: e.evidence, guaranteeWouldHavePaid: guaranteeWouldHavePaid(e.reasonCode) });
      throw e;
    }
  }

  /** HTTP bearer = detached JWS by an agent key over {credentialId, ts, method, taskId}. Credential re-verified on every call. */
  private authenticateBearer(authorization: string | string[] | undefined, method: string, taskId?: string): RegisteredAgent {
    const raw = Array.isArray(authorization) ? authorization[0] : authorization;
    const token = raw?.replace(/^Bearer\s+/i, "");
    if (!token) throw new Refusal("IDENTITY_SIGNATURE_INVALID", "venue.identity", { error: "missing bearer" });
    const [h, p] = token.split(".");
    let claims: { credentialId: string; ts: string; method: string; taskId?: string };
    try {
      claims = JSON.parse(Buffer.from(p ?? "", "base64url").toString("utf8"));
    } catch {
      throw new Refusal("IDENTITY_SIGNATURE_INVALID", "venue.identity", { error: "malformed bearer" });
    }
    void h;
    const cred = this.issuer.get(claims.credentialId);
    const cv = verifyCredential(cred, { issuerPublicKey: this.kp.publicJwk, revocation: this.issuer.revocation(claims.credentialId) });
    if (!cv.ok || !cred) throw new Refusal(cv.reasonCode ?? "CREDENTIAL_UNKNOWN", "venue.identity", cv.evidence);
    const sig = verifyJws(token, importPublicKey(cred.subject.publicKey));
    if (!sig.ok || claims.method !== method || (taskId && claims.taskId !== taskId) || Math.abs(Date.now() - new Date(claims.ts).getTime()) > this.config.messageMaxAgeMs) {
      throw new Refusal("IDENTITY_SIGNATURE_INVALID", "venue.identity", { error: sig.error ?? "bearer claims mismatch" });
    }
    const reg = this.state.agentByCredential(cred.credentialId);
    if (!reg) throw new Refusal("CREDENTIAL_UNKNOWN", "venue.identity", { credentialId: cred.credentialId });
    return reg;
  }

  // ------------------------------------------------------------------ ingest

  /** Every inbound agent message passes through here. Identity is verified before anything else is looked at. */
  async ingest(m: Message): Promise<Task> {
    const meta = m.metadata as SignedMeta | undefined;
    const data = dataPart(m) as NegotiationPayload | undefined;
    if (!meta?.credentialId || !meta.senderAgentId || !meta.nonce || !meta.ts || !data?.type) {
      throw new Refusal("PROTOCOL_VIOLATION", "venue.protocol", { error: "message missing credentialId/senderAgentId/nonce/ts or data part" });
    }
    // 1. replay
    const seen = this.state.nonces.get(meta.nonce);
    if (seen) {
      const ev = { nonce: meta.nonce, originalMessageId: seen.messageId, originalTs: seen.ts, replayedMessageId: m.messageId, payloadType: data.type, taskId: m.taskId };
      this.audit.write({ component: "venue.protocol", event: "ingest", outcome: "REFUSED", reasonCode: "NONCE_REUSED", subject: meta.senderAgentId, taskId: m.taskId, evidence: ev });
      throw new Refusal("NONCE_REUSED", "venue.protocol", ev);
    }
    if (Math.abs(Date.now() - new Date(meta.ts).getTime()) > this.config.messageMaxAgeMs) {
      const ev = { ts: meta.ts, now: new Date().toISOString(), maxAgeMs: this.config.messageMaxAgeMs };
      this.audit.write({ component: "venue.protocol", event: "ingest", outcome: "REFUSED", reasonCode: "MESSAGE_STALE", subject: meta.senderAgentId, taskId: m.taskId, evidence: ev });
      throw new Refusal("MESSAGE_STALE", "venue.protocol", ev);
    }
    // 2. credential (issuer sig, expiry, revocation)
    const cred = this.issuer.get(meta.credentialId);
    const cv = verifyCredential(cred, { issuerPublicKey: this.kp.publicJwk, revocation: this.issuer.revocation(meta.credentialId) });
    if (!cv.ok || !cred) {
      this.audit.write({ component: "venue.identity", event: "ingest", outcome: "REFUSED", reasonCode: cv.reasonCode, subject: meta.senderAgentId, taskId: m.taskId, evidence: cv.evidence });
      throw new Refusal(cv.reasonCode ?? "CREDENTIAL_UNKNOWN", "venue.identity", cv.evidence);
    }
    // 3. presentation (this message signed by the credential-bound key; identifiers match)
    const claimed = "from" in data ? { agentId: data.from.agentId, usdot: data.from.usdot, mc: data.from.mc } : { agentId: meta.senderAgentId, usdot: cred.subject.entity.usdot };
    const pv = verifyPresentation(m, cred, claimed);
    if (!pv.ok) {
      this.audit.write({ component: "venue.identity", event: "ingest", outcome: "REFUSED", reasonCode: pv.reasonCode, subject: meta.senderAgentId, taskId: m.taskId, evidence: { ...pv.evidence, claimed, payloadType: data.type } });
      throw new Refusal(pv.reasonCode!, "venue.identity", { ...pv.evidence, claimed });
    }
    const sender = this.state.agentByCredential(cred.credentialId);
    if (!sender || sender.agentId !== meta.senderAgentId) {
      throw new Refusal("CREDENTIAL_UNKNOWN", "venue.identity", { credentialId: cred.credentialId, senderAgentId: meta.senderAgentId });
    }
    this.state.nonces.set(meta.nonce, { messageId: m.messageId, ts: meta.ts, senderAgentId: sender.agentId });
    this.state.logMessage("IN", m, data.type);
    this.audit.write({ component: "venue.identity", event: "ingest", outcome: "ALLOWED", subject: sender.agentId, taskId: m.taskId, evidence: { payloadType: data.type, credentialId: cred.credentialId, kid: pv.evidence.kid } });

    switch (data.type) {
      case "TENDER":
        return this.startNegotiation(m, data, sender, cred);
      case "COUNTER":
      case "ACCEPT":
      case "REJECT":
        return this.advance(m, data, sender, cred);
      default:
        throw new Refusal("PROTOCOL_VIOLATION", "venue.protocol", { error: `agents may not send ${data.type}` });
    }
  }

  // --------------------------------------------------------- state machine

  private async startNegotiation(m: Message, data: TenderPayload, sender: RegisteredAgent, senderCred: Credential): Promise<Task> {
    const now = new Date();
    const taskId = `task_${randomUUID()}`;
    const contextId = `ctx_${data.load.loadRef}`;
    const violations: { code: ReasonCode; evidence: Record<string, unknown> }[] = [];

    // (a) sender must be in good standing and hold brokerage authority to tender
    const senderLive = liveCheck(this.registry, senderCred, { now });
    if (!senderLive.ok) violations.push({ code: senderLive.reasonCode!, evidence: senderLive.evidence });
    else if (!senderLive.brokerAuthority) violations.push({ code: "NO_BROKERAGE_AUTHORITY", evidence: { usdot: senderCred.subject.entity.usdot, entityType: senderCred.subject.entity.entityType, authorities: this.registry.get(senderCred.subject.entity.usdot)?.authorities } });

    // (b) double-brokering: is the sender the committed performing carrier for this load?
    const fp = loadFingerprint(data.load);
    for (const c of this.state.commitments.values()) {
      if (c.status !== "ACTIVE" || c.carrierAgentId !== sender.agentId) continue;
      const byRef = c.loadRef === data.load.loadRef;
      const byFp = c.loadFingerprint === fp;
      if ((byRef || byFp) && !c.artifact.terms.load.subcontractPermitted) {
        violations.push({ code: "DOUBLE_BROKERING_ATTEMPT", evidence: { existingCommitmentId: c.commitmentId, committedAsCarrierFor: c.brokerAgentId, matchedBy: byRef ? "loadRef" : "loadFingerprint", loadFingerprint: fp, subcontractPermitted: false, attemptedCounterparty: data.to.agentId } });
      }
    }

    // (b2) first commitment wins: a load the sender already has an ACTIVE commitment for cannot be tendered again
    const already = this.activeCommitmentForLoad(sender.agentId, data.load.loadRef, fp);
    if (already) violations.push({ code: "LOAD_ALREADY_COMMITTED", evidence: { existingCommitmentId: already.commitmentId, matchedBy: already.loadRef === data.load.loadRef ? "loadRef" : "loadFingerprint", committedAt: already.artifact.createdAt } });

    // (c) counterparty must be a credentialed carrier in good standing NOW
    const cp = this.state.agents.get(data.to.agentId);
    let cpCred: Credential | undefined;
    let cpLive: LiveCheckResult | undefined;
    if (!cp) violations.push({ code: "COUNTERPARTY_UNVERIFIED", evidence: { requestedAgentId: data.to.agentId, registeredAgents: [...this.state.agents.keys()] } });
    else {
      cpCred = this.issuer.get(cp.credentialId);
      const cv = verifyCredential(cpCred, { issuerPublicKey: this.kp.publicJwk, revocation: this.issuer.revocation(cp.credentialId), now });
      if (!cv.ok || !cpCred) violations.push({ code: cv.reasonCode!, evidence: { counterparty: cp.agentId, ...cv.evidence } });
      else {
        const requiredBipd = sender.envelope?.limits.requiredCounterpartyInsuranceUsd;
        cpLive = liveCheck(this.registry, cpCred, { now, hazmat: data.load.hazmat, requiredBipdUsd: requiredBipd });
        if (!cpLive.ok) violations.push({ code: cpLive.reasonCode!, evidence: { counterparty: cp.agentId, ...cpLive.evidence } });
        if (cpCred.subject.entity.entityType === "BROKER") violations.push({ code: "PROTOCOL_VIOLATION", evidence: { error: "counterparty is not a carrier", entityType: cpCred.subject.entity.entityType } });
      }
    }

    // (d) the sender's registered mandate envelope must permit this offer
    if (sender.envelope) {
      const v = evaluateMandate(envelopeToLimits(sender.envelope), { kind: "OFFER", isTender: true, rateUsd: data.offer.rateUsd, miles: data.load.miles, originState: data.load.origin.state, destinationState: data.load.destination.state, equipment: data.load.equipment, hazmat: data.load.hazmat, paymentTermsDays: data.offer.paymentTermsDays, round: 1 });
      for (const x of v.violations) violations.push({ code: x.code, evidence: { ...x.evidence, envelopePrincipalKid: sender.envelope.principalKid, agentId: sender.agentId } });
    }

    if (violations.length) {
      // most specific first
      const order: ReasonCode[] = ["DOUBLE_BROKERING_ATTEMPT", "LOAD_ALREADY_COMMITTED", "NO_BROKERAGE_AUTHORITY", "INSURANCE_LAPSED", "INSURANCE_BELOW_MINIMUM", "AUTHORITY_NOT_ACTIVE", "CREDENTIAL_REVOKED", "CREDENTIAL_EXPIRED", "COUNTERPARTY_UNVERIFIED", "MANDATE_RATE_ABOVE_CEILING", "MANDATE_RATE_BELOW_FLOOR", "MANDATE_LANE_NOT_APPROVED", "MANDATE_EQUIPMENT_NOT_APPROVED"];
      const primary = [...violations].sort((a, b) => (order.indexOf(a.code) === -1 ? 99 : order.indexOf(a.code)) - (order.indexOf(b.code) === -1 ? 99 : order.indexOf(b.code)))[0]!;
      const refusedBy: Component = primary.code.startsWith("MANDATE_") ? "venue.mandate" : ["DOUBLE_BROKERING_ATTEMPT", "COUNTERPARTY_UNVERIFIED", "NO_BROKERAGE_AUTHORITY", "LOAD_ALREADY_COMMITTED"].includes(primary.code) ? "venue.routing" : "venue.identity";
      const evidence = { ...primary.evidence, allViolations: violations.map((v) => v.code), details: violations };
      const task = this.newTask(taskId, contextId, data, sender.agentId, data.to.agentId, m);
      task.status = "REJECTED";
      task.outcome = { reasonCode: primary.code, refusedBy, evidence, guaranteeWouldHavePaid: guaranteeWouldHavePaid(primary.code) };
      task.task.status = { state: "rejected", timestamp: new Date().toISOString(), message: this.venueMessage({ type: "REFUSED", loadRef: data.load.loadRef, reasonCode: primary.code, refusedBy, evidence }, taskId, contextId) };
      this.state.tasks.set(taskId, task);
      this.state.persist();
      this.audit.write({ component: refusedBy, event: "tender-intake", outcome: "REFUSED", reasonCode: primary.code, subject: sender.agentId, taskId, contextId, evidence });
      return task.task;
    }

    const task = this.newTask(taskId, contextId, data, sender.agentId, data.to.agentId, m);
    task.task.status.state = "working";
    task.onTable = { offer: data.offer, by: sender.agentId, round: 1 };
    task.awaiting = data.to.agentId;
    this.state.tasks.set(taskId, task);
    this.state.persist();
    this.audit.write({ component: "venue.routing", event: "tender-intake", outcome: "ALLOWED", subject: sender.agentId, taskId, contextId, evidence: { loadRef: data.load.loadRef, to: data.to.agentId, rateUsd: data.offer.rateUsd, counterpartyInsurance: cpLive?.insurance?.bipdCoverageUsd } });
    await this.forward(m, task, cp!, sender, senderCred, senderLive, 1);
    return task.task;
  }

  private newTask(taskId: string, contextId: string, data: TenderPayload, brokerAgentId: string, carrierAgentId: string, m: Message): NegotiationTask {
    const t: Task = { kind: "task", id: taskId, contextId, status: { state: "submitted", timestamp: new Date().toISOString() }, history: [m], artifacts: [], metadata: { loadRef: data.load.loadRef, extension: FREIGHT_EXTENSION_URI } };
    const now = new Date().toISOString();
    return { task: t, loadRef: data.load.loadRef, load: data.load, brokerAgentId, carrierAgentId, round: 1, createdAt: now, awaiting: carrierAgentId, awaitingSince: now, acceptances: {}, status: "NEGOTIATING" };
  }

  private async advance(m: Message, data: CounterPayload | AcceptPayload | RejectPayload, sender: RegisteredAgent, senderCred: Credential): Promise<Task> {
    const t = m.taskId ? this.state.tasks.get(m.taskId) : undefined;
    if (!t) throw new Refusal("PROTOCOL_VIOLATION", "venue.protocol", { error: "unknown task", taskId: m.taskId });
    const isParty = sender.agentId === t.brokerAgentId || sender.agentId === t.carrierAgentId;
    if (!isParty || TERMINAL_STATES.includes(t.task.status.state) || t.awaiting !== sender.agentId) {
      const ev = { taskId: t.task.id, state: t.task.status.state, awaiting: t.awaiting, sender: sender.agentId, payloadType: data.type };
      this.audit.write({ component: "venue.protocol", event: "advance", outcome: "REFUSED", reasonCode: "PROTOCOL_VIOLATION", subject: sender.agentId, taskId: t.task.id, evidence: ev });
      throw new Refusal("PROTOCOL_VIOLATION", "venue.protocol", ev);
    }
    t.task.history!.push(m);
    const otherId = sender.agentId === t.brokerAgentId ? t.carrierAgentId : t.brokerAgentId;
    const other = this.state.agents.get(otherId)!;
    const senderLive = liveCheck(this.registry, senderCred, { hazmat: t.load.hazmat });

    if (data.type === "REJECT") {
      await this.fail(t, "NEGOTIATION_WALKAWAY", "venue.protocol", { by: sender.agentId, round: data.round, reason: data.reason }, m, other);
      return t.task;
    }

    if (data.type === "COUNTER") {
      const round = t.round + 1;
      if (round > this.config.maxRounds) {
        await this.fail(t, "NEGOTIATION_MAX_ROUNDS", "venue.protocol", { round, maxRounds: this.config.maxRounds, lastOffers: { onTable: t.onTable, attempted: data.offer } }, m, other);
        return t.task;
      }
      if (sender.envelope) {
        const v = evaluateMandate(envelopeToLimits(sender.envelope), { kind: "OFFER", rateUsd: data.offer.rateUsd, miles: t.load.miles, originState: t.load.origin.state, destinationState: t.load.destination.state, equipment: t.load.equipment, hazmat: t.load.hazmat, paymentTermsDays: data.offer.paymentTermsDays, round });
        if (!v.allowed) {
          await this.fail(t, v.violations[0]!.code, "venue.mandate", { agentId: sender.agentId, envelopePrincipalKid: sender.envelope.principalKid, violations: v.violations, checked: v.checked, round }, m, other);
          return t.task;
        }
      }
      t.round = round;
      t.onTable = { offer: data.offer, by: sender.agentId, round };
      t.awaiting = otherId;
      t.awaitingSince = new Date().toISOString();
      t.status = "NEGOTIATING";
      this.state.persist();
      this.audit.write({ component: "venue.routing", event: "counter", outcome: "ALLOWED", subject: sender.agentId, taskId: t.task.id, evidence: { round, rateUsd: data.offer.rateUsd } });
      await this.forward(m, t, other, sender, senderCred, senderLive, round);
      return t.task;
    }

    // ACCEPT — first commitment wins: if the broker's load was committed elsewhere while this ran, cancel.
    const won = this.activeCommitmentForLoad(t.brokerAgentId, t.loadRef, loadFingerprint(t.load));
    if (won) {
      await this.fail(t, "LOAD_ALREADY_COMMITTED", "venue.commitment", { agentId: t.brokerAgentId, winningCommitmentId: won.commitmentId, canceledTaskId: t.task.id, atRound: data.round, acceptedBy: sender.agentId }, m, other, t.brokerAgentId, "CANCELED");
      return t.task;
    }
    const check = this.checkAcceptTerms(t, data, sender, senderCred);
    if (check) {
      await this.fail(t, "TERMS_HASH_MISMATCH", "venue.protocol", check, m, other);
      return t.task;
    }
    // Venue-side mandate envelope for the accepting party
    const otherCred = this.issuer.get(other.credentialId)!;
    const otherLive = liveCheck(this.registry, otherCred, { hazmat: t.load.hazmat });
    const env = sender.envelope;
    if (!env) {
      await this.fail(t, "MANDATE_ENVELOPE_MISSING", "venue.mandate", { agentId: sender.agentId }, m, other);
      return t.task;
    }
    const quote = this.quoteFor(t, data.terms);
    const guaranteeAvailable = quote.decision === "GUARANTEED";
    // If the venue will not stand behind this deal and either principal requires that it does, stop here —
    // there is no point asking the other side to countersign.
    const anyoneRequiresGuarantee = !!env.limits.requireGuarantee || !!other.envelope?.limits.requireGuarantee;
    if (quote.decision === "DECLINED" && anyoneRequiresGuarantee) {
      const requiredBy = [env.limits.requireGuarantee ? sender.agentId : undefined, other.envelope?.limits.requireGuarantee ? other.agentId : undefined].filter(Boolean);
      await this.fail(t, quote.reasonCode, "underwriting", { ...quote.evidence, mandateRequiresGuarantee: true, requiredBy, assessment: quote.assessment, exposure: quote.exposureAfter, atRound: data.round, acceptedBy: sender.agentId }, m, other);
      return t.task;
    }
    const cpInsurance = sender.agentId === t.brokerAgentId ? otherLive.insurance?.bipdCoverageUsd ?? 0 : otherLive.insurance?.bondUsd ?? 0;
    const verdict = evaluateMandate(
      envelopeToLimits(env),
      { kind: "ACCEPT", rateUsd: data.terms.rateUsd, miles: t.load.miles, originState: t.load.origin.state, destinationState: t.load.destination.state, equipment: t.load.equipment, hazmat: t.load.hazmat, paymentTermsDays: data.terms.paymentTermsDays, round: data.round, counterpartyUsdot: otherCred.subject.entity.usdot, counterpartyInsuranceUsd: cpInsurance, guaranteeAvailable, day: data.terms.pickup.windowStart.slice(0, 10) },
      this.exposureFor(sender.agentId),
    );
    if (!verdict.allowed) {
      const primary = verdict.violations[0]!;
      const ev = { agentId: sender.agentId, envelopePrincipalKid: env.principalKid, violations: verdict.violations, checked: verdict.checked, underwriting: quote.decision === "DECLINED" ? { reasonCode: quote.reasonCode, ...quote.evidence } : undefined };
      // If the only violation is "guarantee required" and underwriting declined, the underwriting reason is the informative one.
      const onlyGuarantee = verdict.violations.every((v) => v.code === "MANDATE_GUARANTEE_REQUIRED");
      if (onlyGuarantee && quote.decision === "DECLINED") await this.fail(t, quote.reasonCode, "underwriting", { ...quote.evidence, mandateRequiresGuarantee: true, agentId: sender.agentId, assessment: quote.assessment }, m, other);
      else await this.fail(t, primary.code, "venue.mandate", ev, m, other);
      return t.task;
    }
    this.audit.write({ component: "venue.mandate", event: "envelope-check", outcome: "ALLOWED", subject: sender.agentId, taskId: t.task.id, evidence: { checked: verdict.checked, rateUsd: data.terms.rateUsd, guaranteeAvailable } });
    t.acceptances[sender.agentId] = m;

    if (!t.acceptances[otherId]) {
      t.status = "COUNTERSIGN";
      t.awaiting = otherId;
      t.awaitingSince = new Date().toISOString();
      this.state.persist();
      await this.forward(m, t, other, sender, senderCred, senderLive, data.round, guaranteeAvailable);
      return t.task;
    }
    await this.commit(t, data.terms);
    return t.task;
  }

  private checkAcceptTerms(t: NegotiationTask, data: AcceptPayload, sender: RegisteredAgent, senderCred: Credential): Record<string, unknown> | undefined {
    if (termsHash(data.terms) !== data.termsHash) return { error: "termsHash != hash(terms)", claimed: data.termsHash, computed: termsHash(data.terms) };
    const ot = t.onTable;
    if (!ot) return { error: "no offer on the table" };
    const expected: Terms = {
      loadRef: t.loadRef,
      load: t.load,
      rateUsd: ot.offer.rateUsd,
      pickup: ot.offer.pickup,
      delivery: ot.offer.delivery,
      paymentTermsDays: ot.offer.paymentTermsDays,
      brokerAgentId: t.brokerAgentId,
      carrierAgentId: t.carrierAgentId,
      brokerEntity: this.entityOf(t.brokerAgentId),
      carrierEntity: this.entityOf(t.carrierAgentId),
    };
    if (canonicalize(expected) !== canonicalize(data.terms)) {
      return { error: "accepted terms differ from the offer on the table", onTable: expected, accepted: data.terms, acceptedBy: sender.agentId, senderEntity: senderCred.subject.entity.usdot };
    }
    const otherId = sender.agentId === t.brokerAgentId ? t.carrierAgentId : t.brokerAgentId;
    const prior = t.acceptances[otherId];
    if (prior) {
      const pd = dataPart(prior) as unknown as AcceptPayload;
      if (pd.termsHash !== data.termsHash) return { error: "countersigned termsHash differs from first acceptance", first: pd.termsHash, second: data.termsHash };
    }
    return undefined;
  }

  private entityOf(agentId: string): { usdot: string; mc?: string } {
    const reg = this.state.agents.get(agentId)!;
    const c = this.issuer.get(reg.credentialId)!;
    return { usdot: c.subject.entity.usdot, mc: c.subject.entity.mc };
  }

  private riskInputs(t: NegotiationTask, terms: Terms): RiskInputs {
    const carrierReg = this.state.agents.get(t.carrierAgentId)!;
    const cred = this.issuer.get(carrierReg.credentialId)!;
    const rec = this.registry.get(cred.subject.entity.usdot)!;
    const brokerReg = this.state.agents.get(t.brokerAgentId)!;
    const now = Date.now();
    const oldest = rec.authorities.filter((a) => a.status === "ACTIVE").map((a) => new Date(a.grantDate).getTime()).sort()[0] ?? now;
    const live = liveCheck(this.registry, cred, { hazmat: t.load.hazmat });
    return {
      usdot: rec.usdot,
      authorityAgeDays: Math.floor((now - oldest) / 86_400_000),
      safetyRating: rec.safetyRating,
      powerUnits: rec.powerUnits,
      bipdUsd: live.insurance?.bipdCoverageUsd ?? 0,
      requiredBipdUsd: brokerReg.envelope?.limits.requiredCounterpartyInsuranceUsd ?? 750_000,
      vettingFlags: cred.evidence.vettingFlags,
      credentialAgeDays: Math.floor((now - new Date(cred.issuedAt).getTime()) / 86_400_000),
      registrySnapshotChangedSinceIssuance: cred.evidence.registrySnapshotHash !== this.registry.snapshotHash(rec.usdot),
      history: this.underwriting.historyFor(rec.usdot),
      amountUsd: terms.rateUsd,
    };
  }

  private quoteFor(t: NegotiationTask, terms: Terms) {
    const brokerUsdot = this.entityOf(t.brokerAgentId).usdot;
    return this.underwriting.quote(this.riskInputs(t, terms), brokerUsdot, terms.pickup.windowStart.slice(0, 10));
  }

  private async commit(t: NegotiationTask, terms: Terms) {
    const brokerReg = this.state.agents.get(t.brokerAgentId)!;
    const carrierReg = this.state.agents.get(t.carrierAgentId)!;
    const brokerCred = this.issuer.get(brokerReg.credentialId)!;
    const carrierCred = this.issuer.get(carrierReg.credentialId)!;

    // Final identity re-verification of both parties at the moment of commitment.
    for (const [reg, cred] of [[brokerReg, brokerCred], [carrierReg, carrierCred]] as const) {
      const cv = verifyCredential(cred, { issuerPublicKey: this.kp.publicJwk, revocation: this.issuer.revocation(cred.credentialId) });
      const lv = cv.ok ? liveCheck(this.registry, cred, { hazmat: t.load.hazmat, requiredBipdUsd: reg.agentId === t.carrierAgentId ? brokerReg.envelope?.limits.requiredCounterpartyInsuranceUsd : undefined }) : undefined;
      const bad = !cv.ok ? cv : lv && !lv.ok ? lv : undefined;
      if (bad) {
        await this.fail(t, bad.reasonCode!, "venue.identity", { stage: "commit", agentId: reg.agentId, ...bad.evidence }, undefined, undefined);
        return;
      }
    }

    const quote = this.quoteFor(t, terms);
    const requireGuarantee = !!brokerReg.envelope?.limits.requireGuarantee || !!carrierReg.envelope?.limits.requireGuarantee;
    if (quote.decision === "DECLINED" && requireGuarantee) {
      await this.fail(t, quote.reasonCode, "underwriting", { ...quote.evidence, mandateRequiresGuarantee: true, assessment: quote.assessment, exposure: quote.exposureAfter }, undefined, undefined);
      return;
    }

    const commitmentId = `cmt_${randomUUID()}`;
    const head = this.ledger.head;
    const artifact: CommitmentArtifact = buildArtifact(
      {
        venue: { venueId: this.config.venueId, publicKey: this.kp.publicJwk },
        terms,
        termsHash: termsHash(terms),
        acceptances: { broker: t.acceptances[t.brokerAgentId]!, carrier: t.acceptances[t.carrierAgentId]! },
        credentials: { broker: brokerCred, carrier: carrierCred },
        underwriting: quote.decision === "GUARANTEED" ? { decision: "GUARANTEED", riskScore: quote.assessment.probabilityOfLoss, guarantee: quote.guarantee } : { decision: "UNGUARANTEED", riskScore: quote.assessment.probabilityOfLoss, reasonCode: quote.reasonCode },
        ledger: { seq: head.seq + 1, prevHash: head.hash },
      },
      this.kp,
      commitmentId,
    );
    const entry = this.ledger.append("COMMITMENT", { commitmentId, termsHash: artifact.termsHash, artifactHash: artifactHash(artifact), loadRef: terms.loadRef, brokerUsdot: terms.brokerEntity.usdot, carrierUsdot: terms.carrierEntity.usdot, rateUsd: terms.rateUsd, guaranteed: quote.decision === "GUARANTEED" });
    artifact.ledgerEntryHash = entry.hash;

    let guaranteeId: string | undefined;
    if (quote.decision === "GUARANTEED") {
      const g = this.underwriting.attach(quote.guarantee.guaranteeId, commitmentId);
      guaranteeId = g.guaranteeId;
      this.ledger.append("GUARANTEE_ATTACHED", { commitmentId, guaranteeId, coveredAmountUsd: g.coveredAmountUsd, premiumUsd: g.premiumUsd, counterpartyUsdot: g.counterpartyUsdot, beneficiaryUsdot: g.beneficiaryUsdot });
      this.audit.write({ component: "underwriting", event: "guarantee-attached", outcome: "ALLOWED", taskId: t.task.id, evidence: { guaranteeId, coveredAmountUsd: g.coveredAmountUsd, premiumUsd: g.premiumUsd, probabilityOfLoss: quote.assessment.probabilityOfLoss, factors: quote.assessment.factors, exposureAfter: quote.exposureAfter } });
    } else {
      this.audit.write({ component: "underwriting", event: "guarantee-declined", outcome: "INFO", reasonCode: quote.reasonCode, taskId: t.task.id, evidence: { ...quote.evidence, proceededUnguaranteed: true } });
    }
    const day = terms.pickup.windowStart.slice(0, 10);
    this.exposureFor(t.brokerAgentId).add(terms.carrierEntity.usdot, terms.rateUsd, day);
    this.exposureFor(t.carrierAgentId).add(terms.brokerEntity.usdot, terms.rateUsd, day);

    const rec: CommitmentRecord = { commitmentId, taskId: t.task.id, loadRef: terms.loadRef, loadFingerprint: loadFingerprint(terms.load), brokerAgentId: t.brokerAgentId, carrierAgentId: t.carrierAgentId, brokerUsdot: terms.brokerEntity.usdot, carrierUsdot: terms.carrierEntity.usdot, rateUsd: terms.rateUsd, pickupWindowStart: terms.pickup.windowStart, status: "ACTIVE", guaranteeId, artifact };
    this.state.commitments.set(commitmentId, rec);
    t.status = "COMMITTED";
    t.commitmentId = commitmentId;
    t.task.artifacts = [{ artifactId: commitmentId, name: "commitment", description: "Signed commitment artifact", parts: [{ kind: "data", data: artifact as unknown as Record<string, unknown> }] }];
    const payload = { type: "COMMITTED" as const, loadRef: terms.loadRef, commitmentId, termsHash: artifact.termsHash, guarantee: quote.decision === "GUARANTEED" ? { guaranteeId: quote.guarantee.guaranteeId, coveredAmountUsd: quote.guarantee.coveredAmountUsd, premiumUsd: quote.guarantee.premiumUsd, scope: quote.guarantee.scope } : undefined, artifact: artifact as unknown as Record<string, unknown> };
    const notice = this.venueMessage(payload, t.task.id, t.task.contextId);
    t.task.status = { state: "completed", timestamp: new Date().toISOString(), message: notice };
    this.state.persist();
    this.audit.write({ component: "venue.commitment", event: "commit", outcome: "ALLOWED", taskId: t.task.id, contextId: t.task.contextId, evidence: { commitmentId, termsHash: artifact.termsHash, rateUsd: terms.rateUsd, guaranteed: !!guaranteeId, ledgerSeq: entry.seq } });
    await Promise.all([this.deliver(brokerReg, notice), this.deliver(carrierReg, notice)]);
    await this.cancelSiblings(t, rec);
  }

  /** An ACTIVE commitment in which `brokerAgentId` is the broker for this physical load, if any. */
  private activeCommitmentForLoad(brokerAgentId: string, loadRef: string, fingerprint: string): CommitmentRecord | undefined {
    for (const c of this.state.commitments.values()) {
      if (c.status === "ACTIVE" && c.brokerAgentId === brokerAgentId && (c.loadRef === loadRef || c.loadFingerprint === fingerprint)) return c;
    }
    return undefined;
  }

  /** Multi-tender: once one carrier's commitment is recorded, every other open negotiation for the same load is canceled. */
  private async cancelSiblings(winner: NegotiationTask, rec: CommitmentRecord) {
    for (const s of this.state.tasks.values()) {
      if (s.task.id === winner.task.id || s.brokerAgentId !== winner.brokerAgentId) continue;
      if (TERMINAL_STATES.includes(s.task.status.state)) continue;
      if (s.loadRef !== rec.loadRef && loadFingerprint(s.load) !== rec.loadFingerprint) continue;
      await this.fail(s, "LOAD_ALREADY_COMMITTED", "venue.commitment", { agentId: s.brokerAgentId, winningCommitmentId: rec.commitmentId, canceledTaskId: s.task.id, canceledCounterparty: s.carrierAgentId, round: s.round, stateAtCancel: s.status }, undefined, undefined, s.brokerAgentId, "CANCELED");
    }
  }

  /**
   * Reply timeout. A negotiation in which the awaited party has not replied
   * within `replyTimeoutMs` is canceled, naming the silent party as subject.
   * A scheduler runs this on an interval; the sim can also trigger it.
   */
  async expireStaleTasks(now = new Date()): Promise<NegotiationTask[]> {
    const expired: NegotiationTask[] = [];
    for (const t of this.state.tasks.values()) {
      if (TERMINAL_STATES.includes(t.task.status.state)) continue;
      const waitedMs = now.getTime() - new Date(t.awaitingSince).getTime();
      if (waitedMs < this.config.replyTimeoutMs) continue;
      await this.fail(t, "NEGOTIATION_TIMEOUT", "venue.protocol", { agentId: t.awaiting, awaiting: t.awaiting, awaitingSince: t.awaitingSince, waitedMs, replyTimeoutMs: this.config.replyTimeoutMs, round: t.round, state: t.status, lastOffers: { onTable: t.onTable } }, undefined, undefined, t.awaiting, "CANCELED");
      expired.push(t);
    }
    return expired;
  }

  /**
   * Terminate a negotiation. The party the refusal is ABOUT (`subject`) gets the
   * full evidence; the other party gets a redacted notice. A broker's mandate
   * ceiling or a carrier's other guaranteed loads must never leak to the
   * counterparty through a refusal (see DECISIONS.md Q2).
   */
  private async fail(t: NegotiationTask, reasonCode: ReasonCode, refusedBy: Component, evidence: Record<string, unknown>, _triggering?: Message, _other?: RegisteredAgent, subject?: string, disposition: "FAILED" | "CANCELED" = reasonCode === "NEGOTIATION_WALKAWAY" ? "CANCELED" : "FAILED") {
    t.status = reasonCode === "NEGOTIATION_WALKAWAY" ? "REJECTED" : disposition === "CANCELED" ? "CANCELED" : "FAILED";
    t.outcome = { reasonCode, refusedBy, evidence, guaranteeWouldHavePaid: guaranteeWouldHavePaid(reasonCode) };
    const subjectId = subject ?? (typeof evidence.agentId === "string" ? evidence.agentId : typeof evidence.acceptedBy === "string" ? evidence.acceptedBy : typeof evidence.by === "string" ? evidence.by : undefined);
    const full = this.venueMessage({ type: "REFUSED", loadRef: t.loadRef, reasonCode, refusedBy, evidence, disposition }, t.task.id, t.task.contextId);
    const redacted = this.venueMessage({ type: "REFUSED", loadRef: t.loadRef, reasonCode, refusedBy, evidence: redactForCounterparty(evidence, subjectId), disposition }, t.task.id, t.task.contextId);
    t.task.status = { state: disposition === "CANCELED" ? "canceled" : "failed", timestamp: new Date().toISOString(), message: full };
    this.state.persist();
    this.audit.write({ component: refusedBy, event: "negotiation-terminated", outcome: "REFUSED", reasonCode, taskId: t.task.id, contextId: t.task.contextId, subject: subjectId, evidence });
    const parties = [this.state.agents.get(t.brokerAgentId), this.state.agents.get(t.carrierAgentId)].filter((x): x is RegisteredAgent => !!x);
    await Promise.all(parties.map((p) => this.deliver(p, !subjectId || p.agentId === subjectId ? full : redacted)));
  }

  // ------------------------------------------------------- outbound to agents

  private attachment(t: NegotiationTask, from: RegisteredAgent, fromCred: Credential, fromLive: LiveCheckResult, round: number, guaranteeAvailable?: boolean): VenueAttachment {
    return {
      taskId: t.task.id,
      contextId: t.task.contextId,
      round,
      forwardedAt: new Date().toISOString(),
      counterparty: {
        agentId: from.agentId,
        credentialId: fromCred.credentialId,
        entity: fromCred.subject.entity,
        publicKey: fromCred.subject.publicKey,
        insurance: { bipdUsd: fromLive.insurance?.bipdCoverageUsd ?? 0, cargoUsd: fromLive.insurance?.cargoCoverageUsd ?? 0, bondUsd: fromLive.insurance?.bondUsd ?? 0 },
        verifiedAt: new Date().toISOString(),
      },
      guaranteeAvailable,
    };
  }

  private async forward(m: Message, t: NegotiationTask, to: RegisteredAgent, from: RegisteredAgent, fromCred: Credential, fromLive: LiveCheckResult, round: number, guaranteeAvailable?: boolean) {
    // Never mutate a signed message: task/context ids ride in the venue attachment.
    const signed = venueSignMessage(m, this.kp, this.attachment(t, from, fromCred, fromLive, round, guaranteeAvailable));
    await this.deliver(to, signed);
  }

  private venueMessage(data: Record<string, unknown>, taskId: string, contextId: string): Message {
    const m = buildMessage({ role: "agent", data, taskId, contextId, senderAgentId: "venue", credentialId: "venue" });
    return venueSignMessage(m, this.kp);
  }

  private async deliver(to: RegisteredAgent, m: Message) {
    this.state.logMessage("OUT", m, `to ${to.agentId}`);
    try {
      const res = await rpcCall(`${to.url}/a2a`, "message/send", { message: m });
      if (res.error) this.audit.write({ component: "venue.routing", event: "deliver", outcome: "INFO", subject: to.agentId, taskId: m.taskId, evidence: { error: res.error } });
    } catch (e) {
      this.audit.write({ component: "venue.routing", event: "deliver", outcome: "INFO", subject: to.agentId, taskId: m.taskId, evidence: { error: String(e) } });
    }
  }

  // ------------------------------------------------- post-commitment checks

  /** Re-verify both parties of every ACTIVE commitment whose pickup is still ahead. A scheduler would run this; the sim triggers it. */
  async prePickupChecks(now = new Date()): Promise<CommitmentRecord[]> {
    const voided: CommitmentRecord[] = [];
    for (const c of this.state.commitments.values()) {
      if (c.status !== "ACTIVE" || new Date(c.pickupWindowStart) < now) continue;
      for (const side of ["broker", "carrier"] as const) {
        const cred = c.artifact.credentials[side];
        const cv = verifyCredential(cred, { issuerPublicKey: this.kp.publicJwk, revocation: this.issuer.revocation(cred.credentialId), now });
        const lv = cv.ok ? liveCheck(this.registry, cred, { now, hazmat: c.artifact.terms.load.hazmat }) : undefined;
        const bad = !cv.ok ? cv : lv && !lv.ok ? lv : undefined;
        if (!bad) continue;
        const reasonCode: ReasonCode = bad.reasonCode === "CREDENTIAL_REVOKED" ? "CREDENTIAL_REVOKED_PRE_PICKUP" : bad.reasonCode!;
        const evidence = { commitmentId: c.commitmentId, party: side, agentId: side === "broker" ? c.brokerAgentId : c.carrierAgentId, pickupWindowStart: c.pickupWindowStart, checkedAt: now.toISOString(), underlying: bad.reasonCode, ...bad.evidence };
        c.status = "VOIDED";
        c.voided = { at: now.toISOString(), reasonCode, evidence };
        this.ledger.append("VOID", { commitmentId: c.commitmentId, reasonCode, evidence });
        if (c.guaranteeId) {
          const g = this.underwriting.release(c.guaranteeId, reasonCode);
          if (g) this.ledger.append("GUARANTEE_RELEASED", { commitmentId: c.commitmentId, guaranteeId: g.guaranteeId, coveredAmountUsd: g.coveredAmountUsd, reason: reasonCode });
        }
        const day = c.pickupWindowStart.slice(0, 10);
        this.exposureFor(c.brokerAgentId).release(c.carrierUsdot, c.rateUsd, day);
        this.exposureFor(c.carrierAgentId).release(c.brokerUsdot, c.rateUsd, day);
        this.audit.write({ component: "venue.commitment", event: "pre-pickup-check", outcome: "VOIDED", reasonCode, taskId: c.taskId, evidence: { ...evidence, guaranteeReleased: !!c.guaranteeId, guaranteeWouldHavePaid: guaranteeWouldHavePaid(reasonCode) } });
        const t = this.state.tasks.get(c.taskId);
        if (t) t.outcome = { reasonCode, refusedBy: "venue.commitment", evidence, guaranteeWouldHavePaid: guaranteeWouldHavePaid(reasonCode) };
        const notice = this.venueMessage({ type: "VOIDED", loadRef: c.loadRef, commitmentId: c.commitmentId, reasonCode, evidence }, c.taskId, `ctx_${c.loadRef}`);
        this.state.persist();
        for (const id of [c.brokerAgentId, c.carrierAgentId]) {
          const reg = this.state.agents.get(id);
          if (reg) await this.deliver(reg, notice);
        }
        voided.push(c);
        break;
      }
    }
    return voided;
  }
}

/** Non-sensitive keys a counterparty may see about a refusal that concerns the other party. */
const COUNTERPARTY_SAFE_KEYS = new Set(["round", "maxRounds", "stage", "atRound", "error", "taskId", "state", "awaiting", "awaitingSince", "waitedMs", "replyTimeoutMs", "lastOffers", "by", "reason", "canceledTaskId"]);

export function redactForCounterparty(evidence: Record<string, unknown>, subjectAgentId: string | undefined): Record<string, unknown> {
  if (!subjectAgentId) return evidence;
  const out: Record<string, unknown> = { redacted: true, concerning: subjectAgentId };
  for (const [k, v] of Object.entries(evidence)) if (COUNTERPARTY_SAFE_KEYS.has(k)) out[k] = v;
  return out;
}
