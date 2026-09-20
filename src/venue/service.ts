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
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { A2A_PROTOCOL_VERSION, FREIGHT_EXTENSION_URI, RPC_ERR, TERMINAL_STATES, dataPart, signAgentCard, verifyAgentCard, type AgentCard, type Message, type Task } from "../protocol/a2a";
import { canonicalize, hashObject } from "../protocol/canonical";
import { importPublicKey, verifyJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { VenueKeyRing } from "./keyring";
import { verifyReceipt, type LedgerHead, type WitnessKey, type WitnessReceipt, type Witnessed } from "../protocol/witness";
import type { CredentialStatusEntry } from "../protocol/types";
import { signJws } from "../protocol/crypto";
import { verifyCert, verifyRevocation, verifyRootEventSelf, rootCommitment, type RootEvent, type VenueKeyCert, type VenueKeyRevocation } from "../protocol/venue-keys";
import { buildMessage, venueSignMessage, type SignedMeta, type VenueAttachment } from "../protocol/envelope";
import { loadFingerprint, termsHash, textDigest, validateNegotiationPayload, type AcceptPayload, type CounterPayload, type NegotiationPayload, type RejectPayload, type TenderPayload, type Terms } from "../protocol/freight";
import { REASONS, type ReasonCode } from "../protocol/reasons";
import { AuditLog, type Component } from "../protocol/audit";
import { rpcCall, RpcRefusal } from "../protocol/rpc";
import type { Credential, MandateEnvelope, RotationAuthorization, RotationClaims } from "../protocol/types";
import { MockRegistry } from "../identity/registry";
import { StubVettingProvider } from "../identity/vetting";
import { CredentialIssuer } from "../identity/issuer";
import { liveCheck, signatureTrustedAt, verifyCredential, verifyPresentation, type LiveCheckResult } from "../identity/verifier";
import { envelopeToLimits, evaluateMandate } from "../mandate/engine";
import { verifyEnvelope } from "../mandate/sign";
import { ExposureBook } from "../mandate/exposure";
import { Ledger, type LedgerEntry } from "../ledger/chain";
import { artifactHash, buildArtifact, reattestArtifact, type CommitmentArtifact } from "../ledger/artifact";
import { UnderwritingEngine } from "../underwriting/engine";
import { DEFAULT_PARAMS, type RiskInputs, type UnderwritingParams } from "../underwriting/types";
import { VenueState, type CommitJournal, type CommitmentRecord, type KeyRotationJournal, type NegotiationTask, type Offer, type RegisteredAgent, type RootRotationJournal, type VoidJournal } from "./state";
import { GUARANTEE_SCOPE } from "../underwriting/types";
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
  /** Deliveries abandoned to the dead-letter queue after this many attempts (agents can still pull via tasks/get). */
  outboxMaxAttempts: number;
  underwriting?: Partial<UnderwritingParams>;
  /** Independent witnesses whose receipts are accepted. Configured by the operator; a witness key is never minted by the venue. */
  witnesses?: WitnessKey[];
}

export class Refusal extends Error {
  constructor(public readonly reasonCode: ReasonCode, public readonly refusedBy: Component, public readonly evidence: Record<string, unknown>) {
    super(`${reasonCode}: ${REASONS[reasonCode]}`);
  }
}

export class VenueService {
  /** Venue key ring: root public key, ACTIVE operational key, certificates, revocations. Never cache `kp` across a rotation. */
  readonly keys: VenueKeyRing;
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
    this.keys = new VenueKeyRing(config.dataDir, config.venueId);
    this.url = `http://127.0.0.1:${config.port}`;
    this.registry = new MockRegistry(config.registryPath);
    this.issuer = new CredentialIssuer(config.venueId, () => this.keys.signer(), this.registry, new StubVettingProvider(this.registry), config.dataDir);
    this.ledger = new Ledger(join(config.dataDir, "ledger.jsonl"), () => this.keys.signer(), this.keys.currentCert(), this.keys.currentRootEvent());
    this.underwriting = new UnderwritingEngine(config.dataDir, { ...DEFAULT_PARAMS, ...config.underwriting });
    this.audit = new AuditLog(join(config.dataDir, "audit.jsonl"));
    this.state = new VenueState(config.dataDir);
    for (const w of config.witnesses ?? []) this.registerWitness(w);
  }

  // ------------------------------------------------------- witnessed heads
  //
  // The ledger is the source of truth; the published status list and key
  // history are projections of it at a head. Independent witnesses cosign
  // heads with their own clocks; the venue merely stores and republishes
  // their receipts. See protocol/witness.ts.

  registerWitness(w: WitnessKey) {
    if (!this.state.witnesses.some((x) => x.witnessId === w.witnessId)) {
      this.state.witnesses.push(w);
      this.state.persist();
      this.audit.write({ component: "venue.identity", event: "witness-registered", outcome: "INFO", evidence: { witnessId: w.witnessId, kid: w.publicKey.kid } });
    }
  }

  ledgerHead(requester?: string): LedgerHead & { venueId: string } {
    const h = this.ledgerViewFor(requester).at(-1)!;
    return { venueId: this.config.venueId, seq: h.seq, hash: h.hash, ts: h.ts };
  }

  /** The key a witness id signs with: a registered independent witness, or a registered AGENT (a party witnessing its own transactions) — any key in its credential lineage. */
  private witnessKeysFor(witnessId: string): OkpJwk[] {
    const w = this.state.witnesses.find((x) => x.witnessId === witnessId);
    if (w) return [w.publicKey];
    const reg = this.state.agents.get(witnessId);
    if (!reg) return [];
    return [reg.credentialId, ...(reg.previousCredentialIds ?? [])].map((id) => this.issuer.get(id)?.subject.publicKey).filter((k): k is OkpJwk => !!k);
  }

  /** Accept a witness receipt for a head that exists in this ledger, from a registered witness or a registered agent (party witness). */
  acceptWitnessReceipt(r: WitnessReceipt): { ok: true; seq: number } {
    const keys = this.witnessKeysFor(r.witnessId);
    if (keys.length === 0) throw new Refusal("PROTOCOL_VIOLATION", "venue.protocol", { error: "unknown witness", witnessId: r.witnessId });
    if (r.venueId !== this.config.venueId || !keys.some((k) => verifyReceipt(r, k))) throw new Refusal("PROTOCOL_VIOLATION", "venue.protocol", { error: "witness receipt does not verify", witnessId: r.witnessId });
    const e = this.ledger.find((x) => x.seq === r.seq);
    if (!e || e.hash !== r.hash) {
      // SIM equivocation fault: the receipt may name a head of the fork shown to this witness — keep it in the second book.
      const forkHead = this.isForkedFor(r.witnessId) ? this.ledgerViewFor(r.witnessId).find((x) => x.seq === r.seq) : undefined;
      if (!forkHead || forkHead.hash !== r.hash) throw new Refusal("PROTOCOL_VIOLATION", "venue.protocol", { error: "receipt names a head this ledger does not have", seq: r.seq, hash: r.hash.slice(0, 12) });
      (this.forkReceipts[r.hash] ??= []).push(r);
      this.audit.write({ component: "sim", event: "equivocation-fault", outcome: "INFO", evidence: { witnessId: r.witnessId, seq: r.seq, forkHash: r.hash.slice(0, 12), realHash: e?.hash.slice(0, 12) } });
      return { ok: true, seq: r.seq };
    }
    const list = (this.state.witnessReceipts[r.hash] ??= []);
    if (!list.some((x) => x.witnessId === r.witnessId && x.at === r.at)) list.push(r);
    this.state.persist();
    this.audit.write({ component: "ledger", event: "witnessed", outcome: "INFO", evidence: { witnessId: r.witnessId, seq: r.seq, hash: r.hash.slice(0, 12), witnessAt: r.at } });
    return { ok: true, seq: r.seq };
  }

  /** The highest head in the CURRENT ledger (as seen by the requester) that a witness has cosigned. After a rollback this is the last surviving one — the tell. */
  latestWitnessedHead(requester?: string): Witnessed["witnessed"] {
    const forked = this.isForkedFor(requester);
    for (const e of [...this.ledgerViewFor(requester)].sort((a, b) => b.seq - a.seq)) {
      const rs = [...(this.state.witnessReceipts[e.hash] ?? []), ...(forked ? this.forkReceipts[e.hash] ?? [] : [])];
      if (rs.length) return { head: { seq: e.seq, hash: e.hash, ts: e.ts }, receipts: rs };
    }
    return null;
  }

  private witnessedEnvelope(requester?: string): Witnessed {
    const h = this.ledgerViewFor(requester).at(-1)!;
    return { venueId: this.config.venueId, asOf: new Date().toISOString(), head: { seq: h.seq, hash: h.hash, ts: h.ts }, witnessed: this.latestWitnessedHead(requester) };
  }

  /** The credential status list: every CREDENTIAL_STATUS entry on the ledger up to the head, plus the witnessed head, signed by the venue. */
  publishedStatusList(requester?: string): Witnessed & { entries: CredentialStatusEntry[]; kid: string; signature: string } {
    const body = { ...this.witnessedEnvelope(requester), entries: this.ledgerViewFor(requester).filter((e) => e.type === "CREDENTIAL_STATUS").map((e) => (e.payload as { status: CredentialStatusEntry }).status) };
    return { ...body, kid: this.kp.kid, signature: signJws(body, this.kp, { typ: "credential-status+jws" }, true) };
  }

  /** The key history with the witnessed head, signed by the venue. */
  publishedKeyHistory(requester?: string) {
    const body = { ...this.witnessedEnvelope(requester), ...this.keys.history() };
    return { ...body, kid: this.kp.kid, signature: signJws(body, this.kp, { typ: "venue-keys+jws" }, true) };
  }

  /** Record a credential status change on the ledger (idempotent by credentialId + status + at). */
  private recordCredentialStatus(st: CredentialStatusEntry): LedgerEntry {
    const existing = this.ledger.find((e) => e.type === "CREDENTIAL_STATUS" && (e.payload as { status: CredentialStatusEntry }).status.credentialId === st.credentialId && (e.payload as { status: CredentialStatusEntry }).status.status === st.status && (e.payload as { status: CredentialStatusEntry }).status.at === st.at);
    return existing ?? this.ledger.append("CREDENTIAL_STATUS", { status: st });
  }

  /** Revoke an agent credential: issuer record + ledger entry. */
  revokeCredential(agentId: string, reason: string, evidence?: Record<string, unknown>): CredentialStatusEntry | undefined {
    const reg = this.state.agents.get(agentId);
    if (!reg) return undefined;
    const entry = this.issuer.revoke(reg.credentialId, reason, evidence);
    if (entry) {
      this.recordCredentialStatus(entry);
      this.audit.write({ component: "venue.identity", event: "revoke", outcome: "INFO", subject: agentId, evidence: { ...entry } });
    }
    return entry;
  }

  /** The current operational signing key. Read it fresh every time; it changes on rotation. */
  get kp(): KeyPair {
    return this.keys.signer();
  }
  /** Resolver for verifying anything signed by ANY certified venue key (current or retired), with compromise awareness. */
  private venueKeys() {
    return this.keys.resolver();
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
        metadata: { venueId: this.config.venueId, issuerKid: this.kp.kid, venueKeys: { rootPublicKey: this.keys.rootPublicKey, rootLog: this.keys.history().rootLog, cert: this.keys.currentCert() } },
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
    const reg: RegisteredAgent = { agentId, credentialId: res.credential.credentialId, previousCredentialIds: [], url: params.agentUrl, card: params.card, envelope, registeredAt: new Date().toISOString() };
    this.state.agents.set(agentId, reg);
    this.state.persist();
    this.audit.write({ component: "venue.identity", event: "onboard", outcome: "ALLOWED", subject: agentId, evidence: { credentialId: res.credential.credentialId, entity: res.credential.subject.entity, envelopeRegistered: !!envelope, vettingFlags: res.credential.evidence.vettingFlags } });
    return { credential: res.credential, venueCard: this.agentCard(), issuerPublicKey: this.kp.publicJwk, venueKeys: this.keys.history() };
  }

  /**
   * Key rotation. Authority: the principal key registered in the agent's
   * mandate envelope, or proof of control — never the agent's own key. The
   * agent id, entity, envelope, open negotiations and ACTIVE commitments all
   * survive; only the key changes. A COMPROMISE rotation additionally voids
   * every ACTIVE commitment whose acceptance the old key signed at or after
   * the declared compromise time.
   */
  async rotate(params: { credentialId: string; newCard: AgentCard; authorization: RotationAuthorization; claims: RotationClaims }) {
    const cardCheck = verifyAgentCard(params.newCard);
    if (!cardCheck.ok || !cardCheck.jwk) throw new Refusal("IDENTITY_SIGNATURE_INVALID", "venue.identity", { error: cardCheck.error, stage: "new-agent-card" });
    const reg = this.state.agentByCredential(params.credentialId);
    if (!reg) throw new Refusal("CREDENTIAL_UNKNOWN", "venue.identity", { credentialId: params.credentialId });
    if (String(params.newCard.metadata?.agentId ?? params.newCard.name) !== reg.agentId) throw new Refusal("ROTATION_UNAUTHORIZED", "venue.identity", { error: "new agent card is for a different agentId" });
    const res = await this.issuer.rotate({ credentialId: params.credentialId, newPublicKey: cardCheck.jwk, authorization: params.authorization, claims: params.claims, principalPublicKey: reg.envelope?.principalPublicKey });
    if (!res.ok) {
      this.audit.write({ component: "venue.identity", event: "rotate", outcome: "REFUSED", reasonCode: res.reasonCode, subject: reg.agentId, evidence: { ...res.evidence, authorization: params.authorization.kind, reason: params.claims.reason } });
      throw new Refusal(res.reasonCode, "venue.identity", { ...res.evidence, authorization: params.authorization.kind });
    }
    reg.previousCredentialIds = [...(reg.previousCredentialIds ?? []), reg.credentialId];
    reg.credentialId = res.credential.credentialId;
    reg.card = params.newCard;
    reg.rotatedAt = new Date().toISOString();
    this.state.persist();
    this.recordCredentialStatus(res.superseded);
    this.audit.write({ component: "venue.identity", event: "rotate", outcome: "ALLOWED", subject: reg.agentId, evidence: { reason: params.claims.reason, authorizedBy: params.authorization.kind, oldCredentialId: res.superseded.credentialId, newCredentialId: res.credential.credentialId, oldKid: this.issuer.get(res.superseded.credentialId)?.subject.publicKey.kid, newKid: res.credential.subject.publicKey.kid, graceUntil: res.superseded.graceUntil, compromisedAt: res.superseded.compromisedAt } });
    let voided: string[] = [];
    if (res.superseded.compromisedAt) voided = (await this.voidUnderCompromisedKey(res.superseded.credentialId, new Date(res.superseded.compromisedAt))).map((c) => c.commitmentId);
    return { credential: res.credential, superseded: res.superseded, voidedCommitments: voided };
  }

  /** Void every ACTIVE commitment whose acceptance this credential signed at or after `compromisedAt`. */
  private async voidUnderCompromisedKey(credentialId: string, compromisedAt: Date): Promise<CommitmentRecord[]> {
    const voided: CommitmentRecord[] = [];
    for (const c of this.state.commitments.values()) {
      if (c.status !== "ACTIVE") continue;
      for (const side of ["broker", "carrier"] as const) {
        const acc = c.artifact.acceptances[side];
        const meta = acc.metadata as SignedMeta;
        if (meta.credentialId !== credentialId) continue;
        const signedAt = new Date(meta.ts);
        if (signedAt < compromisedAt) continue;
        const evidence = { commitmentId: c.commitmentId, party: side, agentId: side === "broker" ? c.brokerAgentId : c.carrierAgentId, credentialId, signedAt: meta.ts, compromisedAt: compromisedAt.toISOString(), note: "acceptance signed after the key's declared compromise time; the legitimate party may re-commit with its new key" };
        const journal: VoidJournal = { kind: "VOID", commitmentId: c.commitmentId, writtenAt: new Date().toISOString(), reasonCode: "COMMITMENT_UNDER_COMPROMISED_KEY", evidence, origin: "compromise-void" };
        this.state.writeJournal(journal);
        const g = c.guaranteeId ? this.underwriting.guaranteeForCommitment(c.commitmentId) : undefined;
        const entry = this.ledger.append("VOID", { commitmentId: c.commitmentId, reasonCode: "COMMITMENT_UNDER_COMPROMISED_KEY", evidence, guaranteeReleased: g ? { guaranteeId: g.guaranteeId, coveredAmountUsd: g.coveredAmountUsd } : null });
        await this.applyVoid(journal, entry, "live");
        voided.push(c);
        break;
      }
    }
    return voided;
  }

  /** Every certificate for the given venue kids (a key may hold an original and a re-certification). */
  private certsFor(kids: string[]): VenueKeyCert[] {
    const out: VenueKeyCert[] = [];
    for (const k of new Set(kids)) for (const c of this.keys.certsFor(k)) if (!out.some((x) => x.rootSignature === c.rootSignature)) out.push(c);
    return out;
  }

  // ------------------------------------------------------------ root rotation
  //
  // Pre-rotation: the operator reveals the root it committed to at the last
  // ceremony, signs the event with it, and commits to the next. The venue
  // process verifies the commitment and the self-signature; nothing the
  // CURRENT root signs can authorize a different successor, so a stolen root
  // cannot rotate. On COMPROMISE the operator also re-certifies the venue's
  // genuine operational key under the new root (original validFrom), so its
  // whole tenure stays trusted while any key the thief certified does not.

  async rootRotationCommit(params: { event: RootEvent; recert?: VenueKeyCert }) {
    const cur = this.keys.currentRootEvent();
    const e = params.event;
    const refuse = (error: string, extra: Record<string, unknown> = {}) => {
      this.audit.write({ component: "venue.identity", event: "root-rotation", outcome: "REFUSED", reasonCode: "ROOT_ROTATION_UNAUTHORIZED", evidence: { error, currentRootKid: cur.rootKid, presentedRootKid: e.rootKid, ...extra } });
      throw new Refusal("ROOT_ROTATION_UNAUTHORIZED", "venue.identity", { error, currentRootKid: cur.rootKid, presentedRootKid: e.rootKid, ...extra });
    };
    if (e.rootKid === cur.rootKid) return { previousRootKid: cur.previousRootKid ?? cur.rootKid, rootKid: cur.rootKid, seq: cur.seq, alreadyInstalled: true };
    if (e.previousRootKid !== cur.rootKid) return refuse("event does not link to the current root");
    if (e.seq !== cur.seq + 1) return refuse("event sequence is not the next one", { expectedSeq: cur.seq + 1 });
    if (rootCommitment(e.rootPublicKey) !== cur.nextRootCommitment) return refuse("new root does not match the pre-committed successor; the current root's signature cannot substitute for it", { presentedCommitment: rootCommitment(e.rootPublicKey), expectedCommitment: cur.nextRootCommitment, previousRootCountersigned: !!e.previousRootSignature });
    if (!verifyRootEventSelf(e)) return refuse("event is not signed by the new root");
    if (e.reason === "COMPROMISE" && !e.compromisedAt) return refuse("COMPROMISE requires compromisedAt");
    if (params.recert && (params.recert.kid !== this.kp.kid || !verifyCert(params.recert, e.rootPublicKey))) return refuse("re-certification must name the active operational key and be signed by the new root");
    const journal: RootRotationJournal = { kind: "ROOT_ROTATION", commitmentId: `rootrot_${e.rootKid.slice(0, 16)}`, writtenAt: new Date().toISOString(), event: e, recert: params.recert };
    this.state.writeJournal(journal);
    const entry = this.ledger.append("ROOT_ROTATION", { rootEvent: e, recert: params.recert ?? null, reason: e.reason });
    this.crashIf("after-root-rotation-append");
    return this.applyRootRotation(journal, entry, "live");
  }

  private async applyRootRotation(j: RootRotationJournal, entry: LedgerEntry, mode: "live" | "recovery") {
    const r = this.keys.installRoot(j.event, j.recert); // idempotent by root kid
    this.state.persist();
    this.state.deleteJournal(j.commitmentId);
    this.audit.writeOnce(`root-rotation:${j.event.rootKid}`, { component: "venue.identity", event: "root-rotation", outcome: "ALLOWED", evidence: { reason: j.event.reason, previousRootKid: r.previousRootKid, newRootKid: j.event.rootKid, seq: j.event.seq, compromisedAt: j.event.compromisedAt, recertifiedOperationalKey: r.recertified, ledgerSeq: entry.seq, previousRootCountersigned: !!j.event.previousRootSignature, mode } });
    await this.flushOutbox();
    return { previousRootKid: r.previousRootKid, rootKid: j.event.rootKid, seq: j.event.seq, recertified: r.recertified, alreadyInstalled: false };
  }

  // ------------------------------------------------------ venue key rotation
  //
  // Two steps, like an agent's: the venue process generates the next key but
  // cannot certify it; the OPERATOR's root does. Commit is a transaction:
  //   journal → KEY_ROTATION ledger entry signed by the SUCCESSOR (its
  //   authority is the root-signed cert it carries) → install → persist →
  //   (compromise: re-issue credentials, re-attest commitments, reseal the
  //   ledger) → notices. Recovery finishes a rotation whose entry is on the
  //   ledger and discards one whose entry is not.

  keyRotationPrepare(params: { authorization: string }) {
    const claims = this.rootAuthorized(params.authorization, "key-rotation/prepare");
    const p = this.keys.prepare();
    this.audit.write({ component: "venue.identity", event: "venue-key-prepare", outcome: "INFO", evidence: { pendingKid: p.kid, seq: p.seq, ts: claims.ts } });
    return p;
  }

  async keyRotationCommit(params: { cert: VenueKeyCert; revocation?: VenueKeyRevocation }) {
    if (!verifyCert(params.cert, this.keys.rootPublicKey)) throw new Refusal("VENUE_KEY_ROTATION_UNAUTHORIZED", "venue.identity", { error: "certificate not signed by the current venue root", certKid: params.cert.kid, rootKid: this.keys.rootPublicKey.kid });
    if (params.revocation && !verifyRevocation(params.revocation, this.keys.rootPublicKey)) throw new Refusal("VENUE_KEY_ROTATION_UNAUTHORIZED", "venue.identity", { error: "revocation not signed by the current venue root" });
    if (params.revocation && params.revocation.kid !== this.kp.kid) throw new Refusal("VENUE_KEY_ROTATION_UNAUTHORIZED", "venue.identity", { error: "revocation does not name the active key", active: this.kp.kid, named: params.revocation.kid });
    const pending = this.keys.pendingSigner();
    if (!pending || pending.kid !== params.cert.kid) throw new Refusal("VENUE_KEY_ROTATION_UNAUTHORIZED", "venue.identity", { error: "certificate does not name the pending key", pendingKid: pending?.kid, certKid: params.cert.kid });
    const previousKid = this.kp.kid;
    const journal: KeyRotationJournal = { kind: "KEY_ROTATION", commitmentId: `keyrot_${params.cert.kid.slice(0, 16)}`, writtenAt: new Date().toISOString(), previousKid, cert: params.cert, revocation: params.revocation };
    this.state.writeJournal(journal);
    // The entry is the successor's first signature; its authority is the root-signed certificate in its payload.
    const entry = this.ledger.append("KEY_ROTATION", { previousKid, cert: params.cert, revocation: params.revocation ?? null, reason: params.cert.reason }, pending);
    this.crashIf("after-key-rotation-append");
    return this.applyKeyRotation(journal, entry, "live");
  }

  private async applyKeyRotation(j: KeyRotationJournal, entry: LedgerEntry, mode: "live" | "recovery") {
    this.keys.install(j.cert, j.revocation); // idempotent by kid
    this.state.persist();
    const compromisedAt = j.revocation?.compromisedAt ? new Date(j.revocation.compromisedAt) : undefined;
    let reissued: string[] = [];
    let reattested: string[] = [];
    let resealed: { fromSeq: number; toSeq: number } | undefined;
    if (compromisedAt) {
      // 1. Credentials issued under the compromised key after the compromise: re-sign under the new key, push to agents.
      const creds = this.issuer.reissueUnder(j.previousKid, compromisedAt);
      reissued = creds.map((c) => c.credentialId);
      for (const c of creds) {
        const reg = this.state.agentByCredential(c.credentialId);
        if (reg) this.enqueue(reg.agentId, this.venueMessage({ type: "CREDENTIAL_REISSUED", credential: c as unknown as Record<string, unknown>, reason: `venue key ${j.previousKid.slice(0, 12)}… compromised as of ${j.revocation!.compromisedAt}` }, "n/a", "n/a"), `CREDENTIAL_REISSUED ${c.credentialId}`);
      }
      // 2. Commitments attested under the compromised key after the compromise: re-attest (additive) and record it.
      for (const c of this.state.commitments.values()) {
        const suspect = c.artifact.venueAttestations.some((a) => a.kid === j.previousKid && new Date(a.at) >= compromisedAt);
        const alreadyReattested = c.artifact.venueAttestations.some((a) => a.kid === this.kp.kid);
        if (!suspect || alreadyReattested) continue;
        const fresh = { broker: this.issuer.get(c.artifact.credentials.broker.credentialId) ?? c.artifact.credentials.broker, carrier: this.issuer.get(c.artifact.credentials.carrier.credentialId) ?? c.artifact.credentials.carrier };
        c.artifact = reattestArtifact(c.artifact, this.kp, { credentials: fresh, addCerts: this.certsFor([this.kp.kid, fresh.broker.issuer.kid, fresh.carrier.issuer.kid]) });
        this.ledger.append("REATTESTATION", { commitmentId: c.commitmentId, previousKid: j.previousKid, kid: this.kp.kid, artifactHash: artifactHash(c.artifact) });
        reattested.push(c.commitmentId);
        const t = this.state.tasks.get(c.taskId);
        if (t) t.task.artifacts = [{ artifactId: c.commitmentId, name: "commitment", description: "Signed commitment artifact (re-attested)", parts: [{ kind: "data", data: c.artifact as unknown as Record<string, unknown> }] }];
        for (const id of [c.brokerAgentId, c.carrierAgentId]) this.enqueue(id, this.venueMessage({ type: "COMMITMENT_REATTESTED", loadRef: c.loadRef, commitmentId: c.commitmentId, artifact: c.artifact as unknown as Record<string, unknown>, reason: `venue key ${j.previousKid.slice(0, 12)}… compromised as of ${j.revocation!.compromisedAt}` }, c.taskId, `ctx_${c.loadRef}`), `COMMITMENT_REATTESTED ${c.commitmentId}`);
      }
      // 3. Ledger entries the compromised key signed after the compromise: the new key affirms them as this venue's own.
      const suspectSeqs = this.ledger.all().filter((e) => e.type !== "KEY_ROTATION" && new Date(e.ts) >= compromisedAt && e.seq < entry.seq).map((e) => e.seq);
      if (suspectSeqs.length) {
        resealed = { fromSeq: Math.min(...suspectSeqs), toSeq: Math.max(...suspectSeqs) };
        this.ledger.append("RESEAL", { ...resealed, previousKid: j.previousKid, reason: "entries signed by a key later declared compromised; affirmed from the venue's own records" });
      }
      this.state.persist();
    }
    this.state.deleteJournal(j.commitmentId);
    this.audit.writeOnce(`venue-key-rotation:${j.cert.kid}`, { component: "venue.identity", event: "venue-key-rotation", outcome: "ALLOWED", evidence: { reason: j.cert.reason, previousKid: j.previousKid, newKid: j.cert.kid, seq: j.cert.seq, ledgerSeq: entry.seq, compromisedAt: j.revocation?.compromisedAt, credentialsReissued: reissued, commitmentsReattested: reattested, resealed, mode } });
    await this.flushOutbox();
    return { previousKid: j.previousKid, kid: j.cert.kid, seq: j.cert.seq, credentialsReissued: reissued, commitmentsReattested: reattested, resealed };
  }

  /** Verify a root-signed operator request `{ action, ts }`. */
  private rootAuthorized(jws: string, action: string): { action: string; ts: string } {
    const res = verifyJws(jws, importPublicKey(this.keys.rootPublicKey));
    const claims = res.payload as { action?: string; ts?: string } | undefined;
    if (!res.ok || claims?.action !== action || !claims.ts || Math.abs(Date.now() - new Date(claims.ts).getTime()) > 5 * 60_000) {
      this.audit.write({ component: "venue.identity", event: action, outcome: "REFUSED", reasonCode: "VENUE_KEY_ROTATION_UNAUTHORIZED", evidence: { error: res.error ?? "claims mismatch", action } });
      throw new Refusal("VENUE_KEY_ROTATION_UNAUTHORIZED", "venue.identity", { error: res.error ?? "operator request not signed by the venue root or stale", action });
    }
    return { action: claims.action, ts: claims.ts };
  }

  // ------------------------------------------------------------- RPC surface

  async handleRpc(method: string, params: unknown, headers: Record<string, string | string[] | undefined>): Promise<unknown> {
    try {
      switch (method) {
        case "venue/onboard":
          return await this.onboard(params as Parameters<VenueService["onboard"]>[0]);
        case "venue/rotate":
          return await this.rotate(params as Parameters<VenueService["rotate"]>[0]);
        case "venue/key-rotation/prepare":
          return this.keyRotationPrepare(params as { authorization: string });
        case "venue/key-rotation/commit":
          return await this.keyRotationCommit(params as { cert: VenueKeyCert; revocation?: VenueKeyRevocation });
        case "venue/root-rotation/commit":
          return await this.rootRotationCommit(params as { event: RootEvent; recert?: VenueKeyCert });
        case "venue/witness":
          return this.acceptWitnessReceipt((params as { receipt: WitnessReceipt }).receipt);
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
    const cv = verifyCredential(cred, { issuerKeys: this.venueKeys(), status: this.issuer.status(claims.credentialId) });
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
    const cv = verifyCredential(cred, { issuerKeys: this.venueKeys(), status: this.issuer.status(meta.credentialId) });
    if (!cv.ok || !cred) {
      this.audit.write({ component: "venue.identity", event: "ingest", outcome: "REFUSED", reasonCode: cv.reasonCode, subject: meta.senderAgentId, taskId: m.taskId, evidence: cv.evidence });
      throw new Refusal(cv.reasonCode ?? "CREDENTIAL_UNKNOWN", "venue.identity", cv.evidence);
    }
    if (cv.evidence.grace) this.audit.write({ component: "venue.identity", event: "ingest", outcome: "INFO", subject: meta.senderAgentId, taskId: m.taskId, evidence: { note: "message signed with a superseded key inside its rotation grace window", ...cv.evidence } });
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
    // 4. closed wire schema — after identity, so the refusal is attributable to an authenticated sender
    const schema = validateNegotiationPayload(data);
    if (!schema.ok) {
      const code: ReasonCode = schema.violations.some((x) => x.rule === "TOO_LONG" || x.rule === "UNSAFE_CHARS" || x.rule === "BAD_ENUM" || x.rule === "UNKNOWN_KEY") ? "UNTRUSTED_TEXT_REJECTED" : "PROTOCOL_VIOLATION";
      const ev = { payloadType: data.type, violations: schema.violations, ...textDigest(typeof (data as { text?: unknown }).text === "string" ? (data as { text: string }).text : undefined) };
      this.audit.write({ component: "venue.protocol", event: "schema", outcome: "REFUSED", reasonCode: code, subject: sender.agentId, taskId: m.taskId, evidence: ev });
      throw new Refusal(code, "venue.protocol", ev);
    }
    this.state.nonces.set(meta.nonce, { messageId: m.messageId, ts: meta.ts, senderAgentId: sender.agentId });
    this.state.persist();
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
      const cv = verifyCredential(cpCred, { issuerKeys: this.venueKeys(), status: this.issuer.status(cp.credentialId), now });
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
      await this.fail(t, "NEGOTIATION_WALKAWAY", "venue.protocol", { by: sender.agentId, round: data.round, reasonCode: data.reasonCode, ...textDigest(data.text) }, m, other);
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
      this.audit.write({ component: "venue.routing", event: "counter", outcome: "ALLOWED", subject: sender.agentId, taskId: t.task.id, evidence: { round, rateUsd: data.offer.rateUsd, noteCode: data.noteCode, ...textDigest(data.text) } });
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
    // Persist the acceptance (and this message's nonce) before attempting the commit: a crash inside
    // commit() then leaves a task recovery can finish, and the sender's retry is answered NONCE_REUSED.
    this.state.persist();

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

  // ------------------------------------------------------------ commit
  //
  // A commit is a transaction over several files. The protocol is:
  //
  //   1. PREPARE  — pure: re-verify identities, quote underwriting, build the
  //                 artifact. Nothing is written.
  //   2. JOURNAL  — write the intent atomically (journal/<commitmentId>.json).
  //   3. COMMIT POINT — one durable ledger append. The COMMITMENT entry carries
  //                 the guarantee, so "committed" and "guaranteed" cannot diverge.
  //   4. APPLY    — side effects, each idempotent by commitmentId: guarantee
  //                 record, exposure books, commitment record, task state, and
  //                 the COMMITTED notices into the outbox. Then one atomic
  //                 snapshot write.
  //   5. CLEANUP  — delete the journal; flush the outbox (at-least-once).
  //
  // A crash before 3 leaves nothing but a journal, which recovery discards
  // (and, because both acceptances are already in the snapshot, retries the
  // commit). A crash after 3 leaves a ledger entry and a journal; recovery
  // re-runs 4–5, and every step tolerates having already happened.

  private async commit(t: NegotiationTask, terms: Terms) {
    const brokerReg = this.state.agents.get(t.brokerAgentId)!;
    const carrierReg = this.state.agents.get(t.carrierAgentId)!;
    // The artifact must embed the credential that SIGNED each acceptance (a party may have rotated its
    // key between accepting and the commit); good standing is checked against the CURRENT credential.
    const brokerCred = this.issuer.get((t.acceptances[t.brokerAgentId]!.metadata as SignedMeta).credentialId)!;
    const carrierCred = this.issuer.get((t.acceptances[t.carrierAgentId]!.metadata as SignedMeta).credentialId)!;

    // 1. PREPARE — final identity re-verification of both parties at the moment of commitment.
    for (const [reg, cred] of [[brokerReg, this.issuer.get(brokerReg.credentialId)!], [carrierReg, this.issuer.get(carrierReg.credentialId)!]] as const) {
      const cv = verifyCredential(cred, { issuerKeys: this.venueKeys(), status: this.issuer.status(cred.credentialId) });
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
    const artifact = buildArtifact(
      {
        venue: { venueId: this.config.venueId, rootPublicKey: this.keys.rootPublicKey, rootLog: this.keys.history().rootLog, certs: this.certsFor([this.kp.kid, brokerCred.issuer.kid, carrierCred.issuer.kid]) },
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
    const day = terms.pickup.windowStart.slice(0, 10);
    const journal: CommitJournal = {
      kind: "COMMIT",
      commitmentId,
      taskId: t.task.id,
      writtenAt: new Date().toISOString(),
      artifact,
      guarantee: quote.decision === "GUARANTEED" ? { guaranteeId: quote.guarantee.guaranteeId, counterpartyUsdot: terms.carrierEntity.usdot, beneficiaryUsdot: terms.brokerEntity.usdot, coveredAmountUsd: quote.guarantee.coveredAmountUsd, premiumUsd: quote.guarantee.premiumUsd, day, probabilityOfLoss: quote.assessment.probabilityOfLoss, factors: quote.assessment.factors } : undefined,
      declined: quote.decision === "DECLINED" ? { reasonCode: quote.reasonCode, evidence: quote.evidence } : undefined,
      ledger: { seq: head.seq + 1, prevHash: head.hash },
    };

    // 2. JOURNAL
    this.state.writeJournal(journal);
    this.crashIf("after-journal");

    // 3. COMMIT POINT
    const entry = this.ledger.append("COMMITMENT", this.ledgerPayloadFor(journal));
    this.crashIf("after-ledger-append");

    // 4–5. APPLY + CLEANUP
    await this.applyCommit(journal, entry, "live");
  }

  private ledgerPayloadFor(j: CommitJournal): Record<string, unknown> {
    const terms = j.artifact.terms;
    return {
      commitmentId: j.commitmentId,
      taskId: j.taskId,
      termsHash: j.artifact.termsHash,
      artifactHash: artifactHash(j.artifact),
      loadRef: terms.loadRef,
      brokerUsdot: terms.brokerEntity.usdot,
      carrierUsdot: terms.carrierEntity.usdot,
      rateUsd: terms.rateUsd,
      guarantee: j.guarantee ? { guaranteeId: j.guarantee.guaranteeId, coveredAmountUsd: j.guarantee.coveredAmountUsd, premiumUsd: j.guarantee.premiumUsd, counterpartyUsdot: j.guarantee.counterpartyUsdot, beneficiaryUsdot: j.guarantee.beneficiaryUsdot } : null,
    };
  }

  /**
   * Apply a committed journal's side effects. Every step is idempotent by
   * commitmentId, so this is safe to run any number of times — which is
   * exactly what recovery does.
   */
  private async applyCommit(j: CommitJournal, entry: LedgerEntry, mode: "live" | "recovery") {
    const t = this.state.tasks.get(j.taskId);
    const terms = j.artifact.terms;
    const day = terms.pickup.windowStart.slice(0, 10);
    const artifact: CommitmentArtifact = { ...j.artifact, ledgerEntryHash: entry.hash };

    let guaranteeId: string | undefined;
    if (j.guarantee) {
      const g = this.underwriting.attach(j.guarantee, j.commitmentId); // no-op if already attached
      guaranteeId = g.guaranteeId;
    }
    const brokerAgentId = terms.brokerAgentId;
    const carrierAgentId = terms.carrierAgentId;
    this.exposureFor(brokerAgentId).add(terms.carrierEntity.usdot, terms.rateUsd, day, j.commitmentId);
    this.exposureFor(carrierAgentId).add(terms.brokerEntity.usdot, terms.rateUsd, day, j.commitmentId);

    const alreadyRecorded = this.state.commitments.has(j.commitmentId);
    if (!alreadyRecorded) {
      const rec: CommitmentRecord = { commitmentId: j.commitmentId, taskId: j.taskId, loadRef: terms.loadRef, loadFingerprint: loadFingerprint(terms.load), brokerAgentId, carrierAgentId, brokerUsdot: terms.brokerEntity.usdot, carrierUsdot: terms.carrierEntity.usdot, rateUsd: terms.rateUsd, pickupWindowStart: terms.pickup.windowStart, status: "ACTIVE", guaranteeId, artifact };
      this.state.commitments.set(j.commitmentId, rec);
    }
    const payload = { type: "COMMITTED" as const, loadRef: terms.loadRef, commitmentId: j.commitmentId, termsHash: artifact.termsHash, guarantee: j.guarantee ? { guaranteeId: j.guarantee.guaranteeId, coveredAmountUsd: j.guarantee.coveredAmountUsd, premiumUsd: j.guarantee.premiumUsd, scope: GUARANTEE_SCOPE } : undefined, artifact: artifact as unknown as Record<string, unknown> };
    if (t && t.status !== "COMMITTED") {
      t.status = "COMMITTED";
      t.commitmentId = j.commitmentId;
      t.task.artifacts = [{ artifactId: j.commitmentId, name: "commitment", description: "Signed commitment artifact", parts: [{ kind: "data", data: artifact as unknown as Record<string, unknown> }] }];
      const notice = this.venueMessage(payload, j.taskId, t.task.contextId);
      t.task.status = { state: "completed", timestamp: new Date().toISOString(), message: notice };
      // Notices are enqueued in the same snapshot as the state change: either both persist or neither.
      for (const id of [brokerAgentId, carrierAgentId]) this.enqueue(id, notice, `COMMITTED ${j.commitmentId}`);
    }
    // Multi-tender losers are canceled INSIDE the transaction: their state change and their
    // notices ride in the same snapshot as the winner's commitment.
    const rec = this.state.commitments.get(j.commitmentId)!;
    const canceled = t ? this.cancelSiblings(t, rec) : 0;
    // Audit entries are keyed by commitment id so re-application after a crash never duplicates them,
    // and they are written BEFORE the journal is deleted so a crash cannot lose them.
    if (j.guarantee) this.audit.writeOnce(`guarantee-attached:${j.commitmentId}`, { component: "underwriting", event: "guarantee-attached", outcome: "ALLOWED", taskId: j.taskId, evidence: { guaranteeId, coveredAmountUsd: j.guarantee.coveredAmountUsd, premiumUsd: j.guarantee.premiumUsd, probabilityOfLoss: j.guarantee.probabilityOfLoss, factors: j.guarantee.factors } });
    else if (j.declined) this.audit.writeOnce(`guarantee-declined:${j.commitmentId}`, { component: "underwriting", event: "guarantee-declined", outcome: "INFO", reasonCode: j.declined.reasonCode, taskId: j.taskId, evidence: { ...j.declined.evidence, proceededUnguaranteed: true } });
    this.audit.writeOnce(`commit:${j.commitmentId}`, { component: "venue.commitment", event: "commit", outcome: "ALLOWED", taskId: j.taskId, contextId: t?.task.contextId, evidence: { commitmentId: j.commitmentId, termsHash: artifact.termsHash, rateUsd: terms.rateUsd, guaranteed: !!guaranteeId, ledgerSeq: entry.seq, mode, siblingsCanceled: canceled } });
    this.state.persist();
    this.crashIf("after-apply");
    this.state.deleteJournal(j.commitmentId);
    await this.flushOutbox();
  }

  // ---------------------------------------------------------------- recovery

  /**
   * Run once at startup, before serving. Reconciles the journal against the
   * ledger, finishes in-flight commits, and re-delivers owed notices.
   */
  async recover(): Promise<{ applied: string[]; aborted: string[]; retried: string[]; redelivered: number; siblingsCanceled: number; downtimeMs: number; shifted: number }> {
    // Read the heartbeat before anything below persists (and refreshes it).
    const lastAliveAt = this.state.lastAliveAt;
    const deliveredBefore = this.delivered;
    const applied: string[] = [];
    const aborted: string[] = [];
    const retried: string[] = [];
    for (const j of this.state.readJournals()) {
      if (j.kind === "ROOT_ROTATION") {
        const onLedger = this.ledger.find((e) => e.type === "ROOT_ROTATION" && (e.payload as { rootEvent?: RootEvent }).rootEvent?.rootKid === j.event.rootKid);
        if (onLedger) {
          await this.applyRootRotation(j, onLedger, "recovery");
          applied.push(j.commitmentId);
        } else {
          this.state.deleteJournal(j.commitmentId);
          aborted.push(j.commitmentId);
        }
        continue;
      }
      if (j.kind === "KEY_ROTATION") {
        const onLedger = this.ledger.find((e) => e.type === "KEY_ROTATION" && (e.payload as { cert?: VenueKeyCert }).cert?.kid === j.cert.kid);
        if (onLedger) {
          await this.applyKeyRotation(j, onLedger, "recovery");
          applied.push(j.commitmentId);
        } else {
          this.state.deleteJournal(j.commitmentId);
          aborted.push(j.commitmentId);
        }
        continue;
      }
      const wantType = j.kind === "COMMIT" ? "COMMITMENT" : "VOID";
      const onLedger = this.ledger.find((e) => e.type === wantType && (e.payload as { commitmentId?: string }).commitmentId === j.commitmentId);
      if (onLedger) {
        // Past the commit point: finish applying. Every step is idempotent.
        if (j.kind === "COMMIT") await this.applyCommit(j, onLedger, "recovery");
        else await this.applyVoid(j, onLedger, "recovery");
        applied.push(j.commitmentId);
      } else {
        // Before the commit point: nothing happened. Discard the intent.
        this.state.deleteJournal(j.commitmentId);
        aborted.push(j.commitmentId);
        this.audit.write({ component: "venue.commitment", event: "recovery", outcome: "INFO", taskId: j.kind === "COMMIT" ? j.taskId : undefined, evidence: { commitAborted: j.commitmentId, reason: "journal without ledger entry — crash before the commit point" } });
      }
    }
    // Tasks that hold both acceptances but never reached a commitment: the crash hit between
    // persisting the second acceptance and the commit point. Re-attempt from the persisted state.
    for (const t of this.state.tasks.values()) {
      if (TERMINAL_STATES.includes(t.task.status.state)) continue;
      if (!t.acceptances[t.brokerAgentId] || !t.acceptances[t.carrierAgentId]) continue;
      if (this.state.commitments.has(t.commitmentId ?? "")) continue;
      const accept = dataPart(t.acceptances[t.carrierAgentId]!) as unknown as AcceptPayload;
      retried.push(t.task.id);
      await this.commit(t, accept.terms);
    }
    // Every credential status the issuer holds must be on the ledger (a crash between the two leaves it off).
    let statusesReconciled = 0;
    for (const st of this.issuer.statusList()) {
      const before = this.ledger.head.seq;
      this.recordCredentialStatus(st);
      if (this.ledger.head.seq !== before) statusesReconciled += 1;
    }
    if (statusesReconciled) this.audit.write({ component: "ledger", event: "recovery", outcome: "INFO", evidence: { credentialStatusesReconciled: statusesReconciled } });
    // Multi-tender losers of any ACTIVE commitment that are somehow still open (a crash between the
    // snapshot and the journal delete cannot cause this any more, but recovery must not depend on that).
    let siblingsCanceled = 0;
    for (const c of this.state.commitments.values()) {
      if (c.status !== "ACTIVE") continue;
      siblingsCanceled += this.cancelSiblings({ task: { id: c.taskId }, brokerAgentId: c.brokerAgentId }, c);
    }
    // The venue's downtime must not count against the party it was waiting on: shift every open
    // task's reply clock forward by the time this venue was dead.
    const now = Date.now();
    const downtimeMs = lastAliveAt ? Math.max(0, now - new Date(lastAliveAt).getTime()) : 0;
    let shifted = 0;
    if (downtimeMs > 0) {
      for (const t of this.state.tasks.values()) {
        if (TERMINAL_STATES.includes(t.task.status.state)) continue;
        t.awaitingSince = new Date(new Date(t.awaitingSince).getTime() + downtimeMs).toISOString();
        shifted += 1;
      }
    }
    this.state.persist();
    await this.flushOutbox();
    const redelivered = this.delivered - deliveredBefore;
    if (applied.length || aborted.length || retried.length || redelivered || siblingsCanceled || shifted) {
      this.audit.write({ component: "venue.commitment", event: "recovery", outcome: "INFO", evidence: { applied, aborted, retriedTasks: retried, redelivered, siblingsCanceled, downtimeMs, replyClocksShifted: shifted, outboxPending: this.state.outbox.length, deadLetter: this.state.deadLetter.length } });
    }
    return { applied, aborted, retried, redelivered, siblingsCanceled, downtimeMs, shifted };
  }

  /** SIM-ONLY fault injection: die at a named point inside a commit. Never present in a deployed venue. */
  simFault?: { crashAt?: string; holdOutbox?: boolean; equivocate?: { witnessIds: string[]; fromSeq: number } };
  /** SIM-ONLY: receipts the fooled witness gave for heads of the fork view — the venue's second book. */
  private forkReceipts: Record<string, WitnessReceipt[]> = {};

  /** The ledger as seen by a given requester: the real chain, or (under the equivocation fault) the fork shown to one witness. */
  ledgerViewFor(requester?: string): LedgerEntry[] {
    const f = this.simFault?.equivocate;
    if (f && requester && f.witnessIds.includes(requester)) return this.ledger.forkView(f.fromSeq, (e) => e.type === "CREDENTIAL_STATUS");
    return this.ledger.all();
  }
  private isForkedFor(requester?: string): boolean {
    const f = this.simFault?.equivocate;
    return !!f && !!requester && f.witnessIds.includes(requester);
  }
  private crashIf(point: string) {
    if (process.env.SIM_MODE === "1" && this.simFault?.crashAt === point) {
      this.audit.write({ component: "sim", event: "crash", outcome: "INFO", evidence: { crashAt: point } });
      process.exit(137);
    }
  }

  /** An ACTIVE commitment in which `brokerAgentId` is the broker for this physical load, if any. */
  private activeCommitmentForLoad(brokerAgentId: string, loadRef: string, fingerprint: string): CommitmentRecord | undefined {
    for (const c of this.state.commitments.values()) {
      if (c.status === "ACTIVE" && c.brokerAgentId === brokerAgentId && (c.loadRef === loadRef || c.loadFingerprint === fingerprint)) return c;
    }
    return undefined;
  }

  /**
   * Multi-tender: once one carrier's commitment is recorded, every other open
   * negotiation for the same load is canceled. Mutates state and enqueues
   * notices only — the caller persists. Idempotent (terminal tasks are skipped),
   * so recovery can call it for every ACTIVE commitment.
   */
  private cancelSiblings(winner: NegotiationTask | { task: { id: string }; brokerAgentId: string }, rec: CommitmentRecord): number {
    let n = 0;
    for (const s of this.state.tasks.values()) {
      if (s.task.id === winner.task.id || s.brokerAgentId !== winner.brokerAgentId) continue;
      if (TERMINAL_STATES.includes(s.task.status.state)) continue;
      if (s.loadRef !== rec.loadRef && loadFingerprint(s.load) !== rec.loadFingerprint) continue;
      this.terminate(s, "LOAD_ALREADY_COMMITTED", "venue.commitment", { agentId: s.brokerAgentId, winningCommitmentId: rec.commitmentId, canceledTaskId: s.task.id, canceledCounterparty: s.carrierAgentId, round: s.round, stateAtCancel: s.status }, s.brokerAgentId, "CANCELED");
      n += 1;
    }
    return n;
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
    this.terminate(t, reasonCode, refusedBy, evidence, subject, disposition);
    this.state.persist();
    await this.flushOutbox();
  }

  /**
   * Terminate a negotiation: mutate the task, write the (idempotent) audit
   * entry, enqueue notices. Does NOT persist or flush — the caller decides
   * what else rides in the same snapshot. The party the refusal is ABOUT
   * (`subject`) gets the full evidence; the other party gets a redacted
   * notice (see DECISIONS.md Q2).
   */
  private terminate(t: NegotiationTask, reasonCode: ReasonCode, refusedBy: Component, evidence: Record<string, unknown>, subject?: string, disposition: "FAILED" | "CANCELED" = "FAILED") {
    t.status = reasonCode === "NEGOTIATION_WALKAWAY" ? "REJECTED" : disposition === "CANCELED" ? "CANCELED" : "FAILED";
    t.outcome = { reasonCode, refusedBy, evidence, guaranteeWouldHavePaid: guaranteeWouldHavePaid(reasonCode) };
    const subjectId = subject ?? (typeof evidence.agentId === "string" ? evidence.agentId : typeof evidence.acceptedBy === "string" ? evidence.acceptedBy : typeof evidence.by === "string" ? evidence.by : undefined);
    const full = this.venueMessage({ type: "REFUSED", loadRef: t.loadRef, reasonCode, refusedBy, evidence, disposition }, t.task.id, t.task.contextId);
    const redacted = this.venueMessage({ type: "REFUSED", loadRef: t.loadRef, reasonCode, refusedBy, evidence: redactForCounterparty(evidence, subjectId), disposition }, t.task.id, t.task.contextId);
    t.task.status = { state: disposition === "CANCELED" ? "canceled" : "failed", timestamp: new Date().toISOString(), message: full };
    this.audit.writeOnce(`terminated:${t.task.id}`, { component: refusedBy, event: "negotiation-terminated", outcome: "REFUSED", reasonCode, taskId: t.task.id, contextId: t.task.contextId, subject: subjectId, evidence });
    for (const id of [t.brokerAgentId, t.carrierAgentId]) if (this.state.agents.has(id)) this.enqueue(id, !subjectId || id === subjectId ? full : redacted, `REFUSED ${reasonCode}`);
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

  // ------------------------------------------------------------- outbox
  //
  // Every message the venue owes an agent goes through a persisted outbox.
  // Enqueue happens inside the same snapshot as the state change that caused
  // it; delivery is at-least-once and agents dedupe by messageId.

  private enqueue(toAgentId: string, m: Message, note?: string) {
    this.state.outbox.push({ id: randomUUID(), toAgentId, message: m, enqueuedAt: new Date().toISOString(), attempts: 0, nextAttemptAt: new Date().toISOString(), note });
  }

  private flushing = false;
  /** Successful deliveries since process start (recovery reports how many notices it owed). */
  private delivered = 0;
  async flushOutbox(): Promise<void> {
    if (this.flushing) return;
    this.flushing = true;
    try {
      const now = Date.now();
      const blocked = new Set<string>(); // per-recipient ordering: a failed delivery blocks only that agent's later notices
      for (const n of [...this.state.outbox]) {
        if (blocked.has(n.toAgentId) || new Date(n.nextAttemptAt).getTime() > now) continue;
        // SIM fault: the venue cannot push its own notices (COMMITTED/REFUSED/VOIDED); forwards still flow.
        if (this.simFault?.holdOutbox && (n.message.metadata as { senderAgentId?: string } | undefined)?.senderAgentId === "venue") {
          blocked.add(n.toAgentId);
          continue;
        }
        const to = this.state.agents.get(n.toAgentId);
        if (!to) {
          this.state.outbox = this.state.outbox.filter((x) => x.id !== n.id);
          continue;
        }
        let ok = false;
        try {
          const res = await rpcCall(`${to.url}/a2a`, "message/send", { message: n.message });
          ok = !res.error;
          if (res.error) this.audit.write({ component: "venue.routing", event: "deliver", outcome: "INFO", subject: to.agentId, taskId: n.message.taskId, evidence: { error: res.error, attempt: n.attempts + 1 } });
        } catch (e) {
          this.audit.write({ component: "venue.routing", event: "deliver", outcome: "INFO", subject: to.agentId, taskId: n.message.taskId, evidence: { error: String(e).slice(0, 120), attempt: n.attempts + 1 } });
        }
        if (ok) {
          this.delivered += 1;
          // Logged only once actually delivered, so the wire log never shows a delivery that did not happen.
          this.state.logMessage("OUT", n.message, `to ${to.agentId}`);
          this.state.outbox = this.state.outbox.filter((x) => x.id !== n.id);
        } else {
          n.attempts += 1;
          n.nextAttemptAt = new Date(Date.now() + Math.min(30_000, 250 * 2 ** n.attempts)).toISOString();
          blocked.add(n.toAgentId);
          if (n.attempts >= this.config.outboxMaxAttempts) {
            // Give up pushing; the agent can still pull the task via tasks/get.
            this.state.outbox = this.state.outbox.filter((x) => x.id !== n.id);
            this.state.deadLetter.push(n);
            this.audit.write({ component: "venue.routing", event: "deliver-abandoned", outcome: "INFO", subject: to.agentId, taskId: n.message.taskId, evidence: { attempts: n.attempts, note: n.note, recoverable: "agent may pull via tasks/get" } });
          }
        }
        this.state.persist();
      }
    } finally {
      this.flushing = false;
    }
  }

  private async deliver(to: RegisteredAgent, m: Message) {
    this.enqueue(to.agentId, m);
    this.state.persist();
    await this.flushOutbox();
  }

  // ------------------------------------------------- post-commitment checks

  /** Re-verify both parties of every ACTIVE commitment whose pickup is still ahead. A scheduler would run this; the sim triggers it. */
  /** Re-verify both parties of every ACTIVE commitment whose pickup is still ahead. A scheduler would run this; the sim triggers it. */
  async prePickupChecks(now = new Date()): Promise<CommitmentRecord[]> {
    const voided: CommitmentRecord[] = [];
    for (const c of this.state.commitments.values()) {
      if (c.status !== "ACTIVE" || new Date(c.pickupWindowStart) < now) continue;
      for (const side of ["broker", "carrier"] as const) {
        const agentId = side === "broker" ? c.brokerAgentId : c.carrierAgentId;
        const signing = c.artifact.credentials[side];
        // A routine rotation must NOT void the deal: check the party's CURRENT credential for standing,
        // and the SIGNING credential only for a compromise declared effective before the signature.
        const current = this.issuer.currentInLineage(signing.credentialId) ?? signing;
        const cv = verifyCredential(current, { issuerKeys: this.venueKeys(), status: this.issuer.status(current.credentialId), now });
        const lv = cv.ok ? liveCheck(this.registry, current, { now, hazmat: c.artifact.terms.load.hazmat }) : undefined;
        const st = signatureTrustedAt(signing, new Date((c.artifact.acceptances[side].metadata as SignedMeta).ts), this.issuer.status(signing.credentialId));
        const bad = !cv.ok ? cv : lv && !lv.ok ? lv : !st.ok ? st : undefined;
        if (!bad) continue;
        void agentId;
        const reasonCode: ReasonCode = bad.reasonCode === "CREDENTIAL_REVOKED" ? "CREDENTIAL_REVOKED_PRE_PICKUP" : bad.reasonCode!;
        const evidence = { commitmentId: c.commitmentId, party: side, agentId: side === "broker" ? c.brokerAgentId : c.carrierAgentId, pickupWindowStart: c.pickupWindowStart, checkedAt: now.toISOString(), underlying: bad.reasonCode, ...bad.evidence };
        // Same transaction shape as commit: journal → one ledger entry (carrying the guarantee release) → idempotent apply.
        const journal: VoidJournal = { kind: "VOID", commitmentId: c.commitmentId, writtenAt: now.toISOString(), reasonCode, evidence };
        this.state.writeJournal(journal);
        const g = c.guaranteeId ? this.underwriting.guaranteeForCommitment(c.commitmentId) : undefined;
        const entry = this.ledger.append("VOID", { commitmentId: c.commitmentId, reasonCode, evidence, guaranteeReleased: g ? { guaranteeId: g.guaranteeId, coveredAmountUsd: g.coveredAmountUsd } : null });
        await this.applyVoid(journal, entry, "live");
        voided.push(c);
        break;
      }
    }
    return voided;
  }

  private async applyVoid(j: VoidJournal, entry: LedgerEntry, mode: "live" | "recovery") {
    const c = this.state.commitments.get(j.commitmentId);
    if (!c) {
      this.state.deleteJournal(j.commitmentId);
      return;
    }
    const day = c.pickupWindowStart.slice(0, 10);
    if (c.guaranteeId) this.underwriting.release(c.guaranteeId, j.reasonCode); // idempotent
    this.exposureFor(c.brokerAgentId).release(c.carrierUsdot, c.rateUsd, day, j.commitmentId);
    this.exposureFor(c.carrierAgentId).release(c.brokerUsdot, c.rateUsd, day, j.commitmentId);
    const first = c.status !== "VOIDED";
    if (first) {
      c.status = "VOIDED";
      c.voided = { at: j.writtenAt, reasonCode: j.reasonCode, evidence: j.evidence };
      const t = this.state.tasks.get(c.taskId);
      if (t) t.outcome = { reasonCode: j.reasonCode, refusedBy: "venue.commitment", evidence: j.evidence, guaranteeWouldHavePaid: guaranteeWouldHavePaid(j.reasonCode) };
      const notice = this.venueMessage({ type: "VOIDED", loadRef: c.loadRef, commitmentId: c.commitmentId, reasonCode: j.reasonCode, evidence: j.evidence }, c.taskId, `ctx_${c.loadRef}`);
      for (const id of [c.brokerAgentId, c.carrierAgentId]) this.enqueue(id, notice, `VOIDED ${c.commitmentId}`);
    }
    this.state.persist();
    this.state.deleteJournal(j.commitmentId);
    if (first) this.audit.write({ component: "venue.commitment", event: j.origin ?? "pre-pickup-check", outcome: "VOIDED", reasonCode: j.reasonCode, taskId: c.taskId, evidence: { ...j.evidence, guaranteeReleased: !!c.guaranteeId, ledgerSeq: entry.seq, mode, guaranteeWouldHavePaid: guaranteeWouldHavePaid(j.reasonCode) } });
    await this.flushOutbox();
  }
}

/** Non-sensitive keys a counterparty may see about a refusal that concerns the other party. */
const COUNTERPARTY_SAFE_KEYS = new Set(["round", "maxRounds", "stage", "atRound", "error", "taskId", "state", "awaiting", "awaitingSince", "waitedMs", "replyTimeoutMs", "lastOffers", "by", "reasonCode", "canceledTaskId"]);

export function redactForCounterparty(evidence: Record<string, unknown>, subjectAgentId: string | undefined): Record<string, unknown> {
  if (!subjectAgentId) return evidence;
  const out: Record<string, unknown> = { redacted: true, concerning: subjectAgentId };
  for (const [k, v] of Object.entries(evidence)) if (COUNTERPARTY_SAFE_KEYS.has(k)) out[k] = v;
  return out;
}
