/**
 * Agent runtime — the equivalent of an A2A SDK. Stateless library code that
 * each agent process instantiates against ITS OWN data directory. It:
 *
 *   - holds the agent's key, credential, mandate and private context
 *   - accepts inbound messages ONLY when signed by the pinned venue key
 *   - runs every outbound offer/accept through the mandate engine first
 *   - keeps its own audit log, exposure book and task store
 *
 * It never receives the counterparty's address, keys, or data directory.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from "node:fs";
import { writeFileAtomic } from "../protocol/fsatomic";
import { join } from "node:path";
import { A2A_PROTOCOL_VERSION, FREIGHT_EXTENSION_URI, RPC_ERR, TERMINAL_STATES, dataPart, signAgentCard, verifyAgentCard, type AgentCard, type Message, type Task } from "../protocol/a2a";
import { hashObject } from "../protocol/canonical";
import { exportPrivateJwk, generateKeyPair, importKeyPair, jwkThumbprint as _jwkThumbprint, signJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { buildMessage, signMessage, verifyMessageSignature, verifyVenueSignature, type SignedMeta, type VenueAttachment } from "../protocol/envelope";
import { termsHash, textDigest, validateNegotiationPayload, type AcceptPayload, type CounterPayload, type LoadSpec, type NegotiationPayload, type RejectPayload, type TenderPayload, type Terms } from "../protocol/freight";
import { AuditLog, type Component } from "../protocol/audit";
import { httpGet, rpcCall, RpcRefusal, startServer, type HttpRoute } from "../protocol/rpc";
import type { Credential, CredentialStatusEntry, MandateEnvelope, RotationAuthorization, RotationClaims, RotationReason } from "../protocol/types";
import { makeResolver, type RootEvent, type VenueKeyCert, type VenueKeyHistory, type VenueKeyResolver } from "../protocol/venue-keys";
import { WitnessCore, emptyWitnessState, type WitnessCoreState, type WitnessPeer } from "../protocol/witness-core";
import { evaluateMandate } from "../mandate/engine";
import { ExposureBook } from "../mandate/exposure";
import { verifyMandate } from "../mandate/sign";
import type { Mandate, MandateAction } from "../mandate/types";
import type { AgentConfig, Decision, LocalTask, NegotiationView, Offer, Strategy } from "./types";

export class AgentRuntime<Ctx extends { canary: string }> {
  readonly kp: KeyPair;
  readonly mandate: Mandate;
  readonly ctx: Ctx;
  readonly audit: AuditLog;
  readonly exposure: ExposureBook;
  readonly envelope?: MandateEnvelope;
  credential?: Credential;
  /** Pinned venue ROOT key (trust-on-first-use, persisted). Operational keys are learned from root-signed certificates. */
  venueRoot?: OkpJwk;
  private venueKeys?: VenueKeyResolver;
  /** @deprecated single-key view kept for readers; verification goes through venueKeys. */
  get venueKey(): OkpJwk | undefined {
    return this.venueRoot;
  }
  private tasks = new Map<string, LocalTask>();
  private readonly comp: { mandate: Component; strategy: Component; runtime: Component };
  /**
   * PARTY WITNESSING. This agent is a witness of its own transactions: it verifies the venue's chain like any
   * witness, signs receipts with its own credential-bound key, and gossips with the independent witnesses its
   * principal chose. The venue cannot control this witness, and the counterparty already trusts its key.
   */
  private witnessState: WitnessCoreState = emptyWitnessState();
  private witnessPeers: WitnessPeer[] = [];
  private partyWitness!: WitnessCore;
  readonly url: string;

  constructor(readonly config: AgentConfig, readonly strategy: Strategy<Ctx>) {
    mkdirSync(config.dataDir, { recursive: true });
    const keyPath = join(config.dataDir, "agent-key.jwk.json");
    if (existsSync(keyPath)) this.kp = importKeyPair(JSON.parse(readFileSync(keyPath, "utf8")));
    else {
      this.kp = generateKeyPair();
      writeFileSync(keyPath, JSON.stringify(exportPrivateJwk(this.kp)));
    }
    this.mandate = JSON.parse(readFileSync(join(config.dataDir, "mandate.json"), "utf8"));
    const mv = verifyMandate(this.mandate);
    if (!mv.ok || this.mandate.principal.kid !== config.principal.publicKey.kid || this.mandate.agentId !== config.agentId) {
      throw new Error(`refusing to start: mandate not validly signed by pinned principal (${mv.error ?? "kid/agentId mismatch"})`);
    }
    const envPath = join(config.dataDir, "envelope.json");
    this.envelope = existsSync(envPath) ? JSON.parse(readFileSync(envPath, "utf8")) : undefined;
    this.ctx = JSON.parse(readFileSync(join(config.dataDir, "private.json"), "utf8"));
    this.audit = new AuditLog(join(config.dataDir, "audit.jsonl"));
    this.exposure = new ExposureBook(join(config.dataDir, "exposure.json"));
    const credPath = join(config.dataDir, "credential.json");
    if (existsSync(credPath)) this.credential = JSON.parse(readFileSync(credPath, "utf8"));
    const tasksPath = join(config.dataDir, "tasks.json");
    if (existsSync(tasksPath)) this.tasks = new Map(Object.entries(JSON.parse(readFileSync(tasksPath, "utf8"))));
    const seenPath = join(config.dataDir, "inbox-seen.json");
    if (existsSync(seenPath)) this.seenInbound = JSON.parse(readFileSync(seenPath, "utf8"));
    this.url = `http://127.0.0.1:${config.port}`;
    const r = config.role;
    this.comp = { mandate: `agent.${r}.mandate`, strategy: `agent.${r}.strategy`, runtime: `agent.${r}.runtime` };
    const self = this;
    const wsPath = join(config.dataDir, "party-witness-state.json");
    if (existsSync(wsPath)) this.witnessState = { ...emptyWitnessState(), ...JSON.parse(readFileSync(wsPath, "utf8")) };
    this.witnessPeers = [...(config.witnessPeers ?? [])];
    this.partyWitness = new WitnessCore({
      witnessId: config.agentId,
      get kp() { return self.kp; },
      venueUrl: config.venueUrl,
      peers: () => this.witnessPeers,
      state: () => this.witnessState,
      persist: () => writeFileAtomic(wsPath, JSON.stringify(this.witnessState, null, 2)),
      log: (event, outcome, evidence, reasonCode) => this.audit.write({ component: this.comp.runtime, event: `party-witness:${event}`, outcome, evidence, reasonCode: reasonCode as never }),
    });
  }

  /** Witness the venue's current head (verify it extends what this agent last cosigned; sign; submit), then gossip with the principal's chosen witnesses. */
  async witnessNow(): Promise<{ poll: Awaited<ReturnType<WitnessCore["poll"]>>; gossip: Awaited<ReturnType<WitnessCore["gossip"]>> }> {
    // The witness signs with whatever key this agent holds NOW (rotation-safe: receipts name the kid via the JWS header).
    const poll = await this.partyWitness.poll();
    const gossip = await this.partyWitness.gossip();
    return { poll, gossip };
  }

  private persistTasks() {
    writeFileAtomic(join(this.config.dataDir, "tasks.json"), JSON.stringify(Object.fromEntries(this.tasks), null, 2));
  }

  /** Inbound messageIds already processed. The venue's outbox is at-least-once; this makes it effectively once. */
  private seenInbound: string[] = [];
  private markSeen(messageId: string) {
    this.seenInbound.push(messageId);
    if (this.seenInbound.length > 1000) this.seenInbound = this.seenInbound.slice(-1000);
    writeFileAtomic(join(this.config.dataDir, "inbox-seen.json"), JSON.stringify(this.seenInbound));
  }

  agentCard(): AgentCard {
    return buildAgentCard(this.config, this.kp, this.url);
  }

  // ------------------------------------------------------------- onboarding

  async pinVenue() {
    const card = await httpGet<AgentCard>(`${this.config.venueUrl}/.well-known/agent-card.json`);
    const v = verifyAgentCard(card);
    if (!v.ok || !v.jwk) throw new Error(`venue agent card does not verify: ${v.error}`);
    const vk = card.metadata?.venueKeys as { rootPublicKey?: OkpJwk; rootLog?: RootEvent[]; cert?: VenueKeyCert } | undefined;
    if (!vk?.rootPublicKey || !vk.cert) throw new Error("venue agent card carries no key hierarchy");
    const pinnedPath = join(this.config.dataDir, "venue-root.pinned.json");
    if (existsSync(pinnedPath)) {
      // Trust continues from the root this agent pinned. If the venue now names a different root, the ONLY
      // acceptable proof is a pre-rotation chain from the pinned root to it (each step: commitment + new
      // root's signature). Anything else is refused; a stolen root cannot produce that chain.
      const pinned = JSON.parse(readFileSync(pinnedPath, "utf8")) as OkpJwk;
      this.venueRoot = pinned;
      this.venueKeys = makeResolver(pinned, { rootLog: vk.rootLog ?? [] });
      if (pinned.x !== vk.rootPublicKey.x && !this.venueKeys.rootTrusted(vk.rootPublicKey.kid ?? "")) {
        try { await this.refreshVenueKeys(); } catch { /* refusal below */ }
        if (!this.venueKeys.rootTrusted(vk.rootPublicKey.kid ?? "")) throw new Error("venue names a root this agent cannot reach from its pinned root by pre-rotation; refusing to re-pin");
      }
      this.repinIfRotated();
    } else {
      // Trust on first use for the ROOT.
      this.venueRoot = vk.rootPublicKey;
      writeFileAtomic(pinnedPath, JSON.stringify(vk.rootPublicKey));
      this.venueKeys = makeResolver(vk.rootPublicKey, { rootLog: vk.rootLog ?? [] });
    }
    if (!this.venueKeys.add(vk.cert)) throw new Error("venue operational key certificate is not signed by a trusted venue root");
    if (vk.cert.kid !== v.jwk.kid && vk.cert.publicKey.x !== v.jwk.x) throw new Error("venue agent card is not signed by its certified operational key");
    await this.refreshVenueKeys();
  }

  /** If the walk from the pinned root now ends at a newer root, pin that one (a restart then walks from it). */
  private repinIfRotated() {
    if (!this.venueKeys || !this.venueRoot) return;
    const cur = this.venueKeys.currentRoot;
    if (cur.x === this.venueRoot.x) return;
    const from = this.venueRoot.kid?.slice(0, 12);
    this.venueRoot = cur;
    writeFileAtomic(join(this.config.dataDir, "venue-root.pinned.json"), JSON.stringify(cur));
    this.audit.write({ component: this.comp.runtime, event: "venue-root-rotated", outcome: "INFO", evidence: { from, to: cur.kid?.slice(0, 12), note: "re-pinned via a pre-rotation chain from the previously pinned root" } });
  }

  /** Fetch the venue's published key history; accept only certificates/revocations signed by the pinned root. */
  async refreshVenueKeys(): Promise<{ kids: string[] }> {
    if (!this.venueKeys) throw new Error("venue not pinned");
    const h = await httpGet<VenueKeyHistory>(`${this.config.venueUrl}/.well-known/venue-keys.json`);
    const rootChanged = this.venueKeys.extendRoots(h.rootLog ?? []);
    let added = 0;
    for (const c of h.certs) if (this.venueKeys.add(c)) added += 1;
    for (const r of h.revocations) this.venueKeys.revoke(r);
    writeFileAtomic(join(this.config.dataDir, "venue-keys.cache.json"), JSON.stringify({ rootLog: h.rootLog, certs: h.certs, revocations: h.revocations }));
    if (rootChanged) this.repinIfRotated();
    if (added || rootChanged) this.audit.write({ component: this.comp.runtime, event: "venue-keys-refreshed", outcome: "INFO", evidence: { roots: this.venueKeys.rootKids().map((k) => k.slice(0, 12)), kids: this.venueKeys.kids().map((k) => k.slice(0, 12)), rootChanged } });
    return { kids: this.venueKeys.kids() };
  }

  /** Resolve a venue signing key by kid; on an unfamiliar kid, refresh once from the venue (root-verified) before giving up. */
  private async resolveVenueKey(kid: string): Promise<OkpJwk | undefined> {
    if (!this.venueKeys) return undefined;
    const k = this.venueKeys.key(kid);
    if (k) return k;
    try {
      await this.refreshVenueKeys();
    } catch (e) {
      this.audit.write({ component: this.comp.runtime, event: "venue-keys-refresh-failed", outcome: "INFO", evidence: { error: String(e).slice(0, 120) } });
    }
    return this.venueKeys.key(kid);
  }

  private venueSignatureOk(m: Message): { ok: boolean; error?: string; kid?: string } {
    if (!this.venueKeys) return { ok: false, error: "venue not pinned" };
    const res = verifyVenueSignature(m, (kid) => this.venueKeys!.key(kid));
    if (res.ok && res.kid) {
      const why = this.venueKeys.untrustedAt(res.kid, new Date());
      if (why) return { ok: false, error: why, kid: res.kid };
    }
    return res;
  }

  async onboard(): Promise<{ ok: true; credential: Credential } | { ok: false; reasonCode: string; evidence: unknown }> {
    if (!this.venueKey) await this.pinVenue();
    const res = await rpcCall<{ credential: Credential }>(`${this.config.venueUrl}/a2a`, "venue/onboard", {
      card: this.agentCard(),
      claimed: { usdot: this.config.entity.usdot, mc: this.config.entity.mc },
      proofOfControl: this.config.proofOfControl,
      agentUrl: this.url,
      envelope: this.envelope,
    });
    if (res.error) {
      const d = res.error.data as { reasonCode?: string; evidence?: unknown } | undefined;
      this.audit.write({ component: this.comp.runtime, event: "onboard", outcome: "REFUSED", evidence: { reasonCode: d?.reasonCode, error: res.error.message } });
      return { ok: false, reasonCode: d?.reasonCode ?? "UNKNOWN", evidence: d?.evidence };
    }
    this.credential = res.result!.credential;
    writeFileAtomic(join(this.config.dataDir, "credential.json"), JSON.stringify(this.credential, null, 2));
    this.audit.write({ component: this.comp.runtime, event: "onboard", outcome: "ALLOWED", evidence: { credentialId: this.credential.credentialId, expiresAt: this.credential.expiresAt } });
    return { ok: true, credential: this.credential };
  }

  // ---------------------------------------------------------------- key rotation
  //
  // Two steps, because the authority to rotate is not this process's to give:
  //   prepare  — generate the next key and hand its public half to the principal
  //   submit   — send the principal's signed authorization (or proof of control)
  //              with the new card; on success, swap keys atomically
  // An agent that tries to authorize its own rotation (CURRENT_KEY_ONLY) is refused by the venue.

  private nextKp?: KeyPair;
  rotatePrepare(): { credentialId: string; newKid: string; newPublicKey: OkpJwk } {
    if (!this.credential) throw new Error("not onboarded");
    this.nextKp = generateKeyPair();
    writeFileAtomic(join(this.config.dataDir, "agent-key.next.jwk.json"), JSON.stringify(exportPrivateJwk(this.nextKp)));
    this.audit.write({ component: this.comp.runtime, event: "rotate-prepare", outcome: "INFO", evidence: { currentKid: this.kp.kid, newKid: this.nextKp.kid } });
    return { credentialId: this.credential.credentialId, newKid: this.nextKp.kid, newPublicKey: this.nextKp.publicJwk };
  }

  async rotateSubmit(input: { authorization: RotationAuthorization | { kind: "CURRENT_KEY_ONLY" }; claims?: RotationClaims; reason: RotationReason; compromisedAt?: string }): Promise<{ ok: true; credential: Credential; superseded: CredentialStatusEntry } | { ok: false; reasonCode: string; evidence: unknown }> {
    if (!this.credential || !this.nextKp) throw new Error("call rotatePrepare first");
    // The claims are what the authorizer signed; this process forwards them verbatim. Only a
    // CURRENT_KEY_ONLY attempt builds and signs its own — the thing the venue must refuse.
    const claims: RotationClaims = input.claims ?? { credentialId: this.credential.credentialId, newKid: this.nextKp.kid, ts: new Date().toISOString(), reason: input.reason, compromisedAt: input.compromisedAt };
    const authorization: RotationAuthorization = input.authorization.kind === "CURRENT_KEY_ONLY" ? { kind: "CURRENT_KEY_ONLY", jws: signJws(claims, this.kp, { typ: "rotation+jws" }, true) } : input.authorization;
    const newCard = buildAgentCard(this.config, this.nextKp, this.url);
    const res = await rpcCall<{ credential: Credential; superseded: CredentialStatusEntry }>(`${this.config.venueUrl}/a2a`, "venue/rotate", { credentialId: this.credential.credentialId, newCard, authorization, claims });
    if (res.error) {
      const d = (res.error.data ?? {}) as { reasonCode?: string; evidence?: unknown };
      this.audit.write({ component: this.comp.runtime, event: "rotate", outcome: "REFUSED", evidence: { reasonCode: d.reasonCode, authorization: authorization.kind, reason: input.reason, currentKid: this.kp.kid, attemptedKid: this.nextKp.kid } });
      return { ok: false, reasonCode: d.reasonCode ?? String(res.error.code), evidence: d.evidence };
    }
    const oldKid = this.kp.kid;
    this.installKey(this.nextKp, res.result!.credential);
    this.nextKp = undefined;
    const nextPath = join(this.config.dataDir, "agent-key.next.jwk.json");
    if (existsSync(nextPath)) unlinkSync(nextPath);
    this.audit.write({ component: this.comp.runtime, event: "rotate", outcome: "ALLOWED", evidence: { reason: input.reason, authorization: authorization.kind, oldKid, newKid: this.kp.kid, oldCredentialId: res.result!.superseded.credentialId, newCredentialId: res.result!.credential.credentialId, graceUntil: res.result!.superseded.graceUntil } });
    return { ok: true, credential: res.result!.credential, superseded: res.result!.superseded };
  }

  /** Make `kp` + `credential` this agent's identity: key file first (atomic), then the credential. The old private key is overwritten, not kept. */
  private installKey(kp: KeyPair, credential: Credential) {
    writeFileAtomic(join(this.config.dataDir, "agent-key.jwk.json"), JSON.stringify(exportPrivateJwk(kp)));
    (this as { kp: KeyPair }).kp = kp;
    this.credential = credential;
    writeFileAtomic(join(this.config.dataDir, "credential.json"), JSON.stringify(credential, null, 2));
  }

  // ---------------------------------------------------------------- outbound

  private bearer(method: string, taskId?: string): string {
    return signJws({ credentialId: this.credential?.credentialId, ts: new Date().toISOString(), method, taskId }, this.kp, { typ: "agent-bearer+jws" });
  }

  private identity() {
    return {
      agentId: this.config.rogue?.presentAgentId ?? this.config.agentId,
      credentialId: this.config.rogue?.presentCredentialId ?? this.credential?.credentialId ?? "unonboarded",
      from: { agentId: this.config.rogue?.presentAgentId ?? this.config.agentId, usdot: this.config.entity.usdot, mc: this.config.entity.mc },
    };
  }

  /**
   * Sign and send a negotiation payload to the venue. Three ways this agent
   * can learn the outcome, tried in order, all idempotent:
   *   1. SYNC ACK  — the Task the venue returns; if it is already terminal
   *                  (the venue committed while answering), its status message
   *                  is processed right here.
   *   2. PULL      — if a retry was answered NONCE_REUSED, the venue processed
   *                  the original before the connection died; tasks/get tells
   *                  us what it did.
   *   3. PUSH      — the venue's outbox delivers the notice to /a2a; deduped.
   */
  async send(data: NegotiationPayload, taskId?: string, contextId?: string): Promise<{ task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown } }> {
    const id = this.identity();
    const m = signMessage(buildMessage({ role: "user", data: data as unknown as Record<string, unknown>, taskId, contextId, senderAgentId: id.agentId, credentialId: id.credentialId }), this.kp);
    const r = await this.sendRaw(m);
    if (r.duplicate && taskId) await this.pullTask(taskId, "pull-after-retry");
    else if (r.task && taskId) await this.ingestTask(r.task, "sync-ack");
    return r;
  }

  /** Fetch a task from the venue and, if it is terminal, process its status message as if it had been pushed. */
  async pullTask(taskId: string, source: "pull-after-retry" | "reconcile" | "control"): Promise<boolean> {
    let task: Task | undefined;
    try {
      task = await this.getTask(taskId);
    } catch (e) {
      this.audit.write({ component: this.comp.runtime, event: "pull-failed", outcome: "INFO", taskId, evidence: { source, error: String(e).slice(0, 120) } });
      return false;
    }
    if (!task) return false;
    return this.ingestTask(task, source);
  }

  /** A terminal Task carries the venue-signed COMMITTED/REFUSED/VOIDED notice in status.message. Process it exactly once. */
  private async ingestTask(task: Task, source: string): Promise<boolean> {
    if (!TERMINAL_STATES.includes(task.status.state) || !task.status.message) return false;
    const m = task.status.message;
    if (!this.venueKeys) return false;
    let vs = this.venueSignatureOk(m);
    if (!vs.ok && vs.kid && !this.venueKeys.key(vs.kid)) {
      await this.resolveVenueKey(vs.kid);
      vs = this.venueSignatureOk(m);
    }
    if (!vs.ok) {
      this.audit.write({ component: this.comp.runtime, event: "task-notice", outcome: "REFUSED", reasonCode: "ENVELOPE_NOT_FROM_VENUE", taskId: task.id, evidence: { source, error: vs.error } });
      return false;
    }
    if (this.seenInbound.includes(m.messageId)) return false;
    this.markSeen(m.messageId);
    this.audit.write({ component: this.comp.runtime, event: "task-notice", outcome: "INFO", taskId: task.id, evidence: { source, state: task.status.state, messageId: m.messageId } });
    await this.process(m);
    return true;
  }

  /** Pull every task this agent still considers OPEN. Runs on a timer; the sim can trigger it. */
  async reconcile(source: "reconcile" | "control" = "reconcile"): Promise<string[]> {
    const done: string[] = [];
    for (const lt of this.tasks.values()) {
      if (lt.status !== "OPEN") continue;
      if (await this.pullTask(lt.taskId, source)) done.push(lt.taskId);
    }
    return done;
  }

  /**
   * Send an already-signed message verbatim. Retries on transport failure
   * (venue unreachable / connection dropped). Because the nonce is inside the
   * signed surface, a retry is exactly idempotent: if the venue had already
   * processed the message before the connection died, it answers NONCE_REUSED,
   * which a retry treats as "delivered".
   */
  async sendRaw(m: Message): Promise<{ task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown; guaranteeWouldHavePaid?: string }; duplicate?: boolean }> {
    let res: Awaited<ReturnType<typeof rpcCall<Task>>> | undefined;
    let attempt = 0;
    for (;;) {
      try {
        res = await rpcCall<Task>(`${this.config.venueUrl}/a2a`, "message/send", { message: m });
        break;
      } catch (e) {
        attempt += 1;
        this.audit.write({ component: this.comp.runtime, event: "send-transport-failure", outcome: "INFO", taskId: m.taskId, evidence: { attempt, error: String(e).slice(0, 120) } });
        if (attempt >= 6) return { refusal: { reasonCode: "TRANSPORT_FAILURE", refusedBy: "network", evidence: String(e) } };
        await new Promise((r) => setTimeout(r, 200 * 2 ** (attempt - 1)));
      }
    }
    if (res.error && attempt > 0 && (res.error.data as { reasonCode?: string } | undefined)?.reasonCode === "NONCE_REUSED") {
      this.audit.write({ component: this.comp.runtime, event: "send-retry-acknowledged", outcome: "INFO", taskId: m.taskId, evidence: { note: "venue had already processed this message before the connection dropped", attempts: attempt + 1 } });
      return { duplicate: true };
    }
    if (res.error) {
      const d = (res.error.data ?? {}) as { reasonCode?: string; refusedBy?: string; evidence?: unknown; guaranteeWouldHavePaid?: string };
      const refusal = { reasonCode: d.reasonCode ?? String(res.error.code), refusedBy: d.refusedBy ?? "venue", evidence: d.evidence ?? res.error.message, guaranteeWouldHavePaid: d.guaranteeWouldHavePaid };
      this.audit.write({ component: this.comp.runtime, event: "send", outcome: "REFUSED", taskId: m.taskId, evidence: { payloadType: (dataPart(m) as { type?: string })?.type, ...refusal } });
      return { refusal };
    }
    return { task: res.result };
  }

  async getTask(taskId: string): Promise<Task | undefined> {
    const res = await fetch(`${this.config.venueUrl}/a2a`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${this.bearer("tasks/get", taskId)}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: "1", method: "tasks/get", params: { id: taskId } }),
    });
    const j = (await res.json()) as { result?: Task };
    return j.result;
  }

  // ------------------------------------------------------- mandate guard

  private guard(action: MandateAction, taskId: string | undefined, what: string): boolean {
    const verdict = evaluateMandate(this.mandate.limits, action, this.exposure);
    if (verdict.allowed) {
      this.audit.write({ component: this.comp.mandate, event: what, outcome: "ALLOWED", taskId, evidence: { checked: verdict.checked, rateUsd: action.rateUsd } });
      return true;
    }
    const bypass = !!this.config.rogue?.bypassLocalMandate;
    this.audit.write({ component: this.comp.mandate, event: what, outcome: "REFUSED", reasonCode: verdict.violations[0]!.code, taskId, evidence: { violations: verdict.violations, checked: verdict.checked, mandateId: this.mandate.mandateId, principalKid: this.mandate.principal.kid, bypassedByFaultInjection: bypass } });
    return bypass;
  }

  private offerAction(load: LoadSpec, offer: Offer, round: number, isTender = false): MandateAction {
    return { kind: "OFFER", isTender, rateUsd: offer.rateUsd, miles: load.miles, originState: load.origin.state, destinationState: load.destination.state, equipment: load.equipment, hazmat: load.hazmat, paymentTermsDays: offer.paymentTermsDays, round };
  }

  private forceRate(offer: Offer): Offer {
    return this.config.rogue?.forceRateUsd ? { ...offer, rateUsd: this.config.rogue.forceRateUsd } : offer;
  }

  // ------------------------------------------------------- initiating

  async tender(load: LoadSpec, to: { agentId: string }): Promise<{ taskId?: string; task?: Task; refusal?: unknown; localRefusal?: boolean }> {
    const offer = this.forceRate(this.strategy.openingOffer(load, this.ctx, this.mandate));
    if (!this.guard(this.offerAction(load, offer, 1, true), undefined, "tender")) return { localRefusal: true };
    const id = this.identity();
    const payload: TenderPayload = { type: "TENDER", load, offer, from: id.from, to };
    const r = await this.send(payload);
    if (r.task) {
      const lt: LocalTask = { taskId: r.task.id, contextId: r.task.contextId, loadRef: load.loadRef, load, role: "initiator", counterpartyAgentId: to.agentId, status: "OPEN", round: 1, myLastOffer: offer };
      if (r.task.status.state === "rejected") {
        lt.status = "REFUSED";
        const d = dataPart(r.task.status.message!) as { reasonCode?: string; refusedBy?: string; evidence?: Record<string, unknown> } | undefined;
        lt.outcome = d ? { reasonCode: d.reasonCode!, refusedBy: d.refusedBy!, evidence: d.evidence ?? {} } : undefined;
        this.audit.write({ component: this.comp.runtime, event: "tender", outcome: "REFUSED", taskId: r.task.id, evidence: { ...lt.outcome } });
      } else {
        this.audit.write({ component: this.comp.strategy, event: "tender", outcome: "INFO", taskId: r.task.id, evidence: { loadRef: load.loadRef, rateUsd: offer.rateUsd, to: to.agentId } });
      }
      this.tasks.set(r.task.id, lt);
      this.persistTasks();
      return { taskId: r.task.id, task: r.task };
    }
    return { refusal: r.refusal };
  }

  // ------------------------------------------------------- inbound

  /** JSON-RPC handler for the agent's own /a2a endpoint. Only the venue may talk to it. */
  async handleRpc(method: string, params: unknown): Promise<unknown> {
    if (method !== "message/send") throw new RpcRefusal(RPC_ERR.METHOD_NOT_FOUND, "method not found");
    const m = (params as { message: Message }).message;
    if (!this.venueKeys) throw new RpcRefusal(RPC_ERR.VENUE_REFUSED, "venue not pinned");
    let vs = this.venueSignatureOk(m);
    if (!vs.ok && vs.kid && !this.venueKeys.key(vs.kid)) {
      // A kid this process has never seen: the venue may have rotated. Learn it from the root-signed history, then re-check.
      await this.resolveVenueKey(vs.kid);
      vs = this.venueSignatureOk(m);
    }
    if (!vs.ok) {
      this.audit.write({ component: this.comp.runtime, event: "inbound", outcome: "REFUSED", reasonCode: "ENVELOPE_NOT_FROM_VENUE", taskId: m.taskId, evidence: { error: vs.error, senderAgentId: (m.metadata as SignedMeta)?.senderAgentId } });
      throw new RpcRefusal(RPC_ERR.VENUE_REFUSED, "ENVELOPE_NOT_FROM_VENUE", { reasonCode: "ENVELOPE_NOT_FROM_VENUE" });
    }
    const meta = m.metadata as SignedMeta;
    if (meta.senderAgentId !== "venue") {
      // Also check the counterparty's own signature against the key the venue attested.
      const cpKey = meta.venue?.counterparty.publicKey;
      const as = cpKey ? verifyMessageSignature(m, cpKey) : { ok: false, error: "no counterparty key in venue attachment" };
      if (!as.ok) {
        this.audit.write({ component: this.comp.runtime, event: "inbound", outcome: "REFUSED", reasonCode: "IDENTITY_SIGNATURE_INVALID", taskId: m.taskId, evidence: { error: as.error } });
        throw new RpcRefusal(RPC_ERR.VENUE_REFUSED, "IDENTITY_SIGNATURE_INVALID");
      }
    }
    // Closed wire schema, enforced here too: even a compromised venue cannot push unbounded or multi-line text into this process.
    const inboundType = (dataPart(m) as { type?: string } | undefined)?.type;
    if (inboundType === "TENDER" || inboundType === "COUNTER" || inboundType === "ACCEPT" || inboundType === "REJECT") {
      const schema = validateNegotiationPayload(dataPart(m));
      if (!schema.ok) {
        this.audit.write({ component: this.comp.runtime, event: "inbound", outcome: "REFUSED", reasonCode: "UNTRUSTED_TEXT_REJECTED", taskId: m.taskId, evidence: { violations: schema.violations } });
        throw new RpcRefusal(RPC_ERR.VENUE_REFUSED, "UNTRUSTED_TEXT_REJECTED", { reasonCode: "UNTRUSTED_TEXT_REJECTED", violations: schema.violations });
      }
    }
    const ack: Task = { kind: "task", id: m.taskId ?? "n/a", contextId: m.contextId ?? "n/a", status: { state: "working", timestamp: new Date().toISOString() } };
    if (this.seenInbound.includes(m.messageId)) {
      this.audit.write({ component: this.comp.runtime, event: "inbound-duplicate", outcome: "INFO", taskId: m.taskId, evidence: { messageId: m.messageId, note: "already processed; acknowledged without re-processing" } });
      return ack;
    }
    this.markSeen(m.messageId);
    setImmediate(() => this.process(m).catch((e) => this.audit.write({ component: this.comp.runtime, event: "process", outcome: "INFO", taskId: m.taskId, evidence: { error: String(e) } })));
    return ack;
  }

  private async process(m: Message) {
    if (this.config.rogue?.dropInbound) {
      this.audit.write({ component: this.comp.runtime, event: "fault-injection", outcome: "INFO", taskId: m.taskId, evidence: { dropInbound: true, note: "acknowledged but not processed" } });
      return;
    }
    if (this.config.thinkMs) await new Promise((r) => setTimeout(r, this.config.thinkMs));
    const data = dataPart(m) as unknown as NegotiationPayload;
    const meta = m.metadata as SignedMeta;
    const att = meta.venue;
    const taskId = att?.taskId ?? m.taskId!;
    const contextId = att?.contextId ?? m.contextId!;
    let lt = this.tasks.get(taskId);

    switch (data.type) {
      case "TENDER": {
        lt = { taskId, contextId, loadRef: data.load.loadRef, load: data.load, role: "responder", counterpartyAgentId: att!.counterparty.agentId, status: "OPEN", round: 1 };
        this.tasks.set(taskId, lt);
        const view: NegotiationView = { taskId, contextId, load: data.load, round: 1, offer: data.offer, counterparty: att!.counterparty };
        const d = this.strategy.onTender(view, this.ctx, this.mandate);
        await this.act(d, view, lt);
        break;
      }
      case "COUNTER": {
        if (!lt) return;
        const load = this.loadFor(lt);
        const round = att!.round;
        lt.round = round;
        // Quarantine: the strategy sees the code, never the text. Only a digest reaches the audit log.
        const view: NegotiationView = { taskId, contextId, load, round, offer: data.offer, noteCode: data.noteCode, myLastOffer: lt.myLastOffer, counterparty: att!.counterparty };
        this.audit.write({ component: this.comp.strategy, event: "counter-received", outcome: "INFO", taskId, evidence: { round, theirRateUsd: data.offer.rateUsd, myLastRateUsd: lt.myLastOffer?.rateUsd, noteCode: data.noteCode, textQuarantined: data.text !== undefined, ...textDigest(data.text) } });
        const d = this.strategy.onCounter(view, this.ctx, this.mandate);
        await this.act(d, view, lt);
        break;
      }
      case "ACCEPT": {
        if (!lt) return;
        const load = this.loadFor(lt);
        const view: NegotiationView = { taskId, contextId, load, round: att!.round, offer: { rateUsd: data.terms.rateUsd, pickup: data.terms.pickup, delivery: data.terms.delivery, paymentTermsDays: data.terms.paymentTermsDays }, myLastOffer: lt.myLastOffer, counterparty: att!.counterparty, guaranteeAvailable: att!.guaranteeAvailable };
        const d = this.strategy.onAcceptRequest(data.terms, view, this.ctx, this.mandate);
        if (d.kind === "REJECT") {
          await this.send(this.rejectPayload(lt, att!.round, d.reasonCode), taskId, contextId);
          lt.status = "REJECTED";
        } else {
          await this.accept(data.terms, view, lt);
        }
        break;
      }
      case "COMMITTED": {
        if (!lt) return;
        if (lt.status === "COMMITTED" && lt.commitmentId === data.commitmentId) {
          this.audit.write({ component: this.comp.runtime, event: "committed-duplicate", outcome: "INFO", taskId, evidence: { commitmentId: data.commitmentId } });
          break;
        }
        lt.status = "COMMITTED";
        lt.commitmentId = data.commitmentId;
        const art = data.artifact as { terms: Terms };
        mkdirSync(join(this.config.dataDir, "commitments"), { recursive: true });
        writeFileAtomic(join(this.config.dataDir, "commitments", `${data.commitmentId}.json`), JSON.stringify(data.artifact, null, 2));
        const cpUsdot = this.config.role === "broker" ? art.terms.carrierEntity.usdot : art.terms.brokerEntity.usdot;
        this.exposure.add(cpUsdot, art.terms.rateUsd, art.terms.pickup.windowStart.slice(0, 10), data.commitmentId);
        this.audit.write({ component: this.comp.runtime, event: "committed", outcome: "ALLOWED", taskId, evidence: { commitmentId: data.commitmentId, rateUsd: art.terms.rateUsd, guarantee: data.guarantee ? { guaranteeId: data.guarantee.guaranteeId, premiumUsd: data.guarantee.premiumUsd } : null, artifactSavedTo: `commitments/${data.commitmentId}.json` } });
        // A party witnesses the head its commitment landed on, and gossips.
        this.witnessNow().catch(() => {});
        break;
      }
      case "REFUSED": {
        if (!lt) return;
        lt.status = data.disposition === "CANCELED" ? "CANCELED" : "REFUSED";
        lt.outcome = { reasonCode: data.reasonCode, refusedBy: data.refusedBy, evidence: data.evidence };
        this.audit.write({ component: this.comp.runtime, event: data.disposition === "CANCELED" ? "canceled-by-venue" : "refused-by-venue", outcome: "INFO", taskId, evidence: { reasonCode: data.reasonCode, refusedBy: data.refusedBy } });
        break;
      }
      case "CREDENTIAL_REISSUED": {
        const c = data.credential as unknown as Credential;
        if (this.credential && c.credentialId === this.credential.credentialId && c.subject.publicKey.x === this.kp.publicJwk.x) {
          this.credential = c;
          writeFileAtomic(join(this.config.dataDir, "credential.json"), JSON.stringify(c, null, 2));
          this.audit.write({ component: this.comp.runtime, event: "credential-reissued", outcome: "INFO", evidence: { credentialId: c.credentialId, issuerKid: c.issuer.kid, reason: data.reason } });
        }
        break;
      }
      case "COMMITMENT_REATTESTED": {
        const p = join(this.config.dataDir, "commitments", `${data.commitmentId}.json`);
        if (existsSync(p)) {
          writeFileAtomic(p, JSON.stringify(data.artifact, null, 2));
          this.audit.write({ component: this.comp.runtime, event: "commitment-reattested", outcome: "INFO", taskId, evidence: { commitmentId: data.commitmentId, attestations: (data.artifact as { venueAttestations?: unknown[] }).venueAttestations?.length, reason: data.reason } });
        }
        break;
      }
      case "VOIDED": {
        if (!lt) return;
        lt.status = "VOIDED";
        lt.outcome = { reasonCode: data.reasonCode, refusedBy: "venue.commitment", evidence: data.evidence };
        const p = join(this.config.dataDir, "commitments", `${data.commitmentId}.json`);
        if (existsSync(p)) {
          const art = JSON.parse(readFileSync(p, "utf8")) as { terms: Terms };
          const cpUsdot = this.config.role === "broker" ? art.terms.carrierEntity.usdot : art.terms.brokerEntity.usdot;
          this.exposure.release(cpUsdot, art.terms.rateUsd, art.terms.pickup.windowStart.slice(0, 10), data.commitmentId);
        }
        this.audit.write({ component: this.comp.runtime, event: "voided-by-venue", outcome: "INFO", taskId, evidence: { commitmentId: data.commitmentId, reasonCode: data.reasonCode } });
        break;
      }
      default:
        break;
    }
    this.persistTasks();
  }

  private loadFor(lt: LocalTask): LoadSpec {
    return lt.load;
  }

  private async act(d: Decision, view: NegotiationView, lt: LocalTask) {
    const id = this.identity();
    if (d.kind === "REJECT") {
      this.audit.write({ component: this.comp.strategy, event: "decision", outcome: "INFO", taskId: view.taskId, evidence: { decision: "REJECT", reasonCode: d.reasonCode, round: view.round } });
      await this.send(this.rejectPayload(lt, view.round, d.reasonCode), view.taskId, view.contextId);
      lt.status = "REJECTED";
      return;
    }
    if (d.kind === "COUNTER") {
      const offer = this.forceRate(d.offer);
      const round = view.round + 1;
      this.audit.write({ component: this.comp.strategy, event: "decision", outcome: "INFO", taskId: view.taskId, evidence: { decision: "COUNTER", round, rateUsd: offer.rateUsd, noteCode: d.noteCode } });
      if (!this.guard(this.offerAction(view.load, offer, round), view.taskId, "counter")) {
        await this.send(this.rejectPayload(lt, view.round, "OUTSIDE_MANDATE"), view.taskId, view.contextId);
        lt.status = "REJECTED";
        return;
      }
      const payload: CounterPayload = { type: "COUNTER", loadRef: lt.loadRef, round, offer, from: id.from, noteCode: d.noteCode, ...(this.config.rogue?.injectText !== undefined ? { text: this.config.rogue.injectText } : {}) };
      lt.myLastOffer = offer;
      lt.round = round;
      await this.send(payload, view.taskId, view.contextId);
      return;
    }
    // ACCEPT the counterparty's offer as it stands
    const terms = this.termsFrom(view, lt);
    await this.accept(terms, view, lt);
  }

  private rejectPayload(lt: LocalTask, round: number, reasonCode: RejectPayload["reasonCode"]): RejectPayload {
    return { type: "REJECT", loadRef: lt.loadRef, round, reasonCode, from: this.identity().from, ...(this.config.rogue?.injectText !== undefined ? { text: this.config.rogue.injectText } : {}) };
  }

  private termsFrom(view: NegotiationView, lt: LocalTask): Terms {
    const me = { agentId: this.config.agentId, usdot: this.config.entity.usdot, mc: this.config.entity.mc };
    const cp = { agentId: view.counterparty.agentId, usdot: view.counterparty.entity.usdot, mc: view.counterparty.entity.mc };
    const broker = this.config.role === "broker" ? me : cp;
    const carrier = this.config.role === "carrier" ? me : cp;
    void lt;
    return {
      loadRef: view.load.loadRef,
      load: view.load,
      rateUsd: view.offer.rateUsd,
      pickup: view.offer.pickup,
      delivery: view.offer.delivery,
      paymentTermsDays: view.offer.paymentTermsDays,
      brokerAgentId: broker.agentId,
      carrierAgentId: carrier.agentId,
      brokerEntity: { usdot: broker.usdot, mc: broker.mc },
      carrierEntity: { usdot: carrier.usdot, mc: carrier.mc },
    };
  }

  private async accept(terms: Terms, view: NegotiationView, lt: LocalTask) {
    const forced = this.forceRate({ rateUsd: terms.rateUsd, pickup: terms.pickup, delivery: terms.delivery, paymentTermsDays: terms.paymentTermsDays });
    const t: Terms = { ...terms, rateUsd: forced.rateUsd };
    const cpIns = this.config.role === "broker" ? view.counterparty.insurance.bipdUsd : view.counterparty.insurance.bondUsd;
    const action: MandateAction = {
      kind: "ACCEPT", rateUsd: t.rateUsd, miles: t.load.miles, originState: t.load.origin.state, destinationState: t.load.destination.state, equipment: t.load.equipment, hazmat: t.load.hazmat,
      paymentTermsDays: t.paymentTermsDays, round: view.round, counterpartyUsdot: view.counterparty.entity.usdot, counterpartyInsuranceUsd: cpIns,
      // First acceptor cannot know yet; the venue enforces requireGuarantee at commitment. Countersigner sees the quote.
      guaranteeAvailable: view.guaranteeAvailable ?? true,
      day: t.pickup.windowStart.slice(0, 10),
    };
    this.audit.write({ component: this.comp.strategy, event: "decision", outcome: "INFO", taskId: view.taskId, evidence: { decision: "ACCEPT", round: view.round, rateUsd: t.rateUsd } });
    if (!this.guard(action, view.taskId, "accept")) {
      await this.send(this.rejectPayload(lt, view.round, "OUTSIDE_MANDATE"), view.taskId, view.contextId);
      lt.status = "REJECTED";
      return;
    }
    const payload: AcceptPayload = { type: "ACCEPT", loadRef: lt.loadRef, round: view.round, terms: t, termsHash: termsHash(t), from: this.identity().from };
    lt.myLastOffer = forced;
    await this.send(payload, view.taskId, view.contextId);
  }

  // ------------------------------------------------------------- server

  async listen() {
    const simMode = process.env.SIM_MODE === "1";
    const ok = (body: unknown) => ({ status: 200, body });
    const routes: Record<string, HttpRoute> = {
      "GET /health": async () => ok({ ok: true, agentId: this.config.agentId, kid: this.kp.kid }),
      "GET /.well-known/agent-card.json": async () => ok(this.agentCard()),
    };
    if (simMode) {
      Object.assign(routes, {
        "POST /control/onboard": async () => ok(await this.onboard()),
        "POST /control/tender": async (_r: unknown, b: unknown) => {
          const { load, to } = b as { load: LoadSpec; to: { agentId: string } };
          return ok(await this.tender(load, to));
        },
        "POST /control/send": async (_r: unknown, b: unknown) => {
          const { data, taskId, contextId } = b as { data: NegotiationPayload; taskId?: string; contextId?: string };
          return ok(await this.send(data, taskId, contextId));
        },
        "POST /control/send-raw": async (_r: unknown, b: unknown) => ok(await this.sendRaw((b as { message: Message }).message)),
        "POST /control/reconcile": async () => ok({ resolved: await this.reconcile("control") }),
        "POST /control/witness/now": async () => ok(await this.witnessNow()),
        "GET /control/witness/status": async () => ok({ witnessId: this.config.agentId, lastCosigned: this.witnessState.lastCosigned ?? null, receipts: this.witnessState.receipts.length, forks: this.witnessState.forks.length, equivocations: this.witnessState.equivocations.length, halted: this.witnessState.halted ?? null, peers: this.witnessPeers.map((p) => p.witnessId) }),
        "GET /control/witness/receipts": async () => ok(this.witnessState.receipts),
        "GET /control/witness/receipt-for": async (req: { url?: string }) => { const seq = Number(new URL(req.url ?? "/", "http://localhost").searchParams.get("seq")); return ok(Number.isInteger(seq) ? this.partyWitness.receiptFor(seq) ?? null : null); },
        "GET /control/witness/equivocations": async () => ok(this.witnessState.equivocations),
        "POST /control/witness/peers": async (_r: unknown, b: unknown) => { for (const p of (b as { peers: WitnessPeer[] }).peers) if (!this.witnessPeers.some((x) => x.witnessId === p.witnessId)) this.witnessPeers.push(p); return ok({ peers: this.witnessPeers.map((p) => p.witnessId) }); },
        "POST /control/refresh-venue-keys": async () => ok({ ...(await this.refreshVenueKeys()), root: this.venueRoot?.kid, roots: this.venueKeys?.rootKids() }),
        "POST /control/rotate/prepare": async () => ok(this.rotatePrepare()),
        "POST /control/rotate/submit": async (_r: unknown, b: unknown) => ok(await this.rotateSubmit(b as Parameters<AgentRuntime<Ctx>["rotateSubmit"]>[0])),
        "GET /control/identity": async () => ok({ agentId: this.config.agentId, kid: this.kp.kid, credentialId: this.credential?.credentialId, supersedes: this.credential?.supersedes, expiresAt: this.credential?.expiresAt, issuerKid: this.credential?.issuer.kid, venueRootKid: this.venueRoot?.kid, venueRootsKnown: this.venueKeys?.rootKids() ?? [], venueKidsKnown: this.venueKeys?.kids() ?? [] }),
        /** Fault injection at runtime: models a compromised agent runtime. */
        "POST /control/rogue": async (_r: unknown, b: unknown) => {
          this.config.rogue = (b as { rogue?: AgentConfig["rogue"] }).rogue;
          this.audit.write({ component: this.comp.runtime, event: "fault-injection", outcome: "INFO", evidence: { rogue: this.config.rogue ?? null } });
          return ok({ ok: true, rogue: this.config.rogue ?? null });
        },
        "GET /control/tasks": async () => ok([...this.tasks.values()]),
        "GET /control/audit": async () => ok(this.audit.readAll()),
        "GET /control/commitments": async () => {
          const dir = join(this.config.dataDir, "commitments");
          return ok(existsSync(dir) ? readdirSync(dir).map((f) => JSON.parse(readFileSync(join(dir, f), "utf8"))) : []);
        },
        /** For the isolation test: what this process knows, WITHOUT revealing private values. */
        "GET /control/state-digest": async () =>
          ok({
            agentId: this.config.agentId,
            dataDir: this.config.dataDir,
            files: readdirSync(this.config.dataDir),
            privateContextHash: hashObject(this.ctx),
            knownAgentUrls: [this.config.venueUrl],
            venueKeyPinned: !!this.venueRoot,
            venueKidsKnown: this.venueKeys?.kids().length ?? 0,
          }),
        "GET /control/private-canary": async () => ok({ canary: this.ctx.canary }),
      } satisfies Record<string, HttpRoute>);
    }
    await startServer(this.config.port, { rpcPath: "/a2a", rpc: (m, p) => this.handleRpc(m, p), routes });
    setInterval(() => {
      if (!this.credential) return;
      this.reconcile().catch(() => {});
      this.refreshVenueKeys().catch(() => {});
      this.witnessNow().catch(() => {});
    }, this.config.reconcileMs ?? 15_000).unref();
    console.log(`[${this.config.agentId}] ${this.config.role} listening on ${this.url}${simMode ? " SIM_MODE" : ""}`);
  }
}

/** The agent's A2A card, signed by `kp`. Exported so a principal provisioning a NEW key for a compromised agent can produce the card the venue requires. */
export function buildAgentCard(config: AgentConfig, kp: KeyPair, url: string): AgentCard {
  return signAgentCard(
    {
      protocolVersion: A2A_PROTOCOL_VERSION,
      name: config.agentId,
      description: `${config.role} agent for ${config.entity.legalName}`,
      url: `${url}/a2a`,
      preferredTransport: "JSONRPC",
      version: "0.1.0",
      provider: { organization: config.entity.legalName },
      capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false, extensions: [{ uri: FREIGHT_EXTENSION_URI, required: true }] },
      defaultInputModes: ["application/json"],
      defaultOutputModes: ["application/json"],
      skills: [{ id: "negotiate-freight", name: "Negotiate freight", description: `Negotiate loads as a ${config.role}`, tags: ["freight", config.role] }],
      metadata: { agentId: config.agentId, registry: { usdot: config.entity.usdot, mc: config.entity.mc } },
    },
    kp,
  );
}

export function loadConfig(): AgentConfig {
  const p = process.env.AGENT_CONFIG;
  if (!p) throw new Error("AGENT_CONFIG env var (path to config json) is required");
  return JSON.parse(readFileSync(p, "utf8"));
}
