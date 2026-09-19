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
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { A2A_PROTOCOL_VERSION, FREIGHT_EXTENSION_URI, RPC_ERR, dataPart, signAgentCard, verifyAgentCard, type AgentCard, type Message, type Task } from "../protocol/a2a";
import { hashObject } from "../protocol/canonical";
import { exportPrivateJwk, generateKeyPair, importKeyPair, signJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { buildMessage, signMessage, verifyMessageSignature, verifyVenueSignature, type SignedMeta, type VenueAttachment } from "../protocol/envelope";
import { termsHash, type AcceptPayload, type CounterPayload, type LoadSpec, type NegotiationPayload, type TenderPayload, type Terms } from "../protocol/freight";
import { AuditLog, type Component } from "../protocol/audit";
import { httpGet, rpcCall, RpcRefusal, startServer, type HttpRoute } from "../protocol/rpc";
import type { Credential, MandateEnvelope } from "../protocol/types";
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
  venueKey?: OkpJwk;
  private tasks = new Map<string, LocalTask>();
  private readonly comp: { mandate: Component; strategy: Component; runtime: Component };
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
    this.url = `http://127.0.0.1:${config.port}`;
    const r = config.role;
    this.comp = { mandate: `agent.${r}.mandate`, strategy: `agent.${r}.strategy`, runtime: `agent.${r}.runtime` };
  }

  private persistTasks() {
    writeFileSync(join(this.config.dataDir, "tasks.json"), JSON.stringify(Object.fromEntries(this.tasks), null, 2));
  }

  agentCard(): AgentCard {
    return signAgentCard(
      {
        protocolVersion: A2A_PROTOCOL_VERSION,
        name: this.config.agentId,
        description: `${this.config.role} agent for ${this.config.entity.legalName}`,
        url: `${this.url}/a2a`,
        preferredTransport: "JSONRPC",
        version: "0.1.0",
        provider: { organization: this.config.entity.legalName },
        capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false, extensions: [{ uri: FREIGHT_EXTENSION_URI, required: true }] },
        defaultInputModes: ["application/json"],
        defaultOutputModes: ["application/json"],
        skills: [{ id: "negotiate-freight", name: "Negotiate freight", description: `Negotiate loads as a ${this.config.role}`, tags: ["freight", this.config.role] }],
        metadata: { agentId: this.config.agentId, registry: { usdot: this.config.entity.usdot, mc: this.config.entity.mc } },
      },
      this.kp,
    );
  }

  // ------------------------------------------------------------- onboarding

  async pinVenue() {
    const card = await httpGet<AgentCard>(`${this.config.venueUrl}/.well-known/agent-card.json`);
    const v = verifyAgentCard(card);
    if (!v.ok || !v.jwk) throw new Error(`venue agent card does not verify: ${v.error}`);
    this.venueKey = v.jwk;
    writeFileSync(join(this.config.dataDir, "venue-key.pinned.json"), JSON.stringify(v.jwk));
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
    writeFileSync(join(this.config.dataDir, "credential.json"), JSON.stringify(this.credential, null, 2));
    this.audit.write({ component: this.comp.runtime, event: "onboard", outcome: "ALLOWED", evidence: { credentialId: this.credential.credentialId, expiresAt: this.credential.expiresAt } });
    return { ok: true, credential: this.credential };
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

  /** Sign and send a negotiation payload to the venue. */
  async send(data: NegotiationPayload, taskId?: string, contextId?: string): Promise<{ task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown } }> {
    const id = this.identity();
    const m = signMessage(buildMessage({ role: "user", data: data as unknown as Record<string, unknown>, taskId, contextId, senderAgentId: id.agentId, credentialId: id.credentialId }), this.kp);
    return this.sendRaw(m);
  }

  /** Send an already-signed message verbatim (used by the replay scenario). */
  async sendRaw(m: Message): Promise<{ task?: Task; refusal?: { reasonCode: string; refusedBy: string; evidence: unknown } }> {
    const res = await rpcCall<Task>(`${this.config.venueUrl}/a2a`, "message/send", { message: m });
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
    if (!this.venueKey) throw new RpcRefusal(RPC_ERR.VENUE_REFUSED, "venue not pinned");
    const vs = verifyVenueSignature(m, this.venueKey);
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
    const ack: Task = { kind: "task", id: m.taskId ?? "n/a", contextId: m.contextId ?? "n/a", status: { state: "working", timestamp: new Date().toISOString() } };
    setImmediate(() => this.process(m).catch((e) => this.audit.write({ component: this.comp.runtime, event: "process", outcome: "INFO", taskId: m.taskId, evidence: { error: String(e) } })));
    return ack;
  }

  private async process(m: Message) {
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
        const view: NegotiationView = { taskId, contextId, load, round, offer: data.offer, myLastOffer: lt.myLastOffer, counterparty: att!.counterparty };
        this.audit.write({ component: this.comp.strategy, event: "counter-received", outcome: "INFO", taskId, evidence: { round, theirRateUsd: data.offer.rateUsd, myLastRateUsd: lt.myLastOffer?.rateUsd } });
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
          await this.send({ type: "REJECT", loadRef: lt.loadRef, round: att!.round, reason: d.reason, from: this.identity().from }, taskId, contextId);
          lt.status = "REJECTED";
        } else {
          await this.accept(data.terms, view, lt);
        }
        break;
      }
      case "COMMITTED": {
        if (!lt) return;
        lt.status = "COMMITTED";
        lt.commitmentId = data.commitmentId;
        const art = data.artifact as { terms: Terms };
        mkdirSync(join(this.config.dataDir, "commitments"), { recursive: true });
        writeFileSync(join(this.config.dataDir, "commitments", `${data.commitmentId}.json`), JSON.stringify(data.artifact, null, 2));
        const cpUsdot = this.config.role === "broker" ? art.terms.carrierEntity.usdot : art.terms.brokerEntity.usdot;
        this.exposure.add(cpUsdot, art.terms.rateUsd, art.terms.pickup.windowStart.slice(0, 10));
        this.audit.write({ component: this.comp.runtime, event: "committed", outcome: "ALLOWED", taskId, evidence: { commitmentId: data.commitmentId, rateUsd: art.terms.rateUsd, guarantee: data.guarantee ? { guaranteeId: data.guarantee.guaranteeId, premiumUsd: data.guarantee.premiumUsd } : null, artifactSavedTo: `commitments/${data.commitmentId}.json` } });
        break;
      }
      case "REFUSED": {
        if (!lt) return;
        lt.status = "REFUSED";
        lt.outcome = { reasonCode: data.reasonCode, refusedBy: data.refusedBy, evidence: data.evidence };
        this.audit.write({ component: this.comp.runtime, event: "refused-by-venue", outcome: "INFO", taskId, evidence: { reasonCode: data.reasonCode, refusedBy: data.refusedBy } });
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
          this.exposure.release(cpUsdot, art.terms.rateUsd, art.terms.pickup.windowStart.slice(0, 10));
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
      this.audit.write({ component: this.comp.strategy, event: "decision", outcome: "INFO", taskId: view.taskId, evidence: { decision: "REJECT", reason: d.reason, round: view.round } });
      await this.send({ type: "REJECT", loadRef: lt.loadRef, round: view.round, reason: d.reason, from: id.from }, view.taskId, view.contextId);
      lt.status = "REJECTED";
      return;
    }
    if (d.kind === "COUNTER") {
      const offer = this.forceRate(d.offer);
      const round = view.round + 1;
      this.audit.write({ component: this.comp.strategy, event: "decision", outcome: "INFO", taskId: view.taskId, evidence: { decision: "COUNTER", round, rateUsd: offer.rateUsd, note: d.note } });
      if (!this.guard(this.offerAction(view.load, offer, round), view.taskId, "counter")) {
        await this.send({ type: "REJECT", loadRef: lt.loadRef, round: view.round, reason: "outside mandate", from: id.from }, view.taskId, view.contextId);
        lt.status = "REJECTED";
        return;
      }
      const payload: CounterPayload = { type: "COUNTER", loadRef: lt.loadRef, round, offer, from: id.from, note: d.note };
      lt.myLastOffer = offer;
      lt.round = round;
      await this.send(payload, view.taskId, view.contextId);
      return;
    }
    // ACCEPT the counterparty's offer as it stands
    const terms = this.termsFrom(view, lt);
    await this.accept(terms, view, lt);
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
      await this.send({ type: "REJECT", loadRef: lt.loadRef, round: view.round, reason: "outside mandate", from: this.identity().from }, view.taskId, view.contextId);
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
            venueKeyPinned: !!this.venueKey,
          }),
        "GET /control/private-canary": async () => ok({ canary: this.ctx.canary }),
      } satisfies Record<string, HttpRoute>);
    }
    await startServer(this.config.port, { rpcPath: "/a2a", rpc: (m, p) => this.handleRpc(m, p), routes });
    console.log(`[${this.config.agentId}] ${this.config.role} listening on ${this.url}${simMode ? " SIM_MODE" : ""}`);
  }
}

export function loadConfig(): AgentConfig {
  const p = process.env.AGENT_CONFIG;
  if (!p) throw new Error("AGENT_CONFIG env var (path to config json) is required");
  return JSON.parse(readFileSync(p, "utf8"));
}
