import type { OkpJwk } from "../protocol/crypto";
import type { CounterNoteCode, LoadSpec, RejectReasonCode, Terms } from "../protocol/freight";
import type { VenueAttachment } from "../protocol/envelope";
import type { Mandate } from "../mandate/types";

export interface Offer {
  rateUsd: number;
  pickup: Terms["pickup"];
  delivery: Terms["delivery"];
  paymentTermsDays: number;
}

export interface AgentConfig {
  agentId: string;
  role: "broker" | "carrier";
  dataDir: string;
  port: number;
  venueUrl: string;
  entity: { usdot: string; mc?: string; legalName: string };
  proofOfControl: { method: string; token: string };
  /** Simulated deliberation time per decision (ms). Makes transcripts readable and lets the sim inject events mid-negotiation. */
  thinkMs?: number;
  /** How often to pull tasks/get for negotiations still OPEN locally (push is at-least-once; pull bounds the gap). Default 15s. */
  reconcileMs?: number;
  /**
   * Independent witnesses this agent gossips with as a witness of its own transactions. Distributed by the
   * PRINCIPAL out of band (its insurer's, an industry body's) — never learned from the venue.
   */
  witnessPeers?: { witnessId: string; url: string; publicKey: OkpJwk }[];
  /** Pinned principal key: the mandate on disk must be signed by this key or the agent refuses to run. */
  principal: { name: string; publicKey: OkpJwk };
  /**
   * SIM-ONLY fault injection. Models a compromised or misbehaving agent
   * runtime. A deployed agent has no such switch.
   */
  rogue?: {
    /** Ignore local mandate refusals and send anyway (the venue must catch it). */
    bypassLocalMandate?: boolean;
    /** Force every offer/accept to this rate (used to attempt an over-ceiling commit). */
    forceRateUsd?: number;
    /** Present someone else's credential id in outbound messages (spoofing). */
    presentCredentialId?: string;
    /** Claim to be someone else. */
    presentAgentId?: string;
    /** Skip onboarding entirely (a spoofer cannot pass proof of control). */
    skipOnboarding?: boolean;
    /** Acknowledge inbound messages but never act on them (a hung or crashed agent). */
    dropInbound?: boolean;
    /** Attach this text to every outbound COUNTER/REJECT (a malicious agent probing the counterparty's LLM). */
    injectText?: string;
  };
}

export type Decision = { kind: "COUNTER"; offer: Offer; noteCode?: CounterNoteCode } | { kind: "ACCEPT" } | { kind: "REJECT"; reasonCode: RejectReasonCode };

export interface NegotiationView {
  taskId: string;
  contextId: string;
  load: LoadSpec;
  round: number;
  /** The counterparty's current offer. */
  offer: Offer;
  /** Why the counterparty says its offer differs — a code, never prose. */
  noteCode?: CounterNoteCode;
  /** What I last offered, if anything. */
  myLastOffer?: Offer;
  counterparty: VenueAttachment["counterparty"];
  guaranteeAvailable?: boolean;
  // Deliberately absent: any free-text field from the counterparty. Strategies (LLM-backed or not)
  // reason over codes and numbers only. See agentkit/prompting.ts.
}

/**
 * A strategy is the agent's private brain. It sees its principal's private
 * context (Ctx) and the mandate; it returns decisions. It never sees the
 * counterparty's private context — only what crossed the wire.
 */
export type MaybeAsync<T> = T | Promise<T>;
export type AcceptDecision = { kind: "ACCEPT" } | { kind: "REJECT"; reasonCode: RejectReasonCode };
export interface Strategy<Ctx> {
  openingOffer(load: LoadSpec, ctx: Ctx, mandate: Mandate): MaybeAsync<Offer>;
  onTender(view: NegotiationView, ctx: Ctx, mandate: Mandate): MaybeAsync<Decision>;
  onCounter(view: NegotiationView, ctx: Ctx, mandate: Mandate): MaybeAsync<Decision>;
  onAcceptRequest(terms: Terms, view: NegotiationView, ctx: Ctx, mandate: Mandate): MaybeAsync<AcceptDecision>;
}

export interface LocalTask {
  taskId: string;
  contextId: string;
  loadRef: string;
  load: LoadSpec;
  role: "initiator" | "responder";
  counterpartyAgentId?: string;
  status: "OPEN" | "COMMITTED" | "REFUSED" | "REJECTED" | "VOIDED" | "CANCELED";
  round: number;
  myLastOffer?: Offer;
  commitmentId?: string;
  outcome?: { reasonCode: string; refusedBy: string; evidence: Record<string, unknown> };
  /** The load after commitment, as the venue relayed the counterparty's statements. */
  lifecycle?: { event: string; by: string; at: string; status: string; ledgerSeq: number }[];
}
