import type { OkpJwk } from "../protocol/crypto";
import type { LoadSpec, Terms } from "../protocol/freight";
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
  };
}

export type Decision = { kind: "COUNTER"; offer: Offer; note?: string } | { kind: "ACCEPT" } | { kind: "REJECT"; reason: string };

export interface NegotiationView {
  taskId: string;
  contextId: string;
  load: LoadSpec;
  round: number;
  /** The counterparty's current offer. */
  offer: Offer;
  /** What I last offered, if anything. */
  myLastOffer?: Offer;
  counterparty: VenueAttachment["counterparty"];
  guaranteeAvailable?: boolean;
}

/**
 * A strategy is the agent's private brain. It sees its principal's private
 * context (Ctx) and the mandate; it returns decisions. It never sees the
 * counterparty's private context — only what crossed the wire.
 */
export interface Strategy<Ctx> {
  openingOffer(load: LoadSpec, ctx: Ctx, mandate: Mandate): Offer;
  onTender(view: NegotiationView, ctx: Ctx, mandate: Mandate): Decision;
  onCounter(view: NegotiationView, ctx: Ctx, mandate: Mandate): Decision;
  onAcceptRequest(terms: Terms, view: NegotiationView, ctx: Ctx, mandate: Mandate): { kind: "ACCEPT" } | { kind: "REJECT"; reason: string };
}

export interface LocalTask {
  taskId: string;
  contextId: string;
  loadRef: string;
  load: LoadSpec;
  role: "initiator" | "responder";
  counterpartyAgentId?: string;
  status: "OPEN" | "COMMITTED" | "REFUSED" | "REJECTED" | "VOIDED";
  round: number;
  myLastOffer?: Offer;
  commitmentId?: string;
  outcome?: { reasonCode: string; refusedBy: string; evidence: Record<string, unknown> };
}
