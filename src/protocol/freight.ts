/**
 * The freight negotiation vocabulary carried in A2A DataParts under
 * FREIGHT_EXTENSION_URI. This is the *only* negotiation content that crosses
 * the wire. Private context (costs, margins, targets) never appears here.
 */
import { hashObject } from "./canonical";

export type Equipment = "VAN" | "REEFER" | "FLATBED" | "STEP_DECK" | "POWER_ONLY";

export interface Stop {
  city: string;
  state: string; // USPS code
  zip: string;
  windowStart: string; // ISO
  windowEnd: string;   // ISO
}

export interface LoadSpec {
  loadRef: string;        // broker's reference, e.g. "L-2026-091-0042"
  origin: Stop;
  destination: Stop;
  equipment: Equipment;
  weightLbs: number;
  commodity: string;
  miles: number;
  hazmat: boolean;
  /** Broker-declared: may the performing carrier subcontract? Almost always false. */
  subcontractPermitted: boolean;
}

/** The terms both parties eventually sign. Rate is all-in linehaul USD. */
export interface Terms {
  loadRef: string;
  load: LoadSpec;
  rateUsd: number;
  pickup: { windowStart: string; windowEnd: string };
  delivery: { windowStart: string; windowEnd: string };
  paymentTermsDays: number;
  brokerAgentId: string;
  carrierAgentId: string;
  brokerEntity: { usdot: string; mc?: string };
  carrierEntity: { usdot: string; mc?: string };
}

export function termsHash(t: Terms): string {
  return hashObject(t);
}

/**
 * A fingerprint of the physical load independent of loadRef — used to catch a
 * committed load being re-tendered under a different reference.
 */
export function loadFingerprint(l: LoadSpec): string {
  return hashObject({
    o: [l.origin.zip, l.origin.windowStart.slice(0, 10)],
    d: [l.destination.zip, l.destination.windowStart.slice(0, 10)],
    eq: l.equipment,
    w: Math.round(l.weightLbs / 500) * 500,
    c: l.commodity.toLowerCase().trim(),
  });
}

// ---- Negotiation payloads (the DataPart `data` field) --------------------

export interface TenderPayload {
  type: "TENDER";
  load: LoadSpec;
  offer: { rateUsd: number; pickup: Terms["pickup"]; delivery: Terms["delivery"]; paymentTermsDays: number };
  /** Identity claim; must match the sender's credential. */
  from: { agentId: string; usdot: string; mc?: string };
  /** For the venue to route; agents never learn each other's URLs. */
  to: { agentId: string };
}

export interface CounterPayload {
  type: "COUNTER";
  loadRef: string;
  round: number;
  offer: { rateUsd: number; pickup: Terms["pickup"]; delivery: Terms["delivery"]; paymentTermsDays: number };
  from: { agentId: string; usdot: string; mc?: string };
  note?: string;
}

export interface AcceptPayload {
  type: "ACCEPT";
  loadRef: string;
  round: number;
  /** The exact terms being accepted, and their hash; the sender signs the whole message. */
  terms: Terms;
  termsHash: string;
  from: { agentId: string; usdot: string; mc?: string };
}

export interface RejectPayload {
  type: "REJECT";
  loadRef: string;
  round: number;
  reason: string;
  from: { agentId: string; usdot: string; mc?: string };
}

/** Venue -> agents */
export interface CommittedPayload {
  type: "COMMITTED";
  loadRef: string;
  commitmentId: string;
  termsHash: string;
  guarantee?: { guaranteeId: string; coveredAmountUsd: number; premiumUsd: number; scope: string[] };
  artifact: Record<string, unknown>; // the signed commitment artifact (see ledger/artifact.ts)
}

export interface RefusedPayload {
  type: "REFUSED";
  loadRef?: string;
  reasonCode: string;
  refusedBy: string;
  evidence: Record<string, unknown>;
  /** FAILED: a check failed. CANCELED: nothing was wrong with this negotiation; it was overtaken (multi-tender) or timed out. */
  disposition?: "FAILED" | "CANCELED";
}

export interface VoidedPayload {
  type: "VOIDED";
  loadRef: string;
  commitmentId: string;
  reasonCode: string;
  evidence: Record<string, unknown>;
}

export type NegotiationPayload =
  | TenderPayload
  | CounterPayload
  | AcceptPayload
  | RejectPayload
  | CommittedPayload
  | RefusedPayload
  | VoidedPayload;

export function isNegotiationPayload(x: unknown): x is NegotiationPayload {
  return !!x && typeof x === "object" && typeof (x as { type?: unknown }).type === "string";
}
