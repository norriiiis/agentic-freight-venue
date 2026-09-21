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

/**
 * Why a counter differs from the offer it answers. A closed vocabulary: the
 * counterparty's agent (possibly an LLM) reasons over codes, never prose.
 */
export const COUNTER_NOTE_CODES = ["RATE", "PICKUP_WINDOW", "DELIVERY_WINDOW", "PAYMENT_TERMS", "EQUIPMENT", "FINAL_OFFER", "OTHER"] as const;
export type CounterNoteCode = (typeof COUNTER_NOTE_CODES)[number];

export const REJECT_REASON_CODES = ["OUTSIDE_MANDATE", "BELOW_MINIMUM", "ABOVE_MAXIMUM", "TERMS_MISMATCH", "WINDOW_INFEASIBLE", "NO_CAPACITY", "NO_INBOUND_TENDERS", "OTHER"] as const;
export type RejectReasonCode = (typeof REJECT_REASON_CODES)[number];

export interface CounterPayload {
  type: "COUNTER";
  loadRef: string;
  round: number;
  offer: { rateUsd: number; pickup: Terms["pickup"]; delivery: Terms["delivery"]; paymentTermsDays: number };
  from: { agentId: string; usdot: string; mc?: string };
  noteCode?: CounterNoteCode;
  /**
   * Optional human remark ("dock closes 16:00"). UNTRUSTED. Bounded by the
   * venue (see validateNegotiationPayload) and quarantined by the agent
   * runtime: strategies never receive it; only a hash reaches audit logs.
   */
  text?: string;
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
  reasonCode: RejectReasonCode;
  from: { agentId: string; usdot: string; mc?: string };
  /** Optional, UNTRUSTED, bounded and quarantined exactly like CounterPayload.text. */
  text?: string;
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

/** Venue -> agent, after a venue-key compromise: your credential was re-signed under the new venue key. */
export interface CredentialReissuedPayload {
  type: "CREDENTIAL_REISSUED";
  credential: Record<string, unknown>;
  reason: string;
}
/** Venue -> agents: a conditional commitment's insurer-renewal condition was satisfied; the origin's word is recorded. */
export interface InsuranceRenewedPayload {
  type: "INSURANCE_RENEWED";
  loadRef: string;
  commitmentId: string;
  attestation: Record<string, unknown>; // InsurerAttestation
  assuredThrough: string;
  ledgerSeq: number;
}
/** Venue -> agents: the other party reported a lifecycle event on a shared commitment. */
export interface LifecyclePayload {
  type: "LIFECYCLE";
  loadRef: string;
  commitmentId: string;
  event: string;
  by: string;
  at: string;
  status: string;
  ledgerSeq: number;
  evidenceHash: string | null;
}
/** Venue -> agent, after a venue-key compromise: this commitment's artifact carries a new attestation. */
export interface CommitmentReattestedPayload {
  type: "COMMITMENT_REATTESTED";
  loadRef: string;
  commitmentId: string;
  artifact: Record<string, unknown>;
  reason: string;
}

export type NegotiationPayload =
  | CredentialReissuedPayload
  | CommitmentReattestedPayload
  | InsuranceRenewedPayload
  | LifecyclePayload
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

// ---- Wire schema validation ------------------------------------------------
//
// Every payload that crosses the wire is validated against a CLOSED schema:
// known keys only, enum codes only, and every string leaf single-line, bounded,
// and free of control / bidi / zero-width characters. This is what makes a
// free-text field safe to carry: it cannot smuggle a prompt, a script, or an
// invisible instruction. The venue validates on ingest; agents validate on
// receipt (a compromised venue must not be able to push unbounded text either).

export const TEXT_MAX_CHARS = 140;
const STRING_MAX_CHARS = 200;
/** Control chars, DEL, line/paragraph separators, zero-width and bidi-control code points. */
const UNSAFE_CHARS = /[\u0000-\u001f\u007f\u0085\u2028\u2029\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/u;

export interface SchemaViolation {
  field: string;
  rule: "UNKNOWN_KEY" | "UNKNOWN_TYPE" | "BAD_ENUM" | "BAD_FORMAT" | "TOO_LONG" | "UNSAFE_CHARS" | "BAD_NUMBER" | "MISSING";
  detail: string;
}

const KEYS: Record<string, string[]> = {
  TENDER: ["type", "load", "offer", "from", "to"],
  COUNTER: ["type", "loadRef", "round", "offer", "from", "noteCode", "text"],
  ACCEPT: ["type", "loadRef", "round", "terms", "termsHash", "from"],
  REJECT: ["type", "loadRef", "round", "reasonCode", "from", "text"],
  COMMITTED: ["type", "loadRef", "commitmentId", "termsHash", "guarantee", "artifact"],
  REFUSED: ["type", "loadRef", "reasonCode", "refusedBy", "evidence", "disposition"],
  VOIDED: ["type", "loadRef", "commitmentId", "reasonCode", "evidence"],
  CREDENTIAL_REISSUED: ["type", "credential", "reason"],
  COMMITMENT_REATTESTED: ["type", "loadRef", "commitmentId", "artifact", "reason"],
  INSURANCE_RENEWED: ["type", "loadRef", "commitmentId", "attestation", "assuredThrough", "ledgerSeq"],
  LIFECYCLE: ["type", "loadRef", "commitmentId", "event", "by", "at", "status", "ledgerSeq", "evidenceHash"],
};
const FORMATS: Record<string, { re: RegExp; max: number }> = {
  loadRef: { re: /^[A-Za-z0-9._\-/]+$/, max: 64 },
  agentId: { re: /^[A-Za-z0-9._\-]+$/, max: 64 },
  usdot: { re: /^\d{1,8}$/, max: 8 },
  mc: { re: /^(MC|MX|FF)-?\d{1,8}$/, max: 12 },
  state: { re: /^[A-Z]{2}$/, max: 2 },
  zip: { re: /^\d{5}(-\d{4})?$/, max: 10 },
  equipment: { re: /^(VAN|REEFER|FLATBED|STEP_DECK|POWER_ONLY)$/, max: 12 },
  windowStart: { re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/, max: 32 },
  windowEnd: { re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/, max: 32 },
  termsHash: { re: /^[0-9a-f]{64}$/, max: 64 },
};

function checkStrings(value: unknown, path: string, out: SchemaViolation[]) {
  if (typeof value === "string") {
    const leaf = path.split(".").pop() ?? path;
    if (UNSAFE_CHARS.test(value)) return out.push({ field: path, rule: "UNSAFE_CHARS", detail: "control, line-break, bidi or zero-width character" });
    const max = leaf === "text" ? TEXT_MAX_CHARS : FORMATS[leaf]?.max ?? STRING_MAX_CHARS;
    if (value.length > max) return out.push({ field: path, rule: "TOO_LONG", detail: `${value.length} > ${max} chars` });
    const f = FORMATS[leaf];
    if (f && !f.re.test(value)) out.push({ field: path, rule: "BAD_FORMAT", detail: `does not match ${f.re}` });
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0) out.push({ field: path, rule: "BAD_NUMBER", detail: String(value) });
    return;
  }
  if (Array.isArray(value)) return value.forEach((v, i) => checkStrings(v, `${path}[${i}]`, out));
  if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) checkStrings(v, path ? `${path}.${k}` : k, out);
}

/** Validate an agent-originated negotiation payload against the closed wire schema. */
export function validateNegotiationPayload(data: unknown): { ok: true } | { ok: false; violations: SchemaViolation[] } {
  const v: SchemaViolation[] = [];
  const d = data as Record<string, unknown> | undefined;
  const type = typeof d?.type === "string" ? d.type : "";
  const allowed = KEYS[type];
  if (!d || !allowed) return { ok: false, violations: [{ field: "type", rule: "UNKNOWN_TYPE", detail: String(type) }] };
  for (const k of Object.keys(d)) if (!allowed.includes(k)) v.push({ field: k, rule: "UNKNOWN_KEY", detail: `not part of ${type}` });
  if (type === "COUNTER" && d.noteCode !== undefined && !COUNTER_NOTE_CODES.includes(d.noteCode as CounterNoteCode)) v.push({ field: "noteCode", rule: "BAD_ENUM", detail: String(d.noteCode) });
  if (type === "REJECT" && !REJECT_REASON_CODES.includes(d.reasonCode as RejectReasonCode)) v.push({ field: "reasonCode", rule: d.reasonCode === undefined ? "MISSING" : "BAD_ENUM", detail: String(d.reasonCode) });
  if ((type === "COUNTER" || type === "REJECT") && d.text !== undefined && typeof d.text !== "string") v.push({ field: "text", rule: "BAD_FORMAT", detail: "must be a string" });
  if (type === "COUNTER" || type === "ACCEPT" || type === "REJECT") {
    if (!Number.isInteger(d.round) || (d.round as number) < 1) v.push({ field: "round", rule: "BAD_NUMBER", detail: String(d.round) });
  }
  const offer = (type === "TENDER" || type === "COUNTER" ? d.offer : type === "ACCEPT" ? (d.terms as Record<string, unknown> | undefined) : undefined) as Record<string, unknown> | undefined;
  if (offer && (typeof offer.rateUsd !== "number" || !(offer.rateUsd > 0) || offer.rateUsd > 1_000_000)) v.push({ field: "rateUsd", rule: "BAD_NUMBER", detail: String(offer.rateUsd) });
  checkStrings(d, "", v);
  return v.length ? { ok: false, violations: v } : { ok: true };
}

/** Stable digest of an untrusted text field for audit logs that must not carry the text itself. */
export function textDigest(text: string | undefined): { textPresent: boolean; textChars: number; textSha256?: string } {
  if (text === undefined) return { textPresent: false, textChars: 0 };
  return { textPresent: true, textChars: text.length, textSha256: hashObject(text) };
}
