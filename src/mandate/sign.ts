import { randomUUID } from "node:crypto";
import { importPublicKey, signJws, verifyJws, type KeyPair } from "../protocol/crypto";
import type { MandateEnvelope } from "../protocol/types";
import type { Mandate, MandateLimits } from "./types";

/** The principal (a human-controlled key) signs a mandate for one agent. */
export function issueMandate(principal: KeyPair, principalName: string, agentId: string, limits: MandateLimits, validityDays = 30, now = new Date()): Mandate {
  const unsigned: Omit<Mandate, "principalSignature"> = {
    schema: "freight-venue/mandate/v1",
    mandateId: `mandate_${randomUUID()}`,
    agentId,
    principal: { name: principalName, kid: principal.kid, publicKey: principal.publicJwk },
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + validityDays * 86_400_000).toISOString(),
    limits,
  };
  return { ...unsigned, principalSignature: signJws(unsigned, principal, { typ: "mandate+jws" }, true) };
}

export function verifyMandate(m: Mandate, now = new Date()): { ok: boolean; error?: string } {
  const { principalSignature, ...unsigned } = m;
  const res = verifyJws(principalSignature, importPublicKey(m.principal.publicKey), unsigned);
  if (!res.ok) return { ok: false, error: res.error };
  if (new Date(m.expiresAt) <= now) return { ok: false, error: "mandate expired" };
  return { ok: true };
}

/**
 * Derive the venue-registered envelope from the full mandate. The principal
 * signs it separately: it is a deliberate, coarser disclosure — a compliance
 * ceiling, not the agent's negotiation target.
 */
export function issueEnvelope(principal: KeyPair, m: Mandate, disclose: Partial<MandateEnvelope["limits"]> = {}): MandateEnvelope {
  const unsigned: Omit<MandateEnvelope, "principalSignature"> = {
    schema: "freight-venue/mandate-envelope/v1",
    agentId: m.agentId,
    principalKid: principal.kid,
    issuedAt: m.issuedAt,
    expiresAt: m.expiresAt,
    principalPublicKey: principal.publicJwk,
    limits: {
      maxRatePerLoadUsd: m.limits.maxRatePerLoadUsd,
      minRatePerLoadUsd: m.limits.minRatePerLoadUsd,
      maxDailyExposureUsd: m.limits.maxDailyExposureUsd,
      maxPerCounterpartyExposureUsd: m.limits.maxPerCounterpartyExposureUsd,
      allowedEquipment: m.limits.allowedEquipment,
      allowedLaneRegions: m.limits.allowedLaneRegions,
      requiredCounterpartyInsuranceUsd: m.limits.requiredCounterpartyInsuranceUsd,
      requireGuarantee: m.limits.requireGuarantee,
      requireInsurerAttestation: m.limits.requireInsurerAttestation,
      requireInsurerUndertaking: m.limits.requireInsurerUndertaking,
      ...disclose,
    },
  };
  return { ...unsigned, principalSignature: signJws(unsigned, principal, { typ: "mandate-envelope+jws" }, true) };
}

export function verifyEnvelope(e: MandateEnvelope, now = new Date()): { ok: boolean; error?: string } {
  const { principalSignature, ...unsigned } = e;
  const res = verifyJws(principalSignature, importPublicKey(e.principalPublicKey), unsigned);
  if (!res.ok) return { ok: false, error: res.error };
  if (new Date(e.expiresAt) <= now) return { ok: false, error: "envelope expired" };
  return { ok: true };
}
