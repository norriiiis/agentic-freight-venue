/**
 * The policy engine. Pure function of (limits, action, exposure) -> verdict.
 * Returns EVERY violation, not just the first, so audit entries are complete.
 */
import type { ReasonCode } from "../protocol/reasons";
import type { MandateEnvelope } from "../protocol/types";
import type { ExposureBook } from "./exposure";
import type { MandateAction, MandateLimits } from "./types";

export interface Violation {
  code: ReasonCode;
  evidence: Record<string, unknown>;
}

export interface MandateVerdict {
  allowed: boolean;
  violations: Violation[];
  checked: string[];
}

function laneApproved(limits: { allowedLaneRegions?: string[] }, o: string, d: string): boolean {
  const r = limits.allowedLaneRegions;
  if (!r || r.length === 0) return true;
  return r.includes(o) && r.includes(d);
}

export function evaluateMandate(limits: MandateLimits, action: MandateAction, exposure?: ExposureBook): MandateVerdict {
  const v: Violation[] = [];
  const checked: string[] = [];
  const perMile = action.miles > 0 ? action.rateUsd / action.miles : Number.POSITIVE_INFINITY;

  checked.push("rate.ceiling");
  if (limits.maxRatePerLoadUsd !== undefined && action.rateUsd > limits.maxRatePerLoadUsd) {
    v.push({ code: "MANDATE_RATE_ABOVE_CEILING", evidence: { rateUsd: action.rateUsd, maxRatePerLoadUsd: limits.maxRatePerLoadUsd } });
  }
  if (limits.maxRatePerMileUsd !== undefined && perMile > limits.maxRatePerMileUsd) {
    v.push({ code: "MANDATE_RATE_ABOVE_CEILING", evidence: { ratePerMileUsd: +perMile.toFixed(3), maxRatePerMileUsd: limits.maxRatePerMileUsd } });
  }
  checked.push("rate.floor");
  if (limits.minRatePerLoadUsd !== undefined && action.rateUsd < limits.minRatePerLoadUsd) {
    v.push({ code: "MANDATE_RATE_BELOW_FLOOR", evidence: { rateUsd: action.rateUsd, minRatePerLoadUsd: limits.minRatePerLoadUsd } });
  }
  if (limits.minRatePerMileUsd !== undefined && perMile < limits.minRatePerMileUsd) {
    v.push({ code: "MANDATE_RATE_BELOW_FLOOR", evidence: { ratePerMileUsd: +perMile.toFixed(3), minRatePerMileUsd: limits.minRatePerMileUsd } });
  }
  checked.push("lane");
  if (!laneApproved(limits, action.originState, action.destinationState)) {
    v.push({ code: "MANDATE_LANE_NOT_APPROVED", evidence: { origin: action.originState, destination: action.destinationState, allowedLaneRegions: limits.allowedLaneRegions } });
  }
  checked.push("equipment");
  if (!limits.allowedEquipment.includes(action.equipment) || (action.hazmat && !limits.hazmatPermitted)) {
    v.push({ code: "MANDATE_EQUIPMENT_NOT_APPROVED", evidence: { equipment: action.equipment, hazmat: action.hazmat, allowedEquipment: limits.allowedEquipment, hazmatPermitted: limits.hazmatPermitted } });
  }
  checked.push("mayTender");
  if (action.kind === "OFFER" && action.isTender && !limits.mayTender) {
    v.push({ code: "NO_BROKERAGE_AUTHORITY", evidence: { mayTender: false, note: "principal has not authorized this agent to tender loads to others" } });
  }
  checked.push("rounds");
  if (action.round > limits.maxNegotiationRounds) {
    v.push({ code: "NEGOTIATION_MAX_ROUNDS", evidence: { round: action.round, maxNegotiationRounds: limits.maxNegotiationRounds } });
  }
  checked.push("paymentTerms");
  if (action.paymentTermsDays < limits.paymentTermsDays.min || action.paymentTermsDays > limits.paymentTermsDays.max) {
    v.push({ code: "PROTOCOL_VIOLATION", evidence: { paymentTermsDays: action.paymentTermsDays, allowed: limits.paymentTermsDays } });
  }

  if (action.kind === "ACCEPT") {
    checked.push("counterpartyInsurance");
    if (action.counterpartyInsuranceUsd < limits.requiredCounterpartyInsuranceUsd) {
      v.push({ code: "MANDATE_INSURANCE_MIN_NOT_MET", evidence: { counterpartyInsuranceUsd: action.counterpartyInsuranceUsd, requiredCounterpartyInsuranceUsd: limits.requiredCounterpartyInsuranceUsd } });
    }
    checked.push("guarantee");
    if (limits.requireGuarantee && !action.guaranteeAvailable) {
      v.push({ code: "MANDATE_GUARANTEE_REQUIRED", evidence: { requireGuarantee: true, guaranteeAvailable: false } });
    }
    if (limits.requireInsurerAttestation || limits.requireInsurerUndertaking) {
      checked.push("insurerAttestation");
      const assured = action.counterpartyInsuranceAssuredThrough ? new Date(action.counterpartyInsuranceAssuredThrough) : undefined;
      const delivery = action.deliveryWindowEnd ? new Date(action.deliveryWindowEnd) : undefined;
      const pickup = action.pickupWindowStart ? new Date(action.pickupWindowStart) : delivery;
      const notice = (action.counterpartyInsuranceNoticeDays ?? 30) * 86_400_000;
      // Short of delivery is allowed as a CONDITION: a renewal signed at or after delivery − notice, on file by pickup.
      const renewable = !!delivery && !!pickup && delivery.getTime() - notice <= pickup.getTime();
      if (!assured || !delivery || (assured < delivery && !renewable)) {
        v.push({ code: "MANDATE_INSURER_ATTESTATION_REQUIRED", evidence: { counterpartyInsuranceAssuredThrough: action.counterpartyInsuranceAssuredThrough ?? null, deliveryWindowEnd: action.deliveryWindowEnd, pickupWindowStart: action.pickupWindowStart, noticeDays: action.counterpartyInsuranceNoticeDays ?? 30, note: !assured ? "no insurer attestation on file for the counterparty" : "no word signed before pickup can assure coverage through delivery: transit outruns the insurer's notice period" } });
      } else if (limits.requireInsurerUndertaking && action.counterpartyInsurerUndertaking !== "NO_DENIAL_FOR_UNDISCLOSED_LAPSE") {
        checked.push("insurerUndertaking");
        v.push({ code: "MANDATE_INSURER_UNDERTAKING_REQUIRED", evidence: { counterpartyInsurerUndertaking: action.counterpartyInsurerUndertaking ?? null, note: "the counterparty's insurer signed a certificate (its belief), not an undertaking (a promise it is liable for)" } });
      }
    }
    if (exposure) {
      checked.push("exposure.counterparty");
      const cp = exposure.outstanding(action.counterpartyUsdot);
      if (cp + action.rateUsd > limits.maxPerCounterpartyExposureUsd) {
        v.push({ code: "MANDATE_EXPOSURE_COUNTERPARTY_EXCEEDED", evidence: { counterpartyUsdot: action.counterpartyUsdot, outstandingUsd: cp, thisLoadUsd: action.rateUsd, wouldBeUsd: cp + action.rateUsd, maxPerCounterpartyExposureUsd: limits.maxPerCounterpartyExposureUsd } });
      }
      checked.push("exposure.daily");
      const d = exposure.daily(action.day);
      if (d + action.rateUsd > limits.maxDailyExposureUsd) {
        v.push({ code: "MANDATE_EXPOSURE_DAILY_EXCEEDED", evidence: { day: action.day, outstandingUsd: d, thisLoadUsd: action.rateUsd, wouldBeUsd: d + action.rateUsd, maxDailyExposureUsd: limits.maxDailyExposureUsd } });
      }
    }
  }
  return { allowed: v.length === 0, violations: v, checked };
}

/** The venue evaluates the registered envelope with the same engine, mapping envelope limits into MandateLimits. */
export function envelopeToLimits(e: MandateEnvelope): MandateLimits {
  return {
    maxRatePerLoadUsd: e.limits.maxRatePerLoadUsd,
    minRatePerLoadUsd: e.limits.minRatePerLoadUsd,
    allowedLaneRegions: e.limits.allowedLaneRegions,
    allowedEquipment: e.limits.allowedEquipment as MandateLimits["allowedEquipment"],
    hazmatPermitted: true, // envelope does not carry hazmat; the agent's private mandate does
    requiredCounterpartyInsuranceUsd: e.limits.requiredCounterpartyInsuranceUsd,
    maxPerCounterpartyExposureUsd: e.limits.maxPerCounterpartyExposureUsd,
    maxDailyExposureUsd: e.limits.maxDailyExposureUsd,
    requireGuarantee: e.limits.requireGuarantee,
    requireInsurerAttestation: e.limits.requireInsurerAttestation,
    requireInsurerUndertaking: e.limits.requireInsurerUndertaking,
    mayTender: true, // brokerage authority is checked by the venue against the registry, not the envelope
    maxNegotiationRounds: Number.MAX_SAFE_INTEGER, // protocol bound is the venue's own, not the envelope's
    paymentTermsDays: { min: 0, max: 365 },
  };
}
