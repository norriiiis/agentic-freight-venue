import { describe, it, expect } from "vitest";
import { generateKeyPair } from "../src/protocol/crypto";
import { issueMandate, verifyMandate, issueEnvelope, verifyEnvelope } from "../src/mandate/sign";
import { evaluateMandate, envelopeToLimits } from "../src/mandate/engine";
import { ExposureBook } from "../src/mandate/exposure";
import type { MandateLimits, MandateAction } from "../src/mandate/types";

const LIMITS: MandateLimits = {
  maxRatePerLoadUsd: 3200,
  minRatePerLoadUsd: 900,
  maxRatePerMileUsd: 4.0,
  allowedLaneRegions: ["TX", "OK", "KS", "MO", "AR", "LA"],
  allowedEquipment: ["VAN", "REEFER"],
  hazmatPermitted: false,
  requiredCounterpartyInsuranceUsd: 1_000_000,
  maxPerCounterpartyExposureUsd: 10_000,
  maxDailyExposureUsd: 25_000,
  requireGuarantee: true,
  mayTender: true,
  maxNegotiationRounds: 6,
  paymentTermsDays: { min: 15, max: 45 },
};

const baseAccept: MandateAction = {
  kind: "ACCEPT", rateUsd: 2400, miles: 780, originState: "TX", destinationState: "KS", equipment: "VAN", hazmat: false,
  paymentTermsDays: 30, round: 3, counterpartyUsdot: "2751903", counterpartyInsuranceUsd: 1_000_000, guaranteeAvailable: true, day: "2026-09-19",
};

describe("mandate: principal-signed, agent cannot loosen it", () => {
  it("verifies a mandate signed by the principal and rejects a tampered one", () => {
    const principal = generateKeyPair();
    const m = issueMandate(principal, "Northline Ops", "broker-1", LIMITS);
    expect(verifyMandate(m).ok).toBe(true);
    const loosened = { ...m, limits: { ...m.limits, maxRatePerLoadUsd: 99_999 } };
    expect(verifyMandate(loosened).ok).toBe(false);
  });
  it("envelope is a separately-signed, coarser disclosure", () => {
    const principal = generateKeyPair();
    const m = issueMandate(principal, "Northline Ops", "broker-1", LIMITS);
    const e = issueEnvelope(principal, m);
    expect(verifyEnvelope(e).ok).toBe(true);
    expect(e.limits.maxRatePerLoadUsd).toBe(3200);
    expect(verifyEnvelope({ ...e, limits: { ...e.limits, maxRatePerLoadUsd: 5000 } }).ok).toBe(false);
  });
});

describe("mandate engine refuses its own principal's agent", () => {
  it("allows an in-policy accept", () => {
    expect(evaluateMandate(LIMITS, baseAccept, new ExposureBook()).allowed).toBe(true);
  });
  it("refuses a rate above the ceiling", () => {
    const v = evaluateMandate(LIMITS, { ...baseAccept, rateUsd: 3300 });
    expect(v.allowed).toBe(false);
    expect(v.violations.map((x) => x.code)).toContain("MANDATE_RATE_ABOVE_CEILING");
  });
  it("refuses a per-mile rate above the ceiling even if the per-load rate is fine", () => {
    const v = evaluateMandate(LIMITS, { ...baseAccept, rateUsd: 3000, miles: 500 });
    expect(v.violations[0]).toMatchObject({ code: "MANDATE_RATE_ABOVE_CEILING", evidence: { ratePerMileUsd: 6 } });
  });
  it("refuses a rate below the floor (too-good-to-be-true is a fraud tell)", () => {
    expect(evaluateMandate(LIMITS, { ...baseAccept, rateUsd: 500 }).violations.map((x) => x.code)).toContain("MANDATE_RATE_BELOW_FLOOR");
  });
  it("refuses a lane outside approved regions", () => {
    expect(evaluateMandate(LIMITS, { ...baseAccept, destinationState: "CA" }).violations.map((x) => x.code)).toContain("MANDATE_LANE_NOT_APPROVED");
  });
  it("refuses equipment and hazmat not approved", () => {
    expect(evaluateMandate(LIMITS, { ...baseAccept, equipment: "FLATBED" }).violations.map((x) => x.code)).toContain("MANDATE_EQUIPMENT_NOT_APPROVED");
    expect(evaluateMandate(LIMITS, { ...baseAccept, hazmat: true }).violations.map((x) => x.code)).toContain("MANDATE_EQUIPMENT_NOT_APPROVED");
  });
  it("refuses a counterparty below the insurance minimum", () => {
    expect(evaluateMandate(LIMITS, { ...baseAccept, counterpartyInsuranceUsd: 750_000 }).violations.map((x) => x.code)).toContain("MANDATE_INSURANCE_MIN_NOT_MET");
  });
  it("refuses to commit without a guarantee when one is required", () => {
    expect(evaluateMandate(LIMITS, { ...baseAccept, guaranteeAvailable: false }).violations.map((x) => x.code)).toContain("MANDATE_GUARANTEE_REQUIRED");
    // The counterparty's own insurer must have vouched through delivery — the one word no registry mirror can forge.
    const strict = { ...LIMITS, requireInsurerAttestation: true };
    const codes = (a: Partial<MandateAction>) => evaluateMandate(strict, { ...baseAccept, ...a } as MandateAction).violations.map((x) => x.code);
    expect(codes({ deliveryWindowEnd: "2026-09-24T21:00:00.000Z" })).toContain("MANDATE_INSURER_ATTESTATION_REQUIRED");
    // Short of delivery is allowed as a CONDITION (a renewal signed within the statutory window, on file by pickup)…
    expect(codes({ pickupWindowStart: "2026-09-23T13:00:00.000Z", deliveryWindowEnd: "2026-09-24T21:00:00.000Z", counterpartyInsuranceAssuredThrough: "2026-09-23T00:00:00.000Z" })).not.toContain("MANDATE_INSURER_ATTESTATION_REQUIRED");
    // …unless no word signed before pickup could reach delivery (transit longer than the notice period).
    expect(codes({ pickupWindowStart: "2026-09-23T13:00:00.000Z", deliveryWindowEnd: "2026-11-24T21:00:00.000Z", counterpartyInsuranceAssuredThrough: "2026-10-20T00:00:00.000Z" })).toContain("MANDATE_INSURER_ATTESTATION_REQUIRED");
    expect(codes({ pickupWindowStart: "2026-09-23T13:00:00.000Z", deliveryWindowEnd: "2026-09-24T21:00:00.000Z", counterpartyInsuranceAssuredThrough: "2026-10-20T00:00:00.000Z" })).not.toContain("MANDATE_INSURER_ATTESTATION_REQUIRED");
    expect(evaluateMandate(LIMITS, { ...baseAccept, deliveryWindowEnd: "2026-09-24T21:00:00.000Z" }).violations.map((x) => x.code)).not.toContain("MANDATE_INSURER_ATTESTATION_REQUIRED");
    // An undertaking, not a certificate.
    const liable = { ...LIMITS, requireInsurerUndertaking: true };
    const ok = { pickupWindowStart: "2026-09-23T13:00:00.000Z", deliveryWindowEnd: "2026-09-24T21:00:00.000Z", counterpartyInsuranceAssuredThrough: "2026-10-20T00:00:00.000Z" };
    expect(evaluateMandate(liable, { ...baseAccept, ...ok }).violations.map((x) => x.code)).toContain("MANDATE_INSURER_UNDERTAKING_REQUIRED");
    expect(evaluateMandate(liable, { ...baseAccept, ...ok, counterpartyInsurerUndertaking: "NO_DENIAL_FOR_UNDISCLOSED_LAPSE" }).violations.map((x) => x.code)).toEqual([]);
    expect(evaluateMandate(liable, { ...baseAccept, deliveryWindowEnd: ok.deliveryWindowEnd }).violations.map((x) => x.code)).toContain("MANDATE_INSURER_ATTESTATION_REQUIRED");
  });
  it("refuses when per-counterparty exposure would be exceeded", () => {
    const book = new ExposureBook();
    book.add("2751903", 8000, "2026-09-18");
    const v = evaluateMandate(LIMITS, baseAccept, book);
    expect(v.violations[0]).toMatchObject({ code: "MANDATE_EXPOSURE_COUNTERPARTY_EXCEEDED", evidence: { outstandingUsd: 8000, wouldBeUsd: 10400 } });
  });
  it("refuses when daily exposure would be exceeded", () => {
    const book = new ExposureBook();
    book.add("other", 23_000, "2026-09-19");
    expect(evaluateMandate(LIMITS, baseAccept, book).violations.map((x) => x.code)).toContain("MANDATE_EXPOSURE_DAILY_EXCEEDED");
  });
  it("refuses beyond the round bound", () => {
    expect(evaluateMandate(LIMITS, { ...baseAccept, round: 7 }).violations.map((x) => x.code)).toContain("NEGOTIATION_MAX_ROUNDS");
  });
  it("reports ALL violations, not just the first", () => {
    const v = evaluateMandate(LIMITS, { ...baseAccept, rateUsd: 5000, equipment: "FLATBED", destinationState: "CA", guaranteeAvailable: false });
    expect(v.violations.length).toBeGreaterThanOrEqual(4);
  });
  it("venue evaluates the registered envelope with the same engine", () => {
    const principal = generateKeyPair();
    const e = issueEnvelope(principal, issueMandate(principal, "p", "broker-1", LIMITS));
    const v = evaluateMandate(envelopeToLimits(e), { ...baseAccept, rateUsd: 3300 });
    expect(v.violations.map((x) => x.code)).toContain("MANDATE_RATE_ABOVE_CEILING");
  });
});
