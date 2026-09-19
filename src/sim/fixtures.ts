/**
 * Scenario fixtures: one realistic load, and the two principals' agents.
 * Numbers are chosen so the happy path converges in ~5 rounds and the
 * private economics are plausible for a 780-mile dry van lane.
 */
import { randomBytes } from "node:crypto";
import type { LoadSpec } from "../protocol/freight";
import type { AgentSpec } from "./harness";

export const LOAD: LoadSpec = {
  loadRef: "L-2026-262-0417",
  origin: { city: "Pasadena", state: "TX", zip: "77507", windowStart: "2026-09-23T13:00:00.000Z", windowEnd: "2026-09-23T19:00:00.000Z" },
  destination: { city: "Kansas City", state: "MO", zip: "64120", windowStart: "2026-09-24T13:00:00.000Z", windowEnd: "2026-09-24T21:00:00.000Z" },
  equipment: "VAN",
  weightLbs: 38_500,
  commodity: "Consumer packaged goods, palletized",
  miles: 780,
  hazmat: false,
  subcontractPermitted: false,
};

export const PICKUP_DAY = LOAD.origin.windowStart.slice(0, 10);

export const canary = () => `canary-${randomBytes(8).toString("hex")}`;

export function brokerSpec(overrides: Partial<AgentSpec> = {}, privateOverrides: Record<string, unknown> = {}): AgentSpec {
  return {
    agentId: "northline-broker-agent",
    role: "broker",
    entity: { usdot: "3312874", mc: "MC-1088412", legalName: "NORTHLINE LOGISTICS LLC" },
    proofOfControlToken: "poc-northline-7f3a",
    principalName: "Northline Logistics — VP Operations",
    limits: {
      maxRatePerLoadUsd: 3200,
      minRatePerLoadUsd: 900,
      maxRatePerMileUsd: 4.0,
      allowedLaneRegions: ["TX", "OK", "KS", "MO", "AR", "LA"],
      allowedEquipment: ["VAN", "REEFER"],
      hazmatPermitted: false,
      requiredCounterpartyInsuranceUsd: 1_000_000,
      maxPerCounterpartyExposureUsd: 12_000,
      maxDailyExposureUsd: 30_000,
      requireGuarantee: true,
      mayTender: true,
      maxNegotiationRounds: 12,
      paymentTermsDays: { min: 15, max: 45 },
    },
    privateContext: {
      canary: canary(),
      customerRateUsd: 2650,
      targetMarginPct: 0.14,
      minMarginPct: 0.07,
      openingDiscountPct: 0.1,
      concessionPct: 0.35,
      acceptGapPct: 0.03,
      pickupFlexHours: 12,
      paymentTermsDays: 30,
      ...privateOverrides,
    },
    ...overrides,
  };
}

export function carrierSpec(overrides: Partial<AgentSpec> = {}, privateOverrides: Record<string, unknown> = {}): AgentSpec {
  return {
    agentId: "prairie-wind-carrier-agent",
    role: "carrier",
    entity: { usdot: "2751903", mc: "MC-0938251", legalName: "PRAIRIE WIND TRANSPORT INC" },
    proofOfControlToken: "poc-prairie-2c91",
    principalName: "Prairie Wind Transport — Dispatch Manager",
    limits: {
      minRatePerLoadUsd: 1500,
      minRatePerMileUsd: 1.9,
      allowedLaneRegions: ["TX", "OK", "KS", "MO", "NE", "IA", "CO"],
      allowedEquipment: ["VAN"],
      hazmatPermitted: false,
      requiredCounterpartyInsuranceUsd: 75_000,
      maxPerCounterpartyExposureUsd: 20_000,
      maxDailyExposureUsd: 15_000,
      requireGuarantee: false,
      mayTender: false,
      maxNegotiationRounds: 12,
      paymentTermsDays: { min: 15, max: 30 },
    },
    privateContext: {
      canary: canary(),
      costPerMileUsd: 1.85,
      deadheadMiles: 110,
      fixedCostPerLoadUsd: 160,
      minMarginPct: 0.06,
      targetMarginPct: 0.22,
      openingMarkupPct: 0.08,
      concessionPct: 0.35,
      acceptGapPct: 0.03,
      earliestPickup: "2026-09-23T15:00:00.000Z",
      paymentTermsDays: 30,
      ...privateOverrides,
    },
    ...overrides,
  };
}

/** A second credentialed carrier (Blue Mesa holds both carrier and broker authority). Slightly pricier than Prairie Wind. */
export function blueMesaCarrierSpec(overrides: Partial<AgentSpec> = {}, privateOverrides: Record<string, unknown> = {}): AgentSpec {
  const base = carrierSpec(
    {
      agentId: "blue-mesa-carrier-agent",
      entity: { usdot: "1984411", mc: "MC-0711450", legalName: "BLUE MESA CARRIERS INC" },
      proofOfControlToken: "poc-bluemesa-4e77",
      principalName: "Blue Mesa Carriers — Operations Manager",
      ...overrides,
    },
    { costPerMileUsd: 2.05, deadheadMiles: 140, targetMarginPct: 0.2, earliestPickup: undefined, ...privateOverrides },
  );
  base.privateContext.canary = canary();
  return base;
}

/** Prior on-venue history for the carrier, so underwriting has something to look at. */
export const CARRIER_HISTORY = { loadsCommitted: 16, loadsCompleted: 14, claimsPaid: 0, disputesOpen: 0, firstLoadAt: "2026-02-11T15:02:00.000Z", lastLoadAt: "2026-09-12T18:40:00.000Z" };
