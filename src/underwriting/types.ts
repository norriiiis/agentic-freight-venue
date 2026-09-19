import type { ReasonCode } from "../protocol/reasons";
import type { GuaranteeSummary } from "../ledger/artifact";

export interface CounterpartyHistory {
  loadsCommitted: number;
  loadsCompleted: number;
  claimsPaid: number;
  disputesOpen: number;
  firstLoadAt?: string;
  lastLoadAt?: string;
}

export interface RiskInputs {
  usdot: string;
  authorityAgeDays: number;
  safetyRating: "SATISFACTORY" | "CONDITIONAL" | "UNSATISFACTORY" | "NONE";
  powerUnits: number;
  bipdUsd: number;
  requiredBipdUsd: number;
  vettingFlags: string[];
  credentialAgeDays: number;
  registrySnapshotChangedSinceIssuance: boolean;
  history: CounterpartyHistory;
  amountUsd: number;
}

export interface RiskAssessment {
  usdot: string;
  probabilityOfLoss: number; // PD
  lossGivenDefault: number;  // LGD
  expectedLossUsd: number;   // PD * LGD * amount
  factors: { name: string; delta: number; note: string }[];
}

export type UnderwritingDecision =
  | { decision: "GUARANTEED"; assessment: RiskAssessment; guarantee: GuaranteeSummary; exposureAfter: ExposureView }
  | { decision: "DECLINED"; assessment: RiskAssessment; reasonCode: ReasonCode; evidence: Record<string, unknown>; exposureAfter?: ExposureView };

export interface ExposureView {
  counterpartyOutstandingUsd: number;
  counterpartyLimitUsd: number;
  pairOutstandingUsd: number;
  portfolioOutstandingUsd: number;
  portfolioLimitUsd: number;
}

export interface UnderwritingParams {
  /** Decline above this probability of loss. */
  maxProbabilityOfLoss: number;
  /** Multiplier over expected loss to cover expenses + capital. */
  loadFactor: number;
  flatFeeUsd: number;
  minPremiumUsd: number;
  maxCounterpartyExposureUsd: number;
  maxPortfolioExposureUsd: number;
  lossGivenDefault: number;
}

export const DEFAULT_PARAMS: UnderwritingParams = {
  maxProbabilityOfLoss: 0.08,
  loadFactor: 1.35,
  flatFeeUsd: 4,
  minPremiumUsd: 12,
  maxCounterpartyExposureUsd: 40_000,
  maxPortfolioExposureUsd: 2_000_000,
  lossGivenDefault: 0.9,
};

/** What the guarantee is and is not. This is the product; see DECISIONS.md Q3. */
export const GUARANTEE_SCOPE = [
  "IDENTITY_FRAUD: payment made to an impersonator whose credential this venue verified",
  "DOUBLE_BROKERING_VIA_VENUE: the committed carrier re-tendered the load through this venue and the venue failed to block it",
  "CREDENTIAL_MISBINDING: the venue bound an agent key to the wrong registry entity",
];
export const GUARANTEE_EXCLUSIONS = [
  "NON_PERFORMANCE: late, no-show, service failure",
  "CARGO_LOSS_OR_DAMAGE: covered by the carrier's cargo policy, not this guarantee",
  "OFF_VENUE_ARRANGEMENTS: anything agreed outside a venue-recorded commitment",
  "PRINCIPAL_OVERRODE_REFUSAL: the principal proceeded after a VOIDED or REFUSED notice",
  "CONTROLS_BYPASSED: the claimant disabled or bypassed mandate/identity checks",
  "PRINCIPAL_KEY_COMPROMISE: loss from a stolen or leaked agent key held by the principal, before the principal declared the compromise",
];
export const GUARANTEE_CONDITIONS = [
  "Venue controls functioned as designed at commitment time (audit trail intact)",
  "Commitment artifact verifies against the venue key",
  "Claim filed within 90 days of scheduled delivery",
];
