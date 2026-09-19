/**
 * A simple, parameterized probability-of-loss model. Deliberately legible:
 * each factor is named and its contribution is reported, because a guarantee
 * decision must be explainable to the principal who is paying for it.
 *
 * STUB: coefficients are illustrative, not fitted. A real model would be fitted
 * on pooled loss data (which is the centralization argument in DECISIONS.md Q4).
 */
import type { RiskAssessment, RiskInputs, UnderwritingParams } from "./types";

export function assessRisk(i: RiskInputs, p: UnderwritingParams): RiskAssessment {
  const factors: RiskAssessment["factors"] = [];
  let pd = 0;

  // Authority age is the single strongest public signal for carrier fraud.
  const ageBase = i.authorityAgeDays < 180 ? 0.06 : i.authorityAgeDays < 730 ? 0.03 : 0.012;
  pd += ageBase;
  factors.push({ name: "authorityAge", delta: ageBase, note: `${i.authorityAgeDays}d of authority` });

  if (i.safetyRating === "CONDITIONAL") { pd += 0.02; factors.push({ name: "safetyRating", delta: 0.02, note: "CONDITIONAL" }); }
  if (i.safetyRating === "UNSATISFACTORY") { pd += 0.5; factors.push({ name: "safetyRating", delta: 0.5, note: "UNSATISFACTORY" }); }

  if (i.powerUnits <= 3) { pd += 0.01; factors.push({ name: "fleetSize", delta: 0.01, note: `${i.powerUnits} power units` }); }

  const headroom = i.requiredBipdUsd > 0 ? i.bipdUsd / i.requiredBipdUsd : 1;
  if (headroom < 1.2) { pd += 0.008; factors.push({ name: "insuranceHeadroom", delta: 0.008, note: `coverage ${headroom.toFixed(2)}x required` }); }

  const badFlags = i.vettingFlags.filter((f) => /mismatch|recently-changed|virtual-office|not-found/.test(f));
  if (badFlags.length) { const d = 0.015 * badFlags.length; pd += d; factors.push({ name: "vettingFlags", delta: d, note: badFlags.join(", ") }); }

  if (i.registrySnapshotChangedSinceIssuance) { pd += 0.01; factors.push({ name: "registryDrift", delta: 0.01, note: "registry record changed since credential issuance" }); }

  const completed = i.history.loadsCompleted;
  const histCredit = -Math.min(0.012, completed * 0.0006);
  if (histCredit) { pd += histCredit; factors.push({ name: "history", delta: histCredit, note: `${completed} completed loads on venue` }); }
  if (i.history.claimsPaid) { const d = 0.02 * i.history.claimsPaid; pd += d; factors.push({ name: "claims", delta: d, note: `${i.history.claimsPaid} paid claims` }); }
  if (i.history.disputesOpen) { const d = 0.01 * i.history.disputesOpen; pd += d; factors.push({ name: "disputes", delta: d, note: `${i.history.disputesOpen} open disputes` }); }

  pd = Math.max(0.002, Math.min(0.99, pd));
  const lgd = p.lossGivenDefault;
  return { usdot: i.usdot, probabilityOfLoss: +pd.toFixed(4), lossGivenDefault: lgd, expectedLossUsd: +(pd * lgd * i.amountUsd).toFixed(2), factors };
}

export function pricePremium(a: RiskAssessment, p: UnderwritingParams): number {
  return +Math.max(p.minPremiumUsd, a.expectedLossUsd * p.loadFactor + p.flatFeeUsd).toFixed(2);
}
