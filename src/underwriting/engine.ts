/**
 * Underwriting engine: decides whether to stand behind a transaction, prices
 * it, and tracks the venue's aggregate guaranteed exposure.
 */
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ExposureBook } from "../mandate/exposure";
import { assessRisk, pricePremium } from "./model";
import { DEFAULT_PARAMS, GUARANTEE_CONDITIONS, GUARANTEE_EXCLUSIONS, GUARANTEE_SCOPE, type CounterpartyHistory, type ExposureView, type RiskInputs, type UnderwritingDecision, type UnderwritingParams } from "./types";

export interface GuaranteeRecord {
  guaranteeId: string;
  commitmentId?: string;
  counterpartyUsdot: string;
  beneficiaryUsdot: string;
  coveredAmountUsd: number;
  premiumUsd: number;
  status: "QUOTED" | "ATTACHED" | "RELEASED" | "CLAIMABLE";
  attachedAt?: string;
  releasedAt?: string;
  releaseReason?: string;
  day: string;
}

export class UnderwritingEngine {
  private readonly counterparty: ExposureBook;
  private readonly pair: ExposureBook;
  private portfolioUsd = 0;
  private guarantees = new Map<string, GuaranteeRecord>();
  private history: Record<string, CounterpartyHistory> = {};
  private readonly dir: string;

  constructor(dataDir: string, public readonly params: UnderwritingParams = DEFAULT_PARAMS) {
    this.dir = join(dataDir, "underwriting");
    mkdirSync(this.dir, { recursive: true });
    this.counterparty = new ExposureBook(join(this.dir, "exposure-counterparty.json"));
    this.pair = new ExposureBook(join(this.dir, "exposure-pair.json"));
    const g = join(this.dir, "guarantees.json");
    if (existsSync(g)) for (const x of JSON.parse(readFileSync(g, "utf8")) as GuaranteeRecord[]) this.guarantees.set(x.guaranteeId, x);
    const h = join(this.dir, "history.json");
    if (existsSync(h)) this.history = JSON.parse(readFileSync(h, "utf8"));
    this.portfolioUsd = [...this.guarantees.values()].filter((x) => x.status === "ATTACHED").reduce((a, x) => a + x.coveredAmountUsd, 0);
  }
  private persist() {
    writeFileSync(join(this.dir, "guarantees.json"), JSON.stringify([...this.guarantees.values()], null, 2));
    writeFileSync(join(this.dir, "history.json"), JSON.stringify(this.history, null, 2));
  }

  historyFor(usdot: string): CounterpartyHistory {
    return this.history[usdot] ?? { loadsCommitted: 0, loadsCompleted: 0, claimsPaid: 0, disputesOpen: 0 };
  }
  /** SIM-ONLY: seed prior history / exposure. */
  seedHistory(usdot: string, h: CounterpartyHistory) {
    this.history[usdot] = h;
    this.persist();
  }
  seedExposure(counterpartyUsdot: string, beneficiaryUsdot: string, amountUsd: number, day: string, note: string) {
    const g: GuaranteeRecord = { guaranteeId: `gtee_seed_${randomUUID().slice(0, 8)}`, commitmentId: `seed:${note}`, counterpartyUsdot, beneficiaryUsdot, coveredAmountUsd: amountUsd, premiumUsd: 0, status: "ATTACHED", attachedAt: new Date().toISOString(), day };
    this.guarantees.set(g.guaranteeId, g);
    this.counterparty.add(counterpartyUsdot, amountUsd, day);
    this.pair.add(`${beneficiaryUsdot}|${counterpartyUsdot}`, amountUsd, day);
    this.portfolioUsd += amountUsd;
    this.persist();
    return g;
  }

  exposure(counterpartyUsdot: string, beneficiaryUsdot: string): ExposureView {
    return {
      counterpartyOutstandingUsd: this.counterparty.outstanding(counterpartyUsdot),
      counterpartyLimitUsd: this.params.maxCounterpartyExposureUsd,
      pairOutstandingUsd: this.pair.outstanding(`${beneficiaryUsdot}|${counterpartyUsdot}`),
      portfolioOutstandingUsd: this.portfolioUsd,
      portfolioLimitUsd: this.params.maxPortfolioExposureUsd,
    };
  }

  /**
   * Quote a guarantee for `beneficiary` against `counterparty` risk. Does not
   * consume exposure; call attach() once the commitment is recorded.
   */
  quote(inputs: RiskInputs, beneficiaryUsdot: string, day: string): UnderwritingDecision {
    const assessment = assessRisk(inputs, this.params);
    const exp = this.exposure(inputs.usdot, beneficiaryUsdot);
    if (assessment.probabilityOfLoss > this.params.maxProbabilityOfLoss) {
      return { decision: "DECLINED", assessment, reasonCode: "UNDERWRITING_DECLINED_RISK", evidence: { probabilityOfLoss: assessment.probabilityOfLoss, threshold: this.params.maxProbabilityOfLoss, factors: assessment.factors }, exposureAfter: exp };
    }
    if (exp.counterpartyOutstandingUsd + inputs.amountUsd > exp.counterpartyLimitUsd) {
      return {
        decision: "DECLINED",
        assessment,
        reasonCode: "VENUE_EXPOSURE_LIMIT_EXCEEDED",
        evidence: { counterpartyUsdot: inputs.usdot, outstandingUsd: exp.counterpartyOutstandingUsd, thisLoadUsd: inputs.amountUsd, wouldBeUsd: exp.counterpartyOutstandingUsd + inputs.amountUsd, limitUsd: exp.counterpartyLimitUsd, attachedGuarantees: [...this.guarantees.values()].filter((g) => g.counterpartyUsdot === inputs.usdot && g.status === "ATTACHED").map((g) => ({ guaranteeId: g.guaranteeId, commitmentId: g.commitmentId, coveredAmountUsd: g.coveredAmountUsd })) },
        exposureAfter: exp,
      };
    }
    if (exp.portfolioOutstandingUsd + inputs.amountUsd > exp.portfolioLimitUsd) {
      return { decision: "DECLINED", assessment, reasonCode: "VENUE_PORTFOLIO_LIMIT_EXCEEDED", evidence: { portfolioOutstandingUsd: exp.portfolioOutstandingUsd, limitUsd: exp.portfolioLimitUsd }, exposureAfter: exp };
    }
    const premiumUsd = pricePremium(assessment, this.params);
    const guaranteeId = `gtee_${randomUUID()}`;
    this.guarantees.set(guaranteeId, { guaranteeId, counterpartyUsdot: inputs.usdot, beneficiaryUsdot, coveredAmountUsd: inputs.amountUsd, premiumUsd, status: "QUOTED", day });
    this.persist();
    return {
      decision: "GUARANTEED",
      assessment,
      guarantee: { guaranteeId, coveredAmountUsd: inputs.amountUsd, premiumUsd, scope: GUARANTEE_SCOPE, exclusions: GUARANTEE_EXCLUSIONS, conditions: GUARANTEE_CONDITIONS },
      exposureAfter: { ...exp, counterpartyOutstandingUsd: exp.counterpartyOutstandingUsd + inputs.amountUsd, pairOutstandingUsd: exp.pairOutstandingUsd + inputs.amountUsd, portfolioOutstandingUsd: exp.portfolioOutstandingUsd + inputs.amountUsd },
    };
  }

  attach(guaranteeId: string, commitmentId: string): GuaranteeRecord {
    const g = this.guarantees.get(guaranteeId);
    if (!g || g.status !== "QUOTED") throw new Error(`guarantee ${guaranteeId} not quoted`);
    g.status = "ATTACHED";
    g.commitmentId = commitmentId;
    g.attachedAt = new Date().toISOString();
    this.counterparty.add(g.counterpartyUsdot, g.coveredAmountUsd, g.day);
    this.pair.add(`${g.beneficiaryUsdot}|${g.counterpartyUsdot}`, g.coveredAmountUsd, g.day);
    this.portfolioUsd += g.coveredAmountUsd;
    const h = (this.history[g.counterpartyUsdot] ??= { loadsCommitted: 0, loadsCompleted: 0, claimsPaid: 0, disputesOpen: 0 });
    h.loadsCommitted += 1;
    h.lastLoadAt = g.attachedAt;
    h.firstLoadAt ??= g.attachedAt;
    this.persist();
    return g;
  }

  release(guaranteeId: string, reason: string): GuaranteeRecord | undefined {
    const g = this.guarantees.get(guaranteeId);
    if (!g || g.status !== "ATTACHED") return undefined;
    g.status = "RELEASED";
    g.releasedAt = new Date().toISOString();
    g.releaseReason = reason;
    this.counterparty.release(g.counterpartyUsdot, g.coveredAmountUsd, g.day);
    this.pair.release(`${g.beneficiaryUsdot}|${g.counterpartyUsdot}`, g.coveredAmountUsd, g.day);
    this.portfolioUsd -= g.coveredAmountUsd;
    this.persist();
    return g;
  }

  guaranteeForCommitment(commitmentId: string): GuaranteeRecord | undefined {
    return [...this.guarantees.values()].find((g) => g.commitmentId === commitmentId);
  }
  allGuarantees(): GuaranteeRecord[] {
    return [...this.guarantees.values()];
  }
}
