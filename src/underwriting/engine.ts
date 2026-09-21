/**
 * Underwriting engine: decides whether to stand behind a transaction, prices
 * it, and tracks the venue's aggregate guaranteed exposure.
 */
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ExposureBook } from "../mandate/exposure";
import { writeFileAtomic } from "../protocol/fsatomic";
import { assessRisk, pricePremium } from "./model";
import { adjudicate, newClaim, reserveAvailable, type Claim, type ClaimContext, type Reserve } from "./claims";
import { DEFAULT_PARAMS, GUARANTEE_CONDITIONS, GUARANTEE_EXCLUSIONS, GUARANTEE_SCOPE, type CounterpartyHistory, type ExposureView, type RiskInputs, type UnderwritingDecision, type UnderwritingParams } from "./types";

export interface GuaranteeRecord {
  guaranteeId: string;
  commitmentId?: string;
  counterpartyUsdot: string;
  beneficiaryUsdot: string;
  coveredAmountUsd: number;
  premiumUsd: number;
  /** ATTACHED while the load is open; CLAIMABLE from completion until the claim window closes; RELEASED after (or on void). */
  status: "ATTACHED" | "RELEASED" | "CLAIMABLE";
  attachedAt?: string;
  releasedAt?: string;
  releaseReason?: string;
  completedAt?: string;
  claimWindowEndsAt?: string;
  day: string;
}

export class UnderwritingEngine {
  private readonly counterparty: ExposureBook;
  private readonly pair: ExposureBook;
  private claims = new Map<string, Claim>();
  private reserve: Reserve = { initialCapitalUsd: 0, premiumsUsd: 0, payoutsUsd: 0, exposureUsd: 0 };
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
    const c = join(this.dir, "claims.json");
    if (existsSync(c)) for (const x of JSON.parse(readFileSync(c, "utf8")) as Claim[]) this.claims.set(x.claimId, x);
    const r = join(this.dir, "reserve.json");
    this.reserve = existsSync(r) ? JSON.parse(readFileSync(r, "utf8")) : { initialCapitalUsd: this.params.initialCapitalUsd ?? 0, premiumsUsd: 0, payoutsUsd: 0, exposureUsd: 0 };
    const h = join(this.dir, "history.json");
    if (existsSync(h)) this.history = JSON.parse(readFileSync(h, "utf8"));
    this.portfolioUsd = [...this.guarantees.values()].filter((x) => x.status === "ATTACHED").reduce((a, x) => a + x.coveredAmountUsd, 0);
  }
  private persist() {
    writeFileAtomic(join(this.dir, "guarantees.json"), JSON.stringify([...this.guarantees.values()], null, 2));
    writeFileAtomic(join(this.dir, "history.json"), JSON.stringify(this.history, null, 2));
    writeFileAtomic(join(this.dir, "claims.json"), JSON.stringify([...this.claims.values()], null, 2));
    this.reserve.exposureUsd = [...this.guarantees.values()].filter((g) => g.status !== "RELEASED").reduce((a, g) => a + g.coveredAmountUsd, 0);
    writeFileAtomic(join(this.dir, "reserve.json"), JSON.stringify(this.reserve, null, 2));
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
    this.counterparty.add(counterpartyUsdot, amountUsd, day, g.guaranteeId);
    this.pair.add(`${beneficiaryUsdot}|${counterpartyUsdot}`, amountUsd, day, g.guaranteeId);
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
   * Quote a guarantee for `beneficiary` against `counterparty` risk. PURE:
   * consumes no exposure and writes nothing. attach() makes it real, keyed by
   * the commitment id so re-applying after a crash is a no-op.
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
    return {
      decision: "GUARANTEED",
      assessment,
      guarantee: { guaranteeId, coveredAmountUsd: inputs.amountUsd, premiumUsd, scope: GUARANTEE_SCOPE, exclusions: GUARANTEE_EXCLUSIONS, conditions: GUARANTEE_CONDITIONS },
      exposureAfter: { ...exp, counterpartyOutstandingUsd: exp.counterpartyOutstandingUsd + inputs.amountUsd, pairOutstandingUsd: exp.pairOutstandingUsd + inputs.amountUsd, portfolioOutstandingUsd: exp.portfolioOutstandingUsd + inputs.amountUsd },
    };
  }

  /**
   * Attach a quoted guarantee to a recorded commitment. Idempotent: a second
   * call for the same commitment returns the existing record and changes
   * nothing — this is what lets crash recovery re-apply a commit safely.
   */
  attach(q: { guaranteeId: string; counterpartyUsdot: string; beneficiaryUsdot: string; coveredAmountUsd: number; premiumUsd: number; day: string }, commitmentId: string): GuaranteeRecord {
    const existing = this.guaranteeForCommitment(commitmentId);
    if (existing) return existing;
    const g: GuaranteeRecord = { ...q, commitmentId, status: "ATTACHED", attachedAt: new Date().toISOString() };
    this.guarantees.set(g.guaranteeId, g);
    this.counterparty.add(g.counterpartyUsdot, g.coveredAmountUsd, g.day, commitmentId);
    this.pair.add(`${g.beneficiaryUsdot}|${g.counterpartyUsdot}`, g.coveredAmountUsd, g.day, commitmentId);
    this.portfolioUsd += g.coveredAmountUsd;
    const h = (this.history[g.counterpartyUsdot] ??= { loadsCommitted: 0, loadsCompleted: 0, claimsPaid: 0, disputesOpen: 0 });
    h.loadsCommitted += 1;
    h.lastLoadAt = g.attachedAt;
    h.firstLoadAt ??= g.attachedAt;
    this.reserve.premiumsUsd += g.premiumUsd; // the premium is earned into the reserve at attach
    this.persist();
    return g;
  }

  /** The load completed: the counterparty's history improves, and the guarantee stays claimable for the claim window. */
  complete(guaranteeId: string, deliveryWindowEnd: string, now = new Date()): GuaranteeRecord | undefined {
    const g = this.guarantees.get(guaranteeId);
    if (!g || g.status === "RELEASED") return g;
    if (g.status === "CLAIMABLE") return g;
    g.status = "CLAIMABLE";
    g.completedAt = now.toISOString();
    g.claimWindowEndsAt = new Date(new Date(deliveryWindowEnd).getTime() + this.params.claimWindowDays * 86_400_000).toISOString();
    const h = (this.history[g.counterpartyUsdot] ??= { loadsCommitted: 0, loadsCompleted: 0, claimsPaid: 0, disputesOpen: 0 });
    h.loadsCompleted += 1;
    this.persist();
    return g;
  }

  /** Claim windows that closed: release (exposure returns to the books). */
  expireClaimWindows(now = new Date()): GuaranteeRecord[] {
    const out: GuaranteeRecord[] = [];
    for (const g of this.guarantees.values()) {
      if (g.status === "CLAIMABLE" && g.claimWindowEndsAt && new Date(g.claimWindowEndsAt) <= now && ![...this.claims.values()].some((c) => c.guaranteeId === g.guaranteeId && (c.status === "FILED" || c.status === "DEFERRED"))) {
        this.release(g.guaranteeId, "claim window closed");
        out.push(g);
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- claims

  /** File and adjudicate by the declared rules; pay from the reserve if it can, else DEFER on the record. */
  fileClaim(input: { guaranteeId: string; commitmentId: string; claimantUsdot: string; peril: string; amountUsd: number; evidence: Record<string, unknown> }, commitment: ClaimContext["commitment"], now = new Date()): Claim {
    const c = newClaim(input, now);
    const g = this.guarantees.get(input.guaranteeId);
    c.decision = adjudicate(c, { guarantee: g, commitment, now, claimWindowDays: this.params.claimWindowDays });
    c.status = c.decision!.covered ? "COVERED" : "DENIED";
    this.claims.set(c.claimId, c);
    if (c.decision!.covered) this.settle(c, now);
    this.persist();
    return c;
  }

  /** A human adjudicator overrides the rules, with a reason on the record. */
  decideClaim(claimId: string, decision: { covered: boolean; reasonCode?: string; why: string; payoutUsd?: number }, now = new Date()): Claim | undefined {
    const c = this.claims.get(claimId);
    if (!c || c.status === "PAID") return c;
    const g = this.guarantees.get(c.guaranteeId);
    c.decision = { covered: decision.covered, reasonCode: decision.reasonCode, basis: [`ops: ${decision.why}`], payoutUsd: decision.covered ? Math.min(decision.payoutUsd ?? c.amountUsd, g?.coveredAmountUsd ?? 0) : 0, decidedAt: now.toISOString(), decidedBy: "ops" };
    c.status = decision.covered ? "COVERED" : "DENIED";
    if (c.decision.covered) this.settle(c, now);
    this.persist();
    return c;
  }

  /** Pay a covered claim if the reserve can bear it; otherwise leave it DEFERRED — never paid from nothing. Idempotent. */
  private settle(c: Claim, now: Date) {
    if (c.status === "PAID" || !c.decision?.covered) return;
    if (reserveAvailable(this.reserve) < c.decision.payoutUsd) { c.status = "DEFERRED"; return; }
    this.reserve.payoutsUsd += c.decision.payoutUsd;
    c.status = "PAID";
    c.paidAt = now.toISOString();
    const g = this.guarantees.get(c.guaranteeId);
    if (g) {
      const h = (this.history[g.counterpartyUsdot] ??= { loadsCommitted: 0, loadsCompleted: 0, claimsPaid: 0, disputesOpen: 0 });
      h.claimsPaid += 1;
      this.release(g.guaranteeId, `claim ${c.claimId} paid`);
    }
  }

  /** Retry deferred claims (after capital was added). */
  settleDeferred(now = new Date()): Claim[] {
    const paid: Claim[] = [];
    for (const c of this.claims.values()) if (c.status === "DEFERRED") { this.settle(c, now); if ((c.status as Claim["status"]) === "PAID") paid.push(c); }
    if (paid.length) this.persist();
    return paid;
  }

  adjustDisputes(usdot: string, delta: number) {
    const h = (this.history[usdot] ??= { loadsCommitted: 0, loadsCompleted: 0, claimsPaid: 0, disputesOpen: 0 });
    h.disputesOpen = Math.max(0, h.disputesOpen + delta);
    this.persist();
  }
  addCapital(usd: number) {
    this.reserve.initialCapitalUsd += usd;
    this.persist();
  }
  reserveView(): Reserve & { availableUsd: number } {
    this.reserve.exposureUsd = [...this.guarantees.values()].filter((g) => g.status !== "RELEASED").reduce((a, g) => a + g.coveredAmountUsd, 0);
    return { ...this.reserve, availableUsd: reserveAvailable(this.reserve) };
  }
  claim(claimId: string): Claim | undefined {
    return this.claims.get(claimId);
  }
  allClaims(): Claim[] {
    return [...this.claims.values()];
  }

  /** Idempotent: releasing an already-released guarantee returns it unchanged. */
  release(guaranteeId: string, reason: string): GuaranteeRecord | undefined {
    const g = this.guarantees.get(guaranteeId);
    if (!g) return undefined;
    if (g.status === "RELEASED") return g;
    g.status = "RELEASED";
    g.releasedAt = new Date().toISOString();
    g.releaseReason = reason;
    this.counterparty.release(g.counterpartyUsdot, g.coveredAmountUsd, g.day, g.commitmentId ?? g.guaranteeId);
    this.pair.release(`${g.beneficiaryUsdot}|${g.counterpartyUsdot}`, g.coveredAmountUsd, g.day, g.commitmentId ?? g.guaranteeId);
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
