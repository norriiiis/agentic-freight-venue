/**
 * Claims and the reserve behind the guarantee.
 *
 * A guarantee is a promise to pay a covered loss. This module makes the
 * promise accountable in the two ways the rest of the system is: every
 * claim is adjudicated against DECLARED rules (scope, exclusions, window,
 * beneficiary, cap) with the basis written down, and every dollar it could
 * pay is counted — premiums in, payouts out, over an initial capital float
 * the operator declares. A claim the rules cover but the reserve cannot pay
 * is DEFERRED, not denied and not silently paid from nothing: the honest
 * state of an under-capitalised guarantee, on the record.
 *
 * What is NOT here: the loss adjustment itself. Whether a payment really
 * went to an impersonator is a question of evidence outside this venue;
 * `evidence` is carried, the ops adjudicator can override the rules with a
 * reason, and both are on the ledger.
 */
import { randomUUID } from "node:crypto";
import type { ReasonCode } from "../protocol/reasons";
import { GUARANTEE_SCOPE } from "./types";

export type Peril = "IDENTITY_FRAUD" | "DOUBLE_BROKERING_VIA_VENUE" | "CREDENTIAL_MISBINDING";
export const PERILS: Peril[] = ["IDENTITY_FRAUD", "DOUBLE_BROKERING_VIA_VENUE", "CREDENTIAL_MISBINDING"];

export interface Claim {
  claimId: string;
  guaranteeId: string;
  commitmentId: string;
  claimantUsdot: string;
  peril: Peril | string;
  amountUsd: number;
  filedAt: string;
  evidence: Record<string, unknown>;
  status: "FILED" | "COVERED" | "DENIED" | "DEFERRED" | "PAID";
  decision?: { covered: boolean; reasonCode?: ReasonCode | string; basis: string[]; payoutUsd: number; decidedAt: string; decidedBy: "rules" | "ops" };
  paidAt?: string;
}

export interface Reserve {
  initialCapitalUsd: number;
  premiumsUsd: number;
  payoutsUsd: number;
  /** Outstanding covered amount: what could still be claimed. */
  exposureUsd: number;
}

export interface ClaimContext {
  guarantee?: { guaranteeId: string; commitmentId?: string; beneficiaryUsdot: string; coveredAmountUsd: number; status: string; releaseReason?: string };
  commitment?: { status: string; deliveryWindowEnd: string; voidedAt?: string; lifecycle: { event: string; at: string; by: string }[] };
  now: Date;
  claimWindowDays: number;
}

/** The rules, in the order they are applied. Each is a line of the decision's basis. */
export function adjudicate(c: Claim, ctx: ClaimContext): Claim["decision"] {
  const basis: string[] = [];
  const deny = (reasonCode: string, why: string): Claim["decision"] => ({ covered: false, reasonCode, basis: [...basis, why], payoutUsd: 0, decidedAt: ctx.now.toISOString(), decidedBy: "rules" });
  const g = ctx.guarantee;
  if (!g) return deny("CLAIM_NO_GUARANTEE", "no guarantee attached to this commitment");
  if (g.beneficiaryUsdot !== c.claimantUsdot) return deny("CLAIM_NOT_BENEFICIARY", `claimant ${c.claimantUsdot} is not the beneficiary ${g.beneficiaryUsdot}`);
  basis.push(`claimant is the beneficiary`);
  if (g.status === "RELEASED") return deny("CLAIM_GUARANTEE_RELEASED", `guarantee released (${g.releaseReason ?? "released"}) before the claim`);
  basis.push(`guarantee ${g.status.toLowerCase()}`);
  if (!PERILS.includes(c.peril as Peril)) return deny("CLAIM_PERIL_NOT_IN_SCOPE", `peril ${c.peril} is not in scope: ${GUARANTEE_SCOPE.map((s) => s.split(":")[0]).join(", ")}`);
  basis.push(`peril ${c.peril} is in scope`);
  const cm = ctx.commitment;
  if (cm) {
    const windowEnd = new Date(new Date(cm.deliveryWindowEnd).getTime() + ctx.claimWindowDays * 86_400_000);
    if (ctx.now > windowEnd) return deny("CLAIM_WINDOW_CLOSED", `claim window closed ${windowEnd.toISOString()} (${ctx.claimWindowDays} days after scheduled delivery)`);
    basis.push(`within the ${ctx.claimWindowDays}-day claim window`);
    // Exclusion: the principal proceeded after a VOIDED notice — the lifecycle shows movement after the void.
    if (cm.voidedAt && cm.lifecycle.some((e) => e.event === "PICKED_UP" && e.at > cm.voidedAt!)) return deny("PRINCIPAL_OVERRODE_REFUSAL", `pickup recorded after the commitment was voided at ${cm.voidedAt}`);
  }
  const payoutUsd = Math.min(c.amountUsd, g.coveredAmountUsd);
  basis.push(`payout capped at the covered amount: min(${c.amountUsd}, ${g.coveredAmountUsd}) = ${payoutUsd}`);
  return { covered: true, basis, payoutUsd, decidedAt: ctx.now.toISOString(), decidedBy: "rules" };
}

export function newClaim(input: { guaranteeId: string; commitmentId: string; claimantUsdot: string; peril: string; amountUsd: number; evidence: Record<string, unknown> }, now = new Date()): Claim {
  return { claimId: `clm_${randomUUID()}`, ...input, filedAt: now.toISOString(), status: "FILED" };
}

export function reserveAvailable(r: Reserve): number {
  return r.initialCapitalUsd + r.premiumsUsd - r.payoutsUsd;
}
