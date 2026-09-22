/**
 * Carrier negotiation strategy. PRIVATE: cost structure and margins never
 * leave this process.
 *
 * Model: cost = costPerMile * (loaded + deadhead miles) + fixed. Floor is
 * cost + minimum margin; target is cost + target margin. Opens above target,
 * concedes toward the broker, accepts at target or when the gap is small,
 * never goes below floor (or the mandate floor).
 */
import type { LoadSpec, Terms } from "../../protocol/freight";
import type { Mandate } from "../../mandate/types";
import type { Decision, NegotiationView, Offer, Strategy } from "../../agentkit/types";

export interface CarrierPrivateContext {
  canary: string;
  costPerMileUsd: number;
  deadheadMiles: number;
  fixedCostPerLoadUsd: number;
  minMarginPct: number;
  targetMarginPct: number;
  openingMarkupPct: number;
  concessionPct: number;
  acceptGapPct: number;
  /** Truck availability: earliest pickup this carrier can make. */
  earliestPickup?: string;
  paymentTermsDays: number;
}

const round5 = (x: number) => Math.round(x / 5) * 5;

/** Cost, floor (cost plus minimum margin, never below the mandate), target and opening ask for a load. */
export function economics(load: LoadSpec, ctx: CarrierPrivateContext, m: Mandate) {
  const cost = ctx.costPerMileUsd * (load.miles + ctx.deadheadMiles) + ctx.fixedCostPerLoadUsd;
  const mandateFloor = Math.max(m.limits.minRatePerLoadUsd ?? 0, (m.limits.minRatePerMileUsd ?? 0) * load.miles);
  const floor = Math.ceil(Math.max(cost * (1 + ctx.minMarginPct), mandateFloor));
  const target = Math.ceil(cost * (1 + ctx.targetMarginPct));
  return { cost, floor, target, openingAsk: round5(target * (1 + ctx.openingMarkupPct)) };
}

function pickupFor(load: LoadSpec, ctx: CarrierPrivateContext, offered: Terms["pickup"]): Terms["pickup"] {
  if (!ctx.earliestPickup || new Date(ctx.earliestPickup) <= new Date(offered.windowStart)) return offered;
  const start = new Date(ctx.earliestPickup);
  const end = new Date(Math.max(start.getTime() + 4 * 3_600_000, new Date(offered.windowEnd).getTime()));
  void load;
  return { windowStart: start.toISOString(), windowEnd: end.toISOString() };
}

export const carrierStrategy: Strategy<CarrierPrivateContext> = {
  openingOffer(load, ctx, mandate): Offer {
    const e = economics(load, ctx, mandate);
    return { rateUsd: e.openingAsk, pickup: { windowStart: load.origin.windowStart, windowEnd: load.origin.windowEnd }, delivery: { windowStart: load.destination.windowStart, windowEnd: load.destination.windowEnd }, paymentTermsDays: ctx.paymentTermsDays };
  },

  onTender(view: NegotiationView, ctx, mandate): Decision {
    const e = economics(view.load, ctx, mandate);
    const pickup = pickupFor(view.load, ctx, view.offer.pickup);
    const windowsOk = pickup.windowStart === view.offer.pickup.windowStart;
    if (windowsOk && view.offer.rateUsd >= e.target) return { kind: "ACCEPT" };
    return { kind: "COUNTER", offer: { rateUsd: Math.max(e.openingAsk, view.offer.rateUsd), pickup, delivery: view.offer.delivery, paymentTermsDays: ctx.paymentTermsDays }, noteCode: windowsOk ? "RATE" : "PICKUP_WINDOW" };
  },

  onCounter(view: NegotiationView, ctx, mandate): Decision {
    const e = economics(view.load, ctx, mandate);
    const offer = view.offer.rateUsd;
    const mine = view.myLastOffer?.rateUsd ?? e.openingAsk;
    const pickup = pickupFor(view.load, ctx, view.offer.pickup);
    const windowsOk = pickup.windowStart === view.offer.pickup.windowStart;
    if (windowsOk && offer >= e.floor && (offer >= e.target || (mine - offer) / offer <= ctx.acceptGapPct)) return { kind: "ACCEPT" };
    const next = Math.max(e.floor, round5(mine - ctx.concessionPct * (mine - Math.max(offer, e.floor))));
    if (windowsOk && next <= offer) return { kind: "ACCEPT" };
    return { kind: "COUNTER", offer: { rateUsd: Math.min(next, mine), pickup, delivery: view.offer.delivery, paymentTermsDays: ctx.paymentTermsDays }, noteCode: windowsOk ? "RATE" : "PICKUP_WINDOW" };
  },

  onAcceptRequest(terms: Terms, view: NegotiationView, ctx, mandate) {
    const e = economics(view.load, ctx, mandate);
    const mine = view.myLastOffer;
    if (!mine || terms.rateUsd !== mine.rateUsd) return { kind: "REJECT", reasonCode: "TERMS_MISMATCH" };
    if (terms.rateUsd < e.floor) return { kind: "REJECT", reasonCode: "BELOW_MINIMUM" };
    return { kind: "ACCEPT" };
  },
};
