/**
 * Broker negotiation strategy. PRIVATE: this file and the context it reads
 * are never disclosed. The venue and the carrier see only offers.
 *
 * Model: the broker holds a customer (shipper) rate. It wants to pay a carrier
 * as little as possible above a target margin, and will never pay above
 * min(mandate ceiling, customerRate * (1 - minMargin)).
 */
import type { LoadSpec, Terms } from "../../protocol/freight";
import type { Mandate } from "../../mandate/types";
import type { Decision, NegotiationView, Offer, Strategy } from "../../agentkit/types";

export interface BrokerPrivateContext {
  canary: string;
  customerRateUsd: number;
  targetMarginPct: number;
  minMarginPct: number;
  openingDiscountPct: number;
  concessionPct: number;
  acceptGapPct: number;
  pickupFlexHours: number;
  paymentTermsDays: number;
}

const round5 = (x: number) => Math.round(x / 5) * 5;

/** The most this principal will pay for a load: the private margin floor, the mandate ceiling, the per-mile ceiling. */
export function maxPay(ctx: BrokerPrivateContext, m: Mandate, miles: number): number {
  const byMargin = ctx.customerRateUsd * (1 - ctx.minMarginPct);
  const byLoad = m.limits.maxRatePerLoadUsd ?? Number.POSITIVE_INFINITY;
  const byMile = m.limits.maxRatePerMileUsd ? m.limits.maxRatePerMileUsd * miles : Number.POSITIVE_INFINITY;
  return Math.floor(Math.min(byMargin, byLoad, byMile));
}

function hoursBetween(a: string, b: string) {
  return Math.abs(new Date(a).getTime() - new Date(b).getTime()) / 3_600_000;
}

export const brokerStrategy: Strategy<BrokerPrivateContext> = {
  openingOffer(load: LoadSpec, ctx, mandate): Offer {
    const target = ctx.customerRateUsd * (1 - ctx.targetMarginPct);
    const rate = Math.min(round5(target * (1 - ctx.openingDiscountPct)), maxPay(ctx, mandate, load.miles));
    return {
      rateUsd: rate,
      pickup: { windowStart: load.origin.windowStart, windowEnd: load.origin.windowEnd },
      delivery: { windowStart: load.destination.windowStart, windowEnd: load.destination.windowEnd },
      paymentTermsDays: ctx.paymentTermsDays,
    };
  },

  onTender(): Decision {
    return { kind: "REJECT", reasonCode: "NO_INBOUND_TENDERS" };
  },

  onCounter(view: NegotiationView, ctx, mandate): Decision {
    const ask = view.offer.rateUsd;
    const mine = view.myLastOffer?.rateUsd ?? 0;
    const cap = maxPay(ctx, mandate, view.load.miles);

    // Pickup window: tolerate a shifted pickup within flex; otherwise hold ours.
    const shifted = hoursBetween(view.offer.pickup.windowStart, view.load.origin.windowStart);
    const pickup = shifted <= ctx.pickupFlexHours ? view.offer.pickup : (view.myLastOffer?.pickup ?? { windowStart: view.load.origin.windowStart, windowEnd: view.load.origin.windowEnd });
    const windowsOk = shifted <= ctx.pickupFlexHours;

    if (windowsOk && ask <= cap && (ask <= mine || (ask - mine) / ask <= ctx.acceptGapPct)) {
      return { kind: "ACCEPT" };
    }
    const next = Math.min(cap, round5(mine + ctx.concessionPct * (Math.min(ask, cap) - mine)));
    if (windowsOk && next >= ask) return { kind: "ACCEPT" };
    // The window we want is in the offer itself; a code says which term is the sticking point.
    // (A free-text note here once leaked pickupFlexHours — private context — onto the wire.)
    return {
      kind: "COUNTER",
      offer: { rateUsd: Math.max(next, mine), pickup, delivery: view.offer.delivery, paymentTermsDays: ctx.paymentTermsDays },
      noteCode: windowsOk ? "RATE" : "PICKUP_WINDOW",
    };
  },

  onAcceptRequest(terms: Terms, view: NegotiationView, ctx, mandate) {
    // The carrier accepted an offer; countersign only if it is exactly what we last put on the table.
    const mine = view.myLastOffer;
    if (!mine || terms.rateUsd !== mine.rateUsd || terms.paymentTermsDays !== mine.paymentTermsDays) {
      return { kind: "REJECT", reasonCode: "TERMS_MISMATCH" };
    }
    if (terms.rateUsd > maxPay(ctx, mandate, view.load.miles)) return { kind: "REJECT", reasonCode: "ABOVE_MAXIMUM" };
    return { kind: "ACCEPT" };
  },
};
