/**
 * Mapping from a commitment artifact onto the documents the industry already
 * exchanges: a rate confirmation, and the X12 850 (tender / purchase order),
 * 855 (acknowledgment) and 856 (ship notice) transaction sets.
 *
 * The 850/855/856 mapping below is a segment-level OUTLINE, per the brief.
 * The motor-carrier sets the industry actually exchanges for truckload —
 * 204 Load Tender, 990 Response, 214 Shipment Status — are serialized in
 * full (envelopes, control numbers, parse-back) in `x12.ts`.
 */
import type { CommitmentArtifact } from "../ledger/artifact";

export interface RateConfirmation {
  documentType: "RATE_CONFIRMATION";
  confirmationNumber: string;
  issuedAt: string;
  broker: { legalName: string; mc?: string; usdot: string };
  carrier: { legalName: string; mc?: string; usdot: string };
  load: { reference: string; equipment: string; weightLbs: number; commodity: string; miles: number; hazmat: boolean };
  stops: { type: "PICKUP" | "DELIVERY"; city: string; state: string; zip: string; windowStart: string; windowEnd: string }[];
  rate: { linehaulUsd: number; fuelSurchargeUsd: number; totalUsd: number; currency: "USD" };
  paymentTerms: string;
  subcontractingProhibited: boolean;
  signatures: { broker: { signedAt: string; agentId: string; kid: string }; carrier: { signedAt: string; agentId: string; kid: string } };
  venueAttestation: { venueId: string; commitmentId: string; termsHash: string; guaranteeId?: string };
}

export function toRateConfirmation(a: CommitmentArtifact): RateConfirmation {
  const t = a.terms;
  const b = a.credentials.broker.subject;
  const c = a.credentials.carrier.subject;
  const kid = (m: CommitmentArtifact["acceptances"]["broker"]) => {
    const sig = (m.metadata as { sig?: string }).sig ?? "";
    try {
      return JSON.parse(Buffer.from(sig.split(".")[0] ?? "", "base64url").toString("utf8")).kid as string;
    } catch {
      return "?";
    }
  };
  return {
    documentType: "RATE_CONFIRMATION",
    confirmationNumber: a.commitmentId,
    issuedAt: a.createdAt,
    broker: { legalName: b.entity.legalName, mc: b.entity.mc, usdot: b.entity.usdot },
    carrier: { legalName: c.entity.legalName, mc: c.entity.mc, usdot: c.entity.usdot },
    load: { reference: t.loadRef, equipment: t.load.equipment, weightLbs: t.load.weightLbs, commodity: t.load.commodity, miles: t.load.miles, hazmat: t.load.hazmat },
    stops: [
      { type: "PICKUP", city: t.load.origin.city, state: t.load.origin.state, zip: t.load.origin.zip, windowStart: t.pickup.windowStart, windowEnd: t.pickup.windowEnd },
      { type: "DELIVERY", city: t.load.destination.city, state: t.load.destination.state, zip: t.load.destination.zip, windowStart: t.delivery.windowStart, windowEnd: t.delivery.windowEnd },
    ],
    rate: { linehaulUsd: t.rateUsd, fuelSurchargeUsd: 0, totalUsd: t.rateUsd, currency: "USD" },
    paymentTerms: `NET ${t.paymentTermsDays}`,
    subcontractingProhibited: !t.load.subcontractPermitted,
    signatures: {
      broker: { signedAt: String((a.acceptances.broker.metadata as { ts?: string }).ts), agentId: b.agentId, kid: kid(a.acceptances.broker) },
      carrier: { signedAt: String((a.acceptances.carrier.metadata as { ts?: string }).ts), agentId: c.agentId, kid: kid(a.acceptances.carrier) },
    },
    venueAttestation: { venueId: a.venue.venueId, commitmentId: a.commitmentId, termsHash: a.termsHash, guaranteeId: a.underwriting.guarantee?.guaranteeId },
  };
}

/** X12 segment outline for the three transaction sets a commitment feeds. */
export function toX12Outline(a: CommitmentArtifact): { set: "850" | "855" | "856"; purpose: string; segments: string[] }[] {
  const t = a.terms;
  const d = (iso: string) => iso.slice(0, 10).replace(/-/g, "");
  const tm = (iso: string) => iso.slice(11, 16).replace(":", "");
  const o = t.load.origin;
  const x = t.load.destination;
  return [
    {
      set: "850",
      purpose: "Tender / purchase order from broker to carrier (the TENDER message)",
      segments: [
        `BEG*00*SA*${t.loadRef}**${d(a.createdAt)}`,
        `REF*CN*${a.commitmentId}`,
        `REF*ZZ*termsHash:${a.termsHash.slice(0, 16)}`,
        `N1*BY*${a.credentials.broker.subject.entity.legalName}*ZZ*${t.brokerEntity.mc ?? t.brokerEntity.usdot}`,
        `N1*CA*${a.credentials.carrier.subject.entity.legalName}*ZZ*${t.carrierEntity.mc ?? t.carrierEntity.usdot}`,
        `N1*SF*${o.city} ${o.state}`, `N4*${o.city}*${o.state}*${o.zip}`,
        `DTM*010*${d(t.pickup.windowStart)}*${tm(t.pickup.windowStart)}`,
        `N1*ST*${x.city} ${x.state}`, `N4*${x.city}*${x.state}*${x.zip}`,
        `DTM*002*${d(t.delivery.windowStart)}*${tm(t.delivery.windowStart)}`,
        `TD5**2*${t.carrierEntity.mc ?? ""}*M`, `TD4**${t.load.hazmat ? "HM" : ""}`,
        `PO1*1*1*EA*${t.rateUsd.toFixed(2)}**VC*${t.load.equipment}`,
        `ITD*01*3*****${t.paymentTermsDays}`,
        `CTT*1`,
      ],
    },
    {
      set: "855",
      purpose: "Acknowledgment from carrier (the carrier's ACCEPT message)",
      segments: [`BAK*00*AD*${t.loadRef}*${d(a.createdAt)}`, `REF*CN*${a.commitmentId}`, `ACK*IA*1*EA***VC*${t.load.equipment}`, `PO1*1*1*EA*${t.rateUsd.toFixed(2)}`, `CTT*1`],
    },
    {
      set: "856",
      purpose: "Ship notice at pickup (downstream of this prototype; commitment supplies the references)",
      segments: [`BSN*00*${t.loadRef}*${d(t.pickup.windowStart)}*${tm(t.pickup.windowStart)}`, `HL*1**S`, `TD5**2*${t.carrierEntity.mc ?? ""}*M`, `REF*CN*${a.commitmentId}`, `N1*SF*${o.city}`, `N1*ST*${x.city}`, `HL*2*1*O`, `PRF*${t.loadRef}`],
    },
  ];
}
