/**
 * The ONE sanctioned way to put a negotiation in front of a language model.
 *
 * Renders a NegotiationView as a fixed-shape, code-and-number-only block.
 * Nothing the counterparty typed can appear here: the view type carries no
 * free text, and this function only emits enum codes, numbers, ISO dates and
 * registry identifiers that the venue validated against the closed schema.
 *
 * An LLM-backed Strategy should build its prompt from this string plus its own
 * private context and mandate — never from a raw Message.
 */
import type { NegotiationView } from "./types";

export function viewToPromptContext(v: NegotiationView): string {
  const l = v.load;
  const cp = v.counterparty;
  const lines = [
    `NEGOTIATION round=${v.round} task=${v.taskId}`,
    `LOAD ref=${l.loadRef} equipment=${l.equipment} miles=${l.miles} weightLbs=${l.weightLbs} hazmat=${l.hazmat} subcontractPermitted=${l.subcontractPermitted}`,
    `ORIGIN ${l.origin.state} ${l.origin.zip} window=${l.origin.windowStart}/${l.origin.windowEnd}`,
    `DESTINATION ${l.destination.state} ${l.destination.zip} window=${l.destination.windowStart}/${l.destination.windowEnd}`,
    `COUNTERPARTY entityType=${cp.entity.entityType} usdot=${cp.entity.usdot} mc=${cp.entity.mc ?? "-"} bipdUsd=${cp.insurance.bipdUsd} cargoUsd=${cp.insurance.cargoUsd} bondUsd=${cp.insurance.bondUsd} verifiedAt=${cp.verifiedAt}`,
    `THEIR_OFFER rateUsd=${v.offer.rateUsd} pickup=${v.offer.pickup.windowStart}/${v.offer.pickup.windowEnd} delivery=${v.offer.delivery.windowStart}/${v.offer.delivery.windowEnd} paymentTermsDays=${v.offer.paymentTermsDays} noteCode=${v.noteCode ?? "-"}`,
    v.myLastOffer ? `MY_LAST_OFFER rateUsd=${v.myLastOffer.rateUsd} pickup=${v.myLastOffer.pickup.windowStart}/${v.myLastOffer.pickup.windowEnd} paymentTermsDays=${v.myLastOffer.paymentTermsDays}` : `MY_LAST_OFFER none`,
    `GUARANTEE ${v.guaranteeAvailable === undefined ? "not-yet-quoted" : v.guaranteeAvailable ? "quoted" : "declined"}`,
  ];
  return lines.join("\n");
}
