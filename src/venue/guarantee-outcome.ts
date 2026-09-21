/**
 * For every refusal the simulator reports "would the guarantee have paid?".
 * This is the venue's own statement of its product boundary, keyed by reason.
 */
import type { ReasonCode } from "../protocol/reasons";

export function guaranteeWouldHavePaid(code: ReasonCode): string {
  switch (code) {
    case "INSURANCE_LAPSED":
    case "INSURANCE_BELOW_MINIMUM":
    case "INSURANCE_CANCELLATION_PENDING":
    case "AUTHORITY_NOT_ACTIVE":
      return "No. Refused before commitment, so no guarantee attached. Even if missed, an uninsured carrier's accident is a liability/cargo loss — excluded (NON_PERFORMANCE / CARGO), not an identity failure.";
    case "IDENTITY_KEY_MISMATCH":
    case "IDENTITY_SIGNATURE_INVALID":
    case "CREDENTIAL_ENTITY_MISMATCH":
    case "CREDENTIAL_ISSUER_INVALID":
      return "Yes — impersonation is the covered peril. Had the venue verified this sender and the broker paid the impersonator, the guarantee pays. Caught here, so no loss and no claim.";
    case "DOUBLE_BROKERING_ATTEMPT":
    case "NO_BROKERAGE_AUTHORITY":
    case "COUNTERPARTY_UNVERIFIED":
      return "Yes, for the original broker — if the venue had let the committed carrier re-tender through the venue to an unverified party. Blocked here. Re-tendering OFF the venue is excluded (OFF_VENUE_ARRANGEMENTS); the artifact is the broker's evidence for a claim against the carrier.";
    case "MANDATE_RATE_ABOVE_CEILING":
    case "MANDATE_RATE_BELOW_FLOOR":
    case "MANDATE_LANE_NOT_APPROVED":
    case "MANDATE_EQUIPMENT_NOT_APPROVED":
    case "MANDATE_INSURANCE_MIN_NOT_MET":
    case "MANDATE_EXPOSURE_COUNTERPARTY_EXCEEDED":
    case "MANDATE_EXPOSURE_DAILY_EXCEEDED":
    case "MANDATE_GUARANTEE_REQUIRED":
      return "N/A — no transaction formed. A mandate refusal is the principal's own control, not an insured peril. A rogue agent that bypassed both the local and venue mandate check would be CONTROLS_BYPASSED: excluded.";
    case "VENUE_EXPOSURE_LIMIT_EXCEEDED":
    case "VENUE_PORTFOLIO_LIMIT_EXCEEDED":
    case "UNDERWRITING_DECLINED_RISK":
      return "No — the venue declined to guarantee. Commitment was refused only because a party's mandate requires a guarantee; a principal whose mandate permits unguaranteed commits could proceed with NO coverage.";
    case "REGISTRY_UNAVAILABLE":
      return "N/A — refused before commitment: the venue could not obtain the registry's signed word and will not attest standing from memory. A liveness cost, not a coverage gap.";
    case "REGISTRY_STALE":
    case "REGISTRY_CONTRADICTS_COMMITMENT":
    case "REGISTRY_ATTESTATION_MISSING":
      return "The guarantee was attached on the venue's say-so, and the artifact shows that say-so was not backed by the registry's word at the time. The venue's own evidence indicts it: a claim against the venue, not against the guarantee's exclusions.";
    case "NEGOTIATION_MAX_ROUNDS":
    case "NEGOTIATION_WALKAWAY":
    case "NEGOTIATION_TIMEOUT":
      return "N/A — no commitment formed; nothing to guarantee.";
    case "LOAD_ALREADY_COMMITTED":
      return "N/A for this negotiation — the load's guarantee rides on the commitment that won.";
    case "COMMITMENT_UNDER_COMPROMISED_KEY":
      return "Guarantee released with the void. A stolen or leaked agent key is the principal's custody failure (PRINCIPAL_KEY_COMPROMISE exclusion): losses before the principal declared the compromise are not covered. A venue-hosted key custody tier would change that.";
    case "CREDENTIAL_SUPERSEDED":
    case "ROTATION_UNAUTHORIZED":
      return "N/A — refused before any transaction. A refused self-rotation is the control working: a stolen key cannot rebind itself.";
    case "CREDENTIAL_REVOKED_PRE_PICKUP":
    case "CREDENTIAL_REVOKED":
      return "Guarantee WAS attached and is now RELEASED with the commitment voided. If the broker ships anyway after the VOIDED notice, PRINCIPAL_OVERRODE_REFUSAL applies: excluded.";
    case "UNTRUSTED_TEXT_REJECTED":
      return "N/A — the message never entered the negotiation. Had it been forwarded, the counterparty's strategy would still not have seen the text (quarantined by the runtime).";
    case "NONCE_REUSED":
    case "REPLAY_DETECTED":
    case "RECORD_TAMPERED":
    case "TERMS_HASH_MISMATCH":
    case "MESSAGE_STALE":
      return "N/A — no new commitment formed. The original commitment and its guarantee are unaffected; a tampered artifact simply fails verification.";
    default:
      return "N/A — refused before commitment.";
  }
}
