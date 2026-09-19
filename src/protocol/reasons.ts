/**
 * Machine-readable refusal / outcome codes. Every refusal anywhere in the
 * system carries one of these, plus the component that produced it and the
 * evidence it relied on. Scenario expectations in sim/ assert on these.
 */
export const REASONS = {
  // identity
  IDENTITY_SIGNATURE_INVALID: "Message signature does not verify against the credential-bound key",
  IDENTITY_KEY_MISMATCH: "Presented key is not the key bound in the credential",
  CREDENTIAL_UNKNOWN: "Credential id not issued by this venue",
  CREDENTIAL_EXPIRED: "Credential past its expiry",
  CREDENTIAL_REVOKED: "Credential has been revoked",
  CREDENTIAL_ISSUER_INVALID: "Credential issuer signature does not verify",
  CREDENTIAL_ENTITY_MISMATCH: "Registry identifiers in the message do not match the credential's bound entity",
  AUTHORITY_NOT_ACTIVE: "Registry shows operating authority is not active",
  INSURANCE_LAPSED: "Registry shows required insurance filing cancelled or expired as of now",
  INSURANCE_BELOW_MINIMUM: "Registry insurance coverage is below the required minimum",
  ONBOARDING_PROOF_OF_CONTROL_FAILED: "Could not prove control of the claimed registry identity",
  ONBOARDING_ENTITY_NOT_FOUND: "Claimed USDOT/MC not found in registry",
  ONBOARDING_KEY_ALREADY_BOUND: "A live credential already binds this entity to a different key",

  // mandate
  MANDATE_RATE_ABOVE_CEILING: "Rate exceeds the principal's mandated ceiling",
  MANDATE_RATE_BELOW_FLOOR: "Rate is below the principal's mandated floor",
  MANDATE_LANE_NOT_APPROVED: "Lane is outside the principal's approved lanes",
  MANDATE_EQUIPMENT_NOT_APPROVED: "Equipment type not approved by the principal",
  MANDATE_INSURANCE_MIN_NOT_MET: "Counterparty insurance is below the principal's required minimum",
  MANDATE_EXPOSURE_COUNTERPARTY_EXCEEDED: "Committing would exceed the principal's per-counterparty exposure limit",
  MANDATE_EXPOSURE_DAILY_EXCEEDED: "Committing would exceed the principal's daily exposure limit",
  MANDATE_GUARANTEE_REQUIRED: "Principal requires a venue guarantee and none is available",
  MANDATE_SIGNATURE_INVALID: "Mandate is not validly signed by the principal",
  MANDATE_ENVELOPE_MISSING: "No principal-signed mandate envelope registered for this agent",

  // venue protocol / routing
  PROTOCOL_VIOLATION: "Message violates the negotiation protocol state machine",
  NONCE_REUSED: "Message nonce already seen",
  MESSAGE_STALE: "Message timestamp outside the acceptance window",
  ENVELOPE_NOT_FROM_VENUE: "Inbound envelope is not signed by the venue",
  TERMS_HASH_MISMATCH: "Accepted terms hash does not match the terms on the table",
  NEGOTIATION_MAX_ROUNDS: "Negotiation did not converge within the bounded number of rounds",
  NEGOTIATION_WALKAWAY: "A party rejected and ended the negotiation",
  DOUBLE_BROKERING_ATTEMPT: "Party attempted to re-tender a load it is committed to perform",
  NO_BROKERAGE_AUTHORITY: "Party lacks brokerage authority to tender loads to others",
  COUNTERPARTY_UNVERIFIED: "Counterparty holds no valid credential on this venue",
  REPLAY_DETECTED: "Commitment record or signed message was already recorded",
  RECORD_TAMPERED: "Record content does not match its signatures or hash",
  CHAIN_BROKEN: "Ledger hash chain is inconsistent",

  // underwriting
  UNDERWRITING_DECLINED_RISK: "Counterparty risk score exceeds the guarantee threshold",
  VENUE_EXPOSURE_LIMIT_EXCEEDED: "Venue's aggregate guaranteed exposure to this counterparty would exceed its limit",
  VENUE_PORTFOLIO_LIMIT_EXCEEDED: "Venue's total guaranteed exposure would exceed its portfolio cap",

  // post-commitment
  CREDENTIAL_REVOKED_PRE_PICKUP: "Counterparty credential revoked after commitment, before pickup; commitment voided",
} as const;

export type ReasonCode = keyof typeof REASONS;

export function describe(code: ReasonCode): string {
  return REASONS[code];
}
