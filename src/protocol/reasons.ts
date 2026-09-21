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
  CREDENTIAL_SUPERSEDED: "Credential was replaced by key rotation and is outside its grace window (or its key was declared compromised)",
  ROTATION_UNAUTHORIZED: "Key rotation must be authorized by the principal key registered in the mandate envelope, or by proof of control; the agent's own key is not sufficient",
  CREDENTIAL_ISSUER_INVALID: "Credential issuer signature does not verify",
  CREDENTIAL_ENTITY_MISMATCH: "Registry identifiers in the message do not match the credential's bound entity",
  AUTHORITY_NOT_ACTIVE: "Registry shows operating authority is not active",
  INSURANCE_LAPSED: "Registry shows required insurance filing cancelled or expired as of now",
  INSURANCE_BELOW_MINIMUM: "Registry insurance coverage is below the required minimum",
  INSURANCE_CANCELLATION_PENDING: "Registry shows a required insurance filing cancelling before the delivery window closes; the carrier would be uninsured in transit",
  REGISTRY_UNAVAILABLE: "The registry's signed word could not be obtained fresh enough to verify standing; the venue refuses rather than rely on what it remembers",
  REGISTRY_STALE: "The registry attestation the venue relied on at commitment is older than its freshness policy: a cancellation filed in between was invisible to it, and it did not ask",
  REGISTRY_CONTRADICTS_COMMITMENT: "The registry's signed record shows a party was not in good standing when the commitment was made; the venue committed against the registry's word",
  REGISTRY_ATTESTATION_INVALID: "The registry attestation in the artifact does not verify under the pinned registry key, or is not about the committed party",
  REGISTRY_ATTESTATION_MISSING: "The artifact carries no signed registry attestation for a party: the venue's claim to have checked standing is unverifiable",
  REGISTRY_QUORUM_NOT_MET: "Fewer pinned registries vouch for a party in the artifact than the verifier requires, or a registry the verifier names is absent; a venue cannot conjure a registry's signature, and one it quietly dropped is one it did not want heard",
  REGISTRY_DISAGREEMENT: "The registries the venue relied on differ on the facts standing rests on (authorities, filings, operating status); at least one mirror is stale or wrong, and which is unknown",
  REGISTRY_FALSE_ATTESTATION: "A registry signed a sync time later than a cancellation's filing date and served a record without that filing: a signed falsehood, proven by any later word that shows the filing — a peer's, its own, or the insurer's",
  INSURER_ATTESTATION_MISSING: "No signed word from the party's own insurer is on file, and the policy requires the origin of the fact to vouch — the one signature no set of registry mirrors can forge",
  INSURER_ATTESTATION_INVALID: "The insurer attestation does not verify under a registered insurer key, or is about another entity or policy",
  INSURANCE_NOT_ASSURED_THROUGH_DELIVERY: "The insurer's own word assures coverage only through an earlier date than the delivery window (its statutory notice period from when it spoke, or a cancellation it disclosed); beyond that only registry mirrors vouch",
  INSURER_CONTRADICTS_COMMITMENT: "The party's own insurer's signed word shows coverage cancelled at or before the commitment, or before delivery; the venue committed against the origin of the fact",
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
  MANDATE_INSURER_ATTESTATION_REQUIRED: "Principal requires the counterparty's own insurer to have attested coverage assured through delivery; none on file, or it assures only an earlier date",
  MANDATE_SIGNATURE_INVALID: "Mandate is not validly signed by the principal",
  MANDATE_ENVELOPE_MISSING: "No principal-signed mandate envelope registered for this agent",

  // venue protocol / routing
  PROTOCOL_VIOLATION: "Message violates the negotiation protocol state machine",
  UNTRUSTED_TEXT_REJECTED: "Payload violates the closed wire schema: unknown key, unknown code, or a string that is too long, multi-line, or carries control/bidi/zero-width characters",
  NONCE_REUSED: "Message nonce already seen",
  MESSAGE_STALE: "Message timestamp outside the acceptance window",
  ENVELOPE_NOT_FROM_VENUE: "Inbound envelope is not signed by the venue",
  TERMS_HASH_MISMATCH: "Accepted terms hash does not match the terms on the table",
  NEGOTIATION_MAX_ROUNDS: "Negotiation did not converge within the bounded number of rounds",
  NEGOTIATION_WALKAWAY: "A party rejected and ended the negotiation",
  NEGOTIATION_TIMEOUT: "The awaited party did not reply within the venue's reply window; negotiation canceled",
  LOAD_ALREADY_COMMITTED: "This load is already committed to another carrier; parallel negotiation canceled (first commitment wins)",
  DOUBLE_BROKERING_ATTEMPT: "Party attempted to re-tender a load it is committed to perform",
  NO_BROKERAGE_AUTHORITY: "Party lacks brokerage authority to tender loads to others",
  COUNTERPARTY_UNVERIFIED: "Counterparty holds no valid credential on this venue",
  REPLAY_DETECTED: "Commitment record or signed message was already recorded",
  RECORD_TAMPERED: "Record content does not match its signatures or hash",
  CHAIN_BROKEN: "Ledger hash chain is inconsistent",
  LEDGER_FORK_DETECTED: "The venue's ledger head does not extend the head this witness previously cosigned (rollback or fork)",
  STATUS_NOT_WITNESSED: "The published status list / key history carries no head cosigned by a pinned independent witness",
  INCLUSION_PROMISE_BROKEN: "The venue signed a promise to record a status notice by a deadline and a witnessed chain past that deadline does not contain it; nothing it publishes can be trusted",
  NOTICE_PENDING: "A pinned witness holds a source-signed status notice the venue has not recorded and never acknowledged; status is uncertain until it appears",
  NOTICE_SOURCE_UNKNOWN: "Status notice is not signed by a registered source (registry feed, insurer) or by the principal of the affected agent",
  VENUE_EQUIVOCATION: "Two witnesses hold validly signed receipts for the same ledger position with different hashes: the venue showed different ledgers to different parties; nothing it publishes can be trusted",
  WITNESS_QUORUM_NOT_MET: "Fewer pinned witnesses cosigned the published head than the verifier requires",
  STATUS_STALE: "The published list is witnessed only up to a time earlier than the moment being judged; later revocations or compromises would be invisible",

  // venue key hierarchy
  VENUE_KEY_UNTRUSTED: "A venue signature is by a key that is not certified by the venue root, or was declared compromised at that time and not re-signed",
  ROOT_ROTATION_UNAUTHORIZED: "Root rotation must reveal the successor the previous root pre-committed to, signed by that successor; the current root's signature cannot authorize a different successor",
  VENUE_KEY_ROTATION_UNAUTHORIZED: "Venue key rotation must carry a certificate (and, for compromise, a revocation) signed by the venue root; the venue process cannot certify its own successor",

  // underwriting
  UNDERWRITING_DECLINED_RISK: "Counterparty risk score exceeds the guarantee threshold",
  VENUE_EXPOSURE_LIMIT_EXCEEDED: "Venue's aggregate guaranteed exposure to this counterparty would exceed its limit",
  VENUE_PORTFOLIO_LIMIT_EXCEEDED: "Venue's total guaranteed exposure would exceed its portfolio cap",

  // post-commitment
  CREDENTIAL_REVOKED_PRE_PICKUP: "Counterparty credential revoked after commitment, before pickup; commitment voided",
  COMMITMENT_UNDER_COMPROMISED_KEY: "A party's acceptance was signed by a key later declared compromised as of a time before the signature; commitment voided",
} as const;

export type ReasonCode = keyof typeof REASONS;

export function describe(code: ReasonCode): string {
  return REASONS[code];
}
