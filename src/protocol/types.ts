/**
 * Shared data shapes that cross the wire. These are the only things both
 * agents and the venue agree on; no component's private state lives here.
 */
import type { OkpJwk } from "./crypto";

export type EntityType = "CARRIER" | "BROKER" | "CARRIER_BROKER";

/** Registry identifiers as FMCSA publishes them. */
export interface RegistryIdentity {
  usdot: string; // e.g. "3456789"
  mc?: string;   // docket number, e.g. "MC-1234567"
  legalName: string;
  entityType: EntityType;
}

/**
 * An agent credential: binds an agent's public key to a legal entity whose
 * identity root is the public registry. Issued and signed by the venue's
 * identity service after registry lookup, insurance check, and proof of
 * control. Expiry and revocation are first-class.
 */
export interface Credential {
  credentialId: string;
  schema: "freight-venue/agent-credential/v1";
  subject: {
    agentId: string;
    entity: RegistryIdentity;
    publicKey: OkpJwk; // the agent's Ed25519 key
  };
  issuer: { venueId: string; kid: string };
  /** When the entity was verified and the credential first issued. Unchanged by re-issuance. */
  issuedAt: string;
  /** When the current issuer signature was made (differs from issuedAt only after a re-issuance under a new venue key). */
  signedAt?: string;
  expiresAt: string;
  /** Lineage: the credential this one replaced (key rotation / renewal). */
  supersedes?: string;
  evidence: {
    registrySnapshotHash: string;
    registryCheckedAt: string;
    /** The registries' signed attestations the issuer relied on, one per registry (see protocol/registry.ts). */
    registries?: { registryId: string; kid: string; asOf: string }[];
    insuranceCheckedAt: string;
    vettingProvider: string;
    vettingFlags: string[];
    proofOfControl: string; // method used, e.g. "stub:fmcsa-portal-email-challenge"
  };
  /** Compact JWS by the issuer over the credential sans this field. */
  issuerSignature: string;
}

/**
 * A credential's non-ACTIVE status. REVOKED: the identity behind it is no
 * longer in good standing (authority revoked, insurance cancelled). SUPERSEDED:
 * the key was rotated — the entity is fine; the OLD key is not. A routine
 * rotation leaves a grace window so in-flight messages signed with the old
 * key are still accepted; a compromise records `compromisedAt`, after which
 * anything the old key signed is suspect and nothing new is accepted.
 */
export interface CredentialStatusEntry {
  credentialId: string;
  status: "REVOKED" | "SUPERSEDED";
  at: string;
  reason: string;
  supersededBy?: string;
  graceUntil?: string;
  compromisedAt?: string;
  evidence?: Record<string, unknown>;
}
/** @deprecated name kept for readability at call sites that only deal with revocation. */
export type RevocationEntry = CredentialStatusEntry;

export type RotationReason = "ROTATION" | "RENEWAL" | "COMPROMISE";

/** What a rotation request must prove. The agent's own current key is deliberately NOT an option. */
export type RotationAuthorization =
  | { kind: "PRINCIPAL"; jws: string }            // detached JWS by the principal key registered in the mandate envelope
  | { kind: "PROOF_OF_CONTROL"; method: string; token: string } // registry-rooted, same gate as onboarding
  | { kind: "CURRENT_KEY_ONLY"; jws: string };    // the agent signs with its own key — refused, by design

export interface RotationClaims {
  credentialId: string;   // the credential being rotated
  newKid: string;         // thumbprint of the new key
  ts: string;
  reason: RotationReason;
  compromisedAt?: string; // COMPROMISE only
}

/**
 * The subset of a principal's mandate that the principal chooses to register
 * with the venue so the venue can enforce it as a second line of defense.
 * Signed by the *principal's* key, not the agent's — the agent cannot loosen it.
 */
export interface MandateEnvelope {
  schema: "freight-venue/mandate-envelope/v1";
  agentId: string;
  principalKid: string;
  issuedAt: string;
  expiresAt: string;
  limits: {
    maxRatePerLoadUsd?: number;
    minRatePerLoadUsd?: number;
    maxDailyExposureUsd: number;
    maxPerCounterpartyExposureUsd: number;
    allowedEquipment: string[];
    allowedLaneRegions?: string[]; // e.g. ["TX", "OK", "LA"]
    requiredCounterpartyInsuranceUsd: number;
    requireGuarantee: boolean;
  };
  principalSignature: string; // JWS over envelope sans this field
  principalPublicKey: OkpJwk;
}
