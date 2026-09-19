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
  issuedAt: string;
  expiresAt: string;
  evidence: {
    registrySnapshotHash: string;
    registryCheckedAt: string;
    insuranceCheckedAt: string;
    vettingProvider: string;
    vettingFlags: string[];
    proofOfControl: string; // method used, e.g. "stub:fmcsa-portal-email-challenge"
  };
  /** Compact JWS by the issuer over the credential sans this field. */
  issuerSignature: string;
}

export interface RevocationEntry {
  credentialId: string;
  revokedAt: string;
  reason: string;
  evidence?: Record<string, unknown>;
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
