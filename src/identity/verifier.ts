/**
 * Credential verification — run by the venue on EVERY exchange, and by any
 * third party who holds the issuer's public key (e.g. when checking a
 * commitment artifact months later).
 *
 * Three layers, each with its own reason code:
 *   1. verifyCredential  — is this credential genuine, unexpired, unrevoked?
 *   2. verifyPresentation — did the holder of the credential's key sign THIS message,
 *                           and do the identifiers in the message match the credential?
 *   3. liveCheck          — is the underlying registry identity still in good standing NOW?
 */
import type { Message } from "../protocol/a2a";
import { importPublicKey, verifyJws, type OkpJwk } from "../protocol/crypto";
import { verifyMessageSignature } from "../protocol/envelope";
import type { ReasonCode } from "../protocol/reasons";
import type { Credential, RevocationEntry } from "../protocol/types";
import { authorityActive, hasBrokerAuthority, insuranceStatus, type InsuranceStatus, type MockRegistry } from "./registry";

export interface Verdict {
  ok: boolean;
  reasonCode?: ReasonCode;
  evidence: Record<string, unknown>;
}

export function verifyCredential(
  cred: Credential | undefined,
  opts: { issuerPublicKey: OkpJwk; revocation?: RevocationEntry; now?: Date },
): Verdict {
  const now = opts.now ?? new Date();
  if (!cred) return { ok: false, reasonCode: "CREDENTIAL_UNKNOWN", evidence: {} };
  const { issuerSignature, ...unsigned } = cred;
  const sig = verifyJws(issuerSignature, importPublicKey(opts.issuerPublicKey), unsigned);
  if (!sig.ok) return { ok: false, reasonCode: "CREDENTIAL_ISSUER_INVALID", evidence: { credentialId: cred.credentialId, error: sig.error } };
  if (new Date(cred.expiresAt) <= now) {
    return { ok: false, reasonCode: "CREDENTIAL_EXPIRED", evidence: { credentialId: cred.credentialId, expiresAt: cred.expiresAt, now: now.toISOString() } };
  }
  if (opts.revocation) {
    return { ok: false, reasonCode: "CREDENTIAL_REVOKED", evidence: { credentialId: cred.credentialId, revocation: opts.revocation } };
  }
  return { ok: true, evidence: { credentialId: cred.credentialId, entity: cred.subject.entity, expiresAt: cred.expiresAt } };
}

export function verifyPresentation(m: Message, cred: Credential, claimed?: { agentId: string; usdot: string; mc?: string }): Verdict {
  const sig = verifyMessageSignature(m, cred.subject.publicKey);
  if (!sig.ok) {
    // Distinguish "signed with a different key" from "no/garbled signature".
    const presentedKid = sig.kid;
    const boundKid = cred.subject.publicKey.kid;
    const code: ReasonCode = presentedKid && boundKid && presentedKid !== boundKid ? "IDENTITY_KEY_MISMATCH" : "IDENTITY_SIGNATURE_INVALID";
    return { ok: false, reasonCode: code, evidence: { credentialId: cred.credentialId, presentedKid, credentialBoundKid: boundKid, error: sig.error } };
  }
  if (claimed) {
    const e = cred.subject.entity;
    if (claimed.agentId !== cred.subject.agentId || claimed.usdot !== e.usdot || (claimed.mc && claimed.mc !== e.mc)) {
      return { ok: false, reasonCode: "CREDENTIAL_ENTITY_MISMATCH", evidence: { claimed, bound: { agentId: cred.subject.agentId, usdot: e.usdot, mc: e.mc } } };
    }
  }
  return { ok: true, evidence: { credentialId: cred.credentialId, kid: sig.kid } };
}

export interface LiveCheckResult extends Verdict {
  insurance?: InsuranceStatus;
  brokerAuthority?: boolean;
  registrySnapshotHash?: string;
}

export function liveCheck(
  registry: MockRegistry,
  cred: Credential,
  opts: { now?: Date; hazmat?: boolean; requiredBipdUsd?: number } = {},
): LiveCheckResult {
  const now = opts.now ?? new Date();
  const rec = registry.get(cred.subject.entity.usdot);
  if (!rec) return { ok: false, reasonCode: "ONBOARDING_ENTITY_NOT_FOUND", evidence: { usdot: cred.subject.entity.usdot } };
  const snapshot = registry.snapshotHash(rec.usdot);
  if (!authorityActive(rec, now)) {
    return {
      ok: false,
      reasonCode: "AUTHORITY_NOT_ACTIVE",
      evidence: { usdot: rec.usdot, operatingStatus: rec.operatingStatus, outOfServiceDate: rec.outOfServiceDate, authorities: rec.authorities, registrySnapshotHash: snapshot },
      registrySnapshotHash: snapshot,
    };
  }
  const ins = insuranceStatus(rec, now, { hazmat: opts.hazmat, requiredBipdUsd: opts.requiredBipdUsd });
  if (!ins.ok) {
    return {
      ok: false,
      reasonCode: ins.reasonCode,
      insurance: ins,
      registrySnapshotHash: snapshot,
      evidence: {
        usdot: rec.usdot,
        asOf: ins.asOf,
        lapsedFilings: ins.lapsedFilings.map((f) => ({ type: f.type, form: f.form, insurer: f.insurer, policyNumber: f.policyNumber, cancellationDate: f.cancellationDate })),
        activeBipdUsd: ins.bipdCoverageUsd,
        requiredBipdUsd: opts.requiredBipdUsd,
        credentialIssuedWithSnapshot: cred.evidence.registrySnapshotHash,
        registrySnapshotNow: snapshot,
        snapshotChangedSinceIssuance: cred.evidence.registrySnapshotHash !== snapshot,
      },
    };
  }
  return {
    ok: true,
    insurance: ins,
    brokerAuthority: hasBrokerAuthority(rec, now),
    registrySnapshotHash: snapshot,
    evidence: { usdot: rec.usdot, bipdUsd: ins.bipdCoverageUsd, cargoUsd: ins.cargoCoverageUsd, bondUsd: ins.bondUsd, safetyRating: rec.safetyRating, registrySnapshotHash: snapshot },
  };
}
