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
import type { Credential, CredentialStatusEntry } from "../protocol/types";
import type { VenueKeyResolver } from "../protocol/venue-keys";
import { registryRef, standing, type InsuranceStatus, type RegistryRef, type RegistryView } from "../protocol/registry";

export interface Verdict {
  ok: boolean;
  reasonCode?: ReasonCode;
  evidence: Record<string, unknown>;
}

/**
 * Is this credential acceptable for a NEW presentation right now?
 * `status` is the venue's status entry for it (REVOKED / SUPERSEDED), if any.
 * A superseded credential is still accepted inside its grace window — unless
 * its key was declared compromised, in which case never.
 */
export function verifyCredential(
  cred: Credential | undefined,
  opts: { issuerPublicKey?: OkpJwk; issuerKeys?: VenueKeyResolver; revocation?: CredentialStatusEntry; status?: CredentialStatusEntry; now?: Date },
): Verdict {
  const now = opts.now ?? new Date();
  if (!cred) return { ok: false, reasonCode: "CREDENTIAL_UNKNOWN", evidence: {} };
  const { issuerSignature, ...unsigned } = cred;
  // The issuing venue key is named in the credential; with a resolver (root + certs) it may be any certified key.
  const issuerKey = opts.issuerKeys ? opts.issuerKeys.key(cred.issuer.kid) : opts.issuerPublicKey;
  if (!issuerKey) return { ok: false, reasonCode: "CREDENTIAL_ISSUER_INVALID", evidence: { credentialId: cred.credentialId, error: `issuer key ${cred.issuer.kid.slice(0, 12)}… is not certified by the venue root` } };
  const sig = verifyJws(issuerSignature, importPublicKey(issuerKey), unsigned);
  if (!sig.ok) return { ok: false, reasonCode: "CREDENTIAL_ISSUER_INVALID", evidence: { credentialId: cred.credentialId, error: sig.error } };
  const issuedWhy = opts.issuerKeys?.untrustedAt(cred.issuer.kid, new Date(cred.signedAt ?? cred.issuedAt));
  if (issuedWhy) return { ok: false, reasonCode: "CREDENTIAL_ISSUER_INVALID", evidence: { credentialId: cred.credentialId, issuerKid: cred.issuer.kid, error: issuedWhy, note: "issued under a venue key later declared compromised as of a time before issuance; awaiting re-issuance" } };
  if (new Date(cred.expiresAt) <= now) {
    return { ok: false, reasonCode: "CREDENTIAL_EXPIRED", evidence: { credentialId: cred.credentialId, expiresAt: cred.expiresAt, now: now.toISOString() } };
  }
  const st = opts.status ?? opts.revocation;
  if (st?.status === "REVOKED") {
    return { ok: false, reasonCode: "CREDENTIAL_REVOKED", evidence: { credentialId: cred.credentialId, revocation: st } };
  }
  if (st?.status === "SUPERSEDED") {
    if (st.compromisedAt) {
      return { ok: false, reasonCode: "CREDENTIAL_SUPERSEDED", evidence: { credentialId: cred.credentialId, supersededBy: st.supersededBy, compromisedAt: st.compromisedAt, reason: st.reason } };
    }
    if (!st.graceUntil || new Date(st.graceUntil) <= now) {
      return { ok: false, reasonCode: "CREDENTIAL_SUPERSEDED", evidence: { credentialId: cred.credentialId, supersededBy: st.supersededBy, graceUntil: st.graceUntil, reason: st.reason } };
    }
    return { ok: true, evidence: { credentialId: cred.credentialId, entity: cred.subject.entity, expiresAt: cred.expiresAt, grace: true, supersededBy: st.supersededBy, graceUntil: st.graceUntil } };
  }
  return { ok: true, evidence: { credentialId: cred.credentialId, entity: cred.subject.entity, expiresAt: cred.expiresAt } };
}

/**
 * Was a signature made at `signedAt` under this credential trustworthy?
 * Historical verification: expiry/supersession AFTER the signature do not
 * matter; a compromise declared effective BEFORE the signature does.
 */
export function signatureTrustedAt(cred: Credential, signedAt: Date, status?: CredentialStatusEntry): Verdict {
  if (signedAt < new Date(cred.issuedAt) || signedAt >= new Date(cred.expiresAt)) {
    return { ok: false, reasonCode: "CREDENTIAL_EXPIRED", evidence: { credentialId: cred.credentialId, signedAt: signedAt.toISOString(), validity: [cred.issuedAt, cred.expiresAt] } };
  }
  if (status?.compromisedAt && signedAt >= new Date(status.compromisedAt)) {
    return { ok: false, reasonCode: "COMMITMENT_UNDER_COMPROMISED_KEY", evidence: { credentialId: cred.credentialId, signedAt: signedAt.toISOString(), compromisedAt: status.compromisedAt } };
  }
  if (status?.status === "REVOKED" && signedAt >= new Date(status.at)) {
    return { ok: false, reasonCode: "CREDENTIAL_REVOKED", evidence: { credentialId: cred.credentialId, signedAt: signedAt.toISOString(), revokedAt: status.at } };
  }
  return { ok: true, evidence: { credentialId: cred.credentialId, signedAt: signedAt.toISOString() } };
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
  /** The registry whose word this verdict rests on: on refusal, the one that showed the lapse; absent for a bare store. */
  registry?: RegistryRef;
  /** Every registry whose fresh word was considered. */
  registries?: RegistryRef[];
}

/**
 * Standing NOW, per the registries' latest word the view holds. The caller is
 * responsible for having refreshed that word (see RegistryView.refresh). With
 * several registries the rule is UNANIMITY: every attestation must show the
 * party in standing, and the coverage figures reported are the lowest any
 * registry shows — a cancellation is news that cannot be un-known, so one
 * mirror that has the filing outranks the others that do not. The verdict
 * names the attestation it rests on and the ones that dissented, so the
 * reliance — and the dissent — are auditable.
 */
export function liveCheck(
  registry: RegistryView,
  cred: Credential,
  opts: { now?: Date; hazmat?: boolean; requiredBipdUsd?: number; through?: Date } = {},
): LiveCheckResult {
  const now = opts.now ?? new Date();
  const usdot = cred.subject.entity.usdot;
  const snapshot = registry.snapshotHash(usdot);
  const stOpts = { hazmat: opts.hazmat, requiredBipdUsd: opts.requiredBipdUsd, through: opts.through };
  const drift = { credentialIssuedWithSnapshot: cred.evidence.registrySnapshotHash, snapshotChangedSinceIssuance: cred.evidence.registrySnapshotHash !== snapshot };
  const atts = registry.attestations?.(usdot) ?? [];
  if (atts.length === 0) {
    // A bare store (tests): one record, no signer.
    const st = standing(registry.get(usdot) ?? null, now, stOpts);
    if (!st.ok) return { ok: false, reasonCode: st.reasonCode, insurance: st.insurance, registrySnapshotHash: snapshot, evidence: { ...st.evidence, registrySnapshotHash: snapshot, ...drift } };
    return { ok: true, insurance: st.insurance, brokerAuthority: st.brokerAuthority, registrySnapshotHash: snapshot, evidence: { ...st.evidence, registrySnapshotHash: snapshot } };
  }
  const verdicts = atts.map((a) => ({ ref: registryRef(a), st: standing(a.record, now, stOpts) }));
  const refs = verdicts.map((v) => v.ref);
  const bad = verdicts.find((v) => !v.st.ok);
  if (bad) {
    const agreeing = verdicts.filter((v) => !v.st.ok).map((v) => v.ref.registryId);
    const dissenting = verdicts.filter((v) => v.st.ok).map((v) => v.ref);
    return {
      ok: false,
      reasonCode: bad.st.reasonCode,
      insurance: bad.st.insurance,
      registrySnapshotHash: snapshot,
      registry: bad.ref,
      registries: refs,
      evidence: {
        ...bad.st.evidence,
        registrySnapshotHash: snapshot,
        registry: bad.ref,
        registries: refs,
        registriesShowingThis: agreeing,
        // Signed word to the contrary from other registries: stale mirrors, or liars — either way, accountable.
        dissentingRegistries: dissenting.length ? dissenting : undefined,
        rule: atts.length > 1 ? "unanimity: any registry's word of a lapse blocks" : undefined,
        ...drift,
      },
    };
  }
  // All in standing: report the most conservative figures any registry shows.
  const first = verdicts[0]!.st;
  const min = (pick: (i: InsuranceStatus) => number) => Math.min(...verdicts.map((v) => pick(v.st.insurance!)));
  const insurance: InsuranceStatus = { ...first.insurance!, bipdCoverageUsd: min((i) => i.bipdCoverageUsd), cargoCoverageUsd: min((i) => i.cargoCoverageUsd), bondUsd: min((i) => i.bondUsd) };
  return { ok: true, insurance, brokerAuthority: verdicts.every((v) => v.st.brokerAuthority), registrySnapshotHash: snapshot, registry: refs[0], registries: refs, evidence: { ...first.evidence, bipdUsd: insurance.bipdCoverageUsd, cargoUsd: insurance.cargoCoverageUsd, bondUsd: insurance.bondUsd, registrySnapshotHash: snapshot, registries: refs } };
}
