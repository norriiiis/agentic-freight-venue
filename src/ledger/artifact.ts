/**
 * The commitment artifact: a self-contained, signed record of what two
 * parties agreed. Either party can hand this file to an auditor, an insurer
 * or a court months later and it verifies WITHOUT the venue's cooperation:
 *
 *   - both parties' ACCEPT messages are included verbatim, each carrying the
 *     signer's detached JWS over the message (which contains the full terms)
 *   - both parties' credentials are included, binding each key to a registry
 *     entity, signed by the venue's issuer key
 *   - the venue's attestation signature covers the whole bundle
 *   - a ledger inclusion pointer lets anyone with the ledger file confirm
 *     the record's position in the chain
 *
 * Trust anchors an independent verifier needs: the venue's public key (which
 * a production venue would publish in a transparency log / DNS / well-known
 * URL). The artifact embeds it for convenience; a verifier SHOULD pin it.
 */
import { randomUUID } from "node:crypto";
import { canonicalize, hashObject } from "../protocol/canonical";
import { importPublicKey, signJws, verifyJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { dataPart, type Message } from "../protocol/a2a";
import { verifyMessageSignature } from "../protocol/envelope";
import { termsHash, type AcceptPayload, type Terms } from "../protocol/freight";
import type { Credential, CredentialStatusEntry } from "../protocol/types";
import { makeResolver, type VenueKeyCert, type VenueKeyHistory } from "../protocol/venue-keys";
import type { ReasonCode } from "../protocol/reasons";

export interface GuaranteeSummary {
  guaranteeId: string;
  coveredAmountUsd: number;
  premiumUsd: number;
  scope: string[];
  exclusions: string[];
  conditions: string[];
}

export interface VenueAttestation {
  kid: string;
  at: string;
  /** Detached JWS over { contentHash } — the hash of everything in the artifact except attestations and the ledger pointer. */
  jws: string;
}

export interface CommitmentArtifact {
  schema: "freight-venue/commitment-artifact/v2";
  commitmentId: string;
  createdAt: string;
  /**
   * The venue's key material a verifier needs: the root (to pin) and the
   * root-signed certificates for every venue kid this artifact references
   * (attestation keys and credential issuer keys).
   */
  venue: { venueId: string; rootPublicKey: OkpJwk; certs: VenueKeyCert[] };
  terms: Terms;
  termsHash: string;
  acceptances: { broker: Message; carrier: Message };
  credentials: { broker: Credential; carrier: Credential };
  underwriting: { decision: "GUARANTEED" | "UNGUARANTEED"; riskScore?: number; guarantee?: GuaranteeSummary; reasonCode?: ReasonCode };
  /** Position this record will occupy in the venue ledger (known before append, so it is inside the attestation). */
  ledger: { seq: number; prevHash: string };
  /**
   * Attestations are ADDITIVE: the original, plus any re-attestation under a
   * new venue key after a compromise. A verifier needs at least one that is
   * both valid and trusted at its signing time.
   */
  venueAttestations: VenueAttestation[];
  /** Filled after append; NOT covered by attestations. Inclusion is checked against the ledger file. */
  ledgerEntryHash?: string;
}

/** What an attestation signs and what the ledger entry commits to: the artifact content, minus attestations and the post-append pointer. */
export function artifactHash(a: Omit<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash"> & Partial<Pick<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash">>): string {
  const { ledgerEntryHash: _x, venueAttestations: _y, ...rest } = a;
  return hashObject(rest);
}

export function attest(content: Omit<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash">, venueKp: KeyPair, at = new Date()): VenueAttestation {
  return { kid: venueKp.kid, at: at.toISOString(), jws: signJws({ contentHash: artifactHash(content) }, venueKp, { typ: "commitment-attestation+jws" }, true) };
}

export function buildArtifact(
  input: Omit<CommitmentArtifact, "schema" | "commitmentId" | "createdAt" | "venueAttestations" | "ledgerEntryHash">,
  venueKp: KeyPair,
  commitmentId = `cmt_${randomUUID()}`,
): CommitmentArtifact {
  const content: Omit<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash"> = {
    schema: "freight-venue/commitment-artifact/v2",
    commitmentId,
    createdAt: new Date().toISOString(),
    ...input,
  };
  return { ...content, venueAttestations: [attest(content, venueKp)] };
}

/** Re-attest an existing artifact under a (new) venue key, optionally swapping in re-issued credentials and adding the certs a verifier will need. */
export function reattestArtifact(a: CommitmentArtifact, venueKp: KeyPair, opts: { credentials?: CommitmentArtifact["credentials"]; addCerts?: VenueKeyCert[] } = {}): CommitmentArtifact {
  const certs = [...a.venue.certs];
  for (const c of opts.addCerts ?? []) if (!certs.some((x) => x.kid === c.kid)) certs.push(c);
  const { venueAttestations, ledgerEntryHash, ...content } = a;
  const next = { ...content, credentials: opts.credentials ?? a.credentials, venue: { ...a.venue, certs } };
  // Replacing credentials or certs changes the content hash, so earlier attestations no longer bind: keep only those that still verify.
  const kept = venueAttestations.filter((x) => hashObject(next) === artifactHash(a) ? true : false);
  return { ...next, venueAttestations: [...kept, attest(next, venueKp)], ledgerEntryHash };
}

export interface ArtifactCheck {
  name: string;
  ok: boolean;
  detail?: string;
}
export interface ArtifactVerification {
  ok: boolean;
  reasonCode?: ReasonCode;
  checks: ArtifactCheck[];
  summary: { loadRef: string; rateUsd: number; broker: string; carrier: string; guaranteed: boolean };
}

/**
 * Independent verification. Pin the venue ROOT key (`pinnedRootKey`) to refuse
 * the embedded one (recommended). Pass the venue's published key history to
 * learn of venue-key compromises, and its credential status list to learn of
 * agent-key compromises; without them, a compromise declared after signing is
 * invisible offline. Every check is reported, not just the first failure.
 */
export function verifyArtifact(a: CommitmentArtifact, opts: { pinnedRootKey?: OkpJwk; keyHistory?: Pick<VenueKeyHistory, "certs" | "revocations">; statusList?: CredentialStatusEntry[]; now?: Date } = {}): ArtifactVerification {
  const checks: ArtifactCheck[] = [];
  const push = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail });
  const root = opts.pinnedRootKey ?? a.venue.rootPublicKey;
  if (opts.pinnedRootKey) push("venue.root.pinned-matches-embedded", opts.pinnedRootKey.x === a.venue.rootPublicKey.x, "embedded root differs from pinned root");
  const resolver = makeResolver(root, { certs: [...a.venue.certs, ...(opts.keyHistory?.certs ?? [])], revocations: opts.keyHistory?.revocations ?? [] });
  push("venue.certs.signed-by-root", a.venue.certs.length > 0 && a.venue.certs.every((c) => resolver.cert(c.kid) !== undefined), `${resolver.kids().length}/${a.venue.certs.length} embedded certificates verify against the root`);

  // 1. Attestations: valid signature by a certified key, trusted at signing time. At least one must pass both.
  const content = artifactHash(a);
  let anyTrusted = false;
  a.venueAttestations.forEach((att, i) => {
    const key = resolver.key(att.kid);
    const sig = key ? verifyJws(att.jws, importPublicKey(key), { contentHash: content }) : { ok: false, error: "attesting key not certified by the root" };
    push(`venue.attestation[${i}].signature`, sig.ok, sig.error);
    const why = resolver.untrustedAt(att.kid, new Date(att.at));
    push(`venue.attestation[${i}].trusted-at-signing`, sig.ok && !why, why);
    if (sig.ok && !why) anyTrusted = true;
  });
  push("venue.attestation.any-trusted", anyTrusted, "no attestation is both valid and by a key trusted at its signing time");

  // 2. termsHash is the hash of the terms
  push("terms.hash", termsHash(a.terms) === a.termsHash, `computed ${termsHash(a.terms).slice(0, 12)}… vs recorded ${a.termsHash.slice(0, 12)}…`);

  // 3. Each acceptance: is an ACCEPT over these exact terms, signed by the credential-bound key
  for (const side of ["broker", "carrier"] as const) {
    const msg = a.acceptances[side];
    const cred = a.credentials[side];
    const data = dataPart(msg) as AcceptPayload | undefined;
    push(`${side}.accept.type`, data?.type === "ACCEPT", `got ${data?.type}`);
    push(`${side}.accept.terms-match`, !!data && canonicalize(data.terms) === canonicalize(a.terms), "terms inside ACCEPT differ from artifact terms");
    push(`${side}.accept.termsHash-match`, data?.termsHash === a.termsHash);
    const sig = verifyMessageSignature(msg, cred.subject.publicKey);
    push(`${side}.accept.signature`, sig.ok, sig.error);
    push(`${side}.accept.signer-is-credential-subject`, (msg.metadata as { senderAgentId?: string })?.senderAgentId === cred.subject.agentId && (msg.metadata as { credentialId?: string })?.credentialId === cred.credentialId);
    // 4. Credential genuine: issuer signature by the venue key named in the credential, trusted when it issued
    const { issuerSignature, ...credUnsigned } = cred;
    const issuerKey = resolver.key(cred.issuer.kid);
    const cs = issuerKey ? verifyJws(issuerSignature, importPublicKey(issuerKey), credUnsigned) : { ok: false, error: `issuer key ${cred.issuer.kid.slice(0, 12)}… not certified by the root` };
    push(`${side}.credential.issuer-signature`, cs.ok, cs.error);
    const issuedWhy = resolver.untrustedAt(cred.issuer.kid, new Date(cred.signedAt ?? cred.issuedAt));
    push(`${side}.credential.issuer-trusted-at-issuance`, cs.ok && !issuedWhy, issuedWhy);
    const termsEntity = side === "broker" ? a.terms.brokerEntity : a.terms.carrierEntity;
    push(`${side}.credential.entity-matches-terms`, cred.subject.entity.usdot === termsEntity.usdot && (termsEntity.mc ?? cred.subject.entity.mc) === cred.subject.entity.mc);
    const termsAgent = side === "broker" ? a.terms.brokerAgentId : a.terms.carrierAgentId;
    push(`${side}.credential.agent-matches-terms`, cred.subject.agentId === termsAgent);
    // Note: credential validity AT SIGNING TIME is what matters for a historical record. Later expiry or
    // a later routine key rotation does not invalidate an old signature; a compromise declared effective
    // BEFORE the signature does — which needs the venue's published status list.
    const signedAt = new Date((msg.metadata as { ts?: string })?.ts ?? 0);
    push(`${side}.credential.valid-at-signing`, signedAt >= new Date(cred.issuedAt) && signedAt < new Date(cred.expiresAt), `signed ${signedAt.toISOString()}, valid ${cred.issuedAt}..${cred.expiresAt}`);
    if (opts.statusList) {
      const st = opts.statusList.find((x) => x.credentialId === cred.credentialId);
      const compromisedBefore = !!st?.compromisedAt && signedAt >= new Date(st.compromisedAt);
      const revokedBefore = st?.status === "REVOKED" && signedAt >= new Date(st.at);
      push(`${side}.credential.trusted-at-signing`, !compromisedBefore && !revokedBefore, compromisedBefore ? `key declared compromised as of ${st!.compromisedAt}, signature at ${signedAt.toISOString()}` : revokedBefore ? `revoked ${st!.at}, signature at ${signedAt.toISOString()}` : st ? `status ${st.status} (${st.reason}) after signing — does not affect this signature` : "");
    }
  }

  const failed = checks.filter((c) => !c.ok);
  const structural = failed.some((c) => /\.signature$|terms\.hash|-match$/.test(c.name) && !c.name.startsWith("venue.attestation["));
  const venueKeyProblem = failed.some((c) => c.name === "venue.attestation.any-trusted" || c.name.endsWith("issuer-trusted-at-issuance") || c.name === "venue.certs.signed-by-root" || c.name === "venue.root.pinned-matches-embedded");
  const agentKeyProblem = failed.some((c) => c.name.endsWith("credential.trusted-at-signing"));
  const reasonCode: ReasonCode | undefined = failed.length === 0 ? undefined : structural ? "RECORD_TAMPERED" : agentKeyProblem && !venueKeyProblem ? "COMMITMENT_UNDER_COMPROMISED_KEY" : venueKeyProblem ? "VENUE_KEY_UNTRUSTED" : "CREDENTIAL_ISSUER_INVALID";
  return {
    ok: failed.length === 0,
    reasonCode,
    checks,
    summary: {
      loadRef: a.terms.loadRef,
      rateUsd: a.terms.rateUsd,
      broker: `${a.credentials.broker.subject.entity.legalName} (${a.credentials.broker.subject.entity.mc ?? a.credentials.broker.subject.entity.usdot})`,
      carrier: `${a.credentials.carrier.subject.entity.legalName} (${a.credentials.carrier.subject.entity.mc ?? a.credentials.carrier.subject.entity.usdot})`,
      guaranteed: a.underwriting.decision === "GUARANTEED",
    },
  };
}
