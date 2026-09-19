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
import type { ReasonCode } from "../protocol/reasons";

export interface GuaranteeSummary {
  guaranteeId: string;
  coveredAmountUsd: number;
  premiumUsd: number;
  scope: string[];
  exclusions: string[];
  conditions: string[];
}

export interface CommitmentArtifact {
  schema: "freight-venue/commitment-artifact/v1";
  commitmentId: string;
  createdAt: string;
  venue: { venueId: string; publicKey: OkpJwk };
  terms: Terms;
  termsHash: string;
  acceptances: { broker: Message; carrier: Message };
  credentials: { broker: Credential; carrier: Credential };
  underwriting: { decision: "GUARANTEED" | "UNGUARANTEED"; riskScore?: number; guarantee?: GuaranteeSummary; reasonCode?: ReasonCode };
  /** Position this record will occupy in the venue ledger (known before append, so it is inside the attestation). */
  ledger: { seq: number; prevHash: string };
  venueAttestation: string; // detached JWS over artifact sans this field and sans ledgerEntryHash
  /** Filled after append; NOT covered by the attestation. Inclusion is checked against the ledger file. */
  ledgerEntryHash?: string;
}

/** The hash the ledger entry commits to: the attested artifact, minus the post-append pointer. */
export function artifactHash(a: CommitmentArtifact): string {
  const { ledgerEntryHash: _x, ...rest } = a;
  return hashObject(rest);
}

export function buildArtifact(
  input: Omit<CommitmentArtifact, "schema" | "commitmentId" | "createdAt" | "venueAttestation" | "ledgerEntryHash">,
  venueKp: KeyPair,
  commitmentId = `cmt_${randomUUID()}`,
): CommitmentArtifact {
  const unsigned: Omit<CommitmentArtifact, "venueAttestation" | "ledgerEntryHash"> = {
    schema: "freight-venue/commitment-artifact/v1",
    commitmentId,
    createdAt: new Date().toISOString(),
    ...input,
  };
  return { ...unsigned, venueAttestation: signJws(unsigned, venueKp, { typ: "commitment-attestation+jws" }, true) };
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
 * Independent verification. Pass `pinnedVenueKey` to refuse the embedded key
 * (recommended). Every check is reported, not just the first failure.
 */
export function verifyArtifact(a: CommitmentArtifact, opts: { pinnedVenueKey?: OkpJwk; now?: Date; statusList?: CredentialStatusEntry[] } = {}): ArtifactVerification {
  const checks: ArtifactCheck[] = [];
  const push = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail });
  const venueKey = opts.pinnedVenueKey ?? a.venue.publicKey;

  if (opts.pinnedVenueKey) push("venue.key.pinned-matches-embedded", opts.pinnedVenueKey.x === a.venue.publicKey.x, "embedded key differs from pinned key");

  // 1. Venue attestation covers the whole bundle
  const { venueAttestation, ledgerEntryHash: _le, ...unsigned } = a;
  const att = verifyJws(venueAttestation, importPublicKey(venueKey), unsigned);
  push("venue.attestation", att.ok, att.error);

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
    // 4. Credential genuine (issuer signature) and entity matches terms
    const { issuerSignature, ...credUnsigned } = cred;
    const cs = verifyJws(issuerSignature, importPublicKey(venueKey), credUnsigned);
    push(`${side}.credential.issuer-signature`, cs.ok, cs.error);
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
  const reasonCode: ReasonCode | undefined = failed.length === 0 ? undefined : failed.some((c) => c.name.endsWith("trusted-at-signing")) && !failed.some((c) => c.name.includes("signature") || c.name.includes("attestation") || c.name.includes("hash")) ? "COMMITMENT_UNDER_COMPROMISED_KEY" : failed.some((c) => c.name.includes("signature") || c.name.includes("attestation") || c.name.includes("hash") || c.name.includes("match")) ? "RECORD_TAMPERED" : "CREDENTIAL_ISSUER_INVALID";
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
