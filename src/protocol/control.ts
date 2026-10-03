/**
 * Proof that whoever is registering a key actually controls the operating
 * authority it is about to be bound to.
 *
 * This is the gate no signature downstream can repair. Every other check in
 * this system asks "is this entity in good standing" — this one asks "is this
 * the entity at all", and if it is wrong, a fraudster holds a credential the
 * venue issued, the registries vouch for, and the verifier passes. There is
 * nothing clever further down that recovers from it.
 *
 * Three properties the old stub did not have, and that everything here exists
 * to provide:
 *
 *   BOUND TO THE KEY. A proof names the public key it is about, by
 *   thumbprint. A proof obtained for one key is worthless for another, so
 *   intercepting one buys nothing unless you also hold that key.
 *
 *   SINGLE USE, AND DATED. Every proof carries an id the venue records and a
 *   window it is good for. Presenting one twice is refused as a replay.
 *
 *   SAID BY SOMEONE NAMED. Either the venue itself ran the challenge — it
 *   sent a code to the contact point on the public record and nobody else
 *   could read it — or a verifier the venue pins signed a statement about
 *   what it did. "The caller fetched a token from a public endpoint" is not
 *   one of the options.
 *
 * The honest limit, stated where it belongs rather than in a footnote: the
 * contact point on FMCSA's record is frequently a filing agent's address
 * rather than the carrier's, and is sometimes years stale. A challenge to it
 * proves control of THAT ADDRESS, which is a far better thing to know than
 * nothing and a worse thing than identity. That is why a second method
 * exists, why a credential records which method backed it, and why a verifier
 * reading an artifact can insist on one method and refuse another.
 */
import { importPublicKey, jwkThumbprint, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";
import type { ReasonCode } from "./reasons";

export const CONTROL_METHODS = [
  /** The venue sent a one-time code to the contact point on the public record and it came back. The venue ran it; nobody vouched. */
  "REGISTRY_CONTACT_CHALLENGE",
  /** A vetting provider the venue pins asserts it verified this entity's control of this key. */
  "VETTING_PROVIDER_ASSERTION",
  /** A named human at a pinned verifier did an out-of-band check and signed what they did. Strongest today, and it does not scale. */
  "OPERATOR_ATTESTED",
  /** SIMULATION ONLY: the registry's readable stub token. Accepted only when the venue is run in SIM_MODE, and never otherwise. */
  "SIM_STUB_TOKEN",
] as const;
export type ControlMethod = (typeof CONTROL_METHODS)[number];

/** What a verifier signs. The venue pins the verifier's key; the attestation names the key it is about. */
export interface ControlAttestation {
  schema: "freight-venue/control-attestation/v1";
  verifierId: string;
  usdot: string;
  mc?: string;
  /** JWK thumbprint of the key this proof is about. A proof is about one key and no other. */
  subjectKid: string;
  method: Exclude<ControlMethod, "REGISTRY_CONTACT_CHALLENGE" | "SIM_STUB_TOKEN">;
  /** What was actually done, in the verifier's own words. A hash stands in for anything the verifier holds and will not publish. */
  evidence: { note?: string; channel?: string; contactedAt?: string; operator?: string; reference?: string; evidenceHash?: string };
  verifiedAt: string;
  expiresAt: string;
  /** Single use. The venue records it and refuses a second presentation. */
  jti: string;
  kid: string;
  /** Detached JWS by the verifier's key over the attestation sans this field. */
  signature: string;
}

export interface ControlVerifierKey {
  verifierId: string;
  publicKey: OkpJwk;
  /** Which methods this verifier may assert. A vetting provider that may not speak for an operator's manual check, and the reverse. */
  methods?: ControlMethod[];
}

export function signControlAttestation(verifier: KeyPair, verifierId: string, fields: Omit<ControlAttestation, "schema" | "verifierId" | "kid" | "signature">): ControlAttestation {
  const unsigned: Omit<ControlAttestation, "signature"> = { schema: "freight-venue/control-attestation/v1", verifierId, ...fields, kid: verifier.kid };
  return { ...unsigned, signature: signJws(unsigned, verifier, { typ: "control-attestation+jws" }, true) };
}

export function verifyControlAttestation(a: ControlAttestation, key: OkpJwk): boolean {
  if (a.schema !== "freight-venue/control-attestation/v1") return false;
  const { signature, ...unsigned } = a;
  try {
    return verifyJws(signature, importPublicKey(key), unsigned).ok;
  } catch {
    return false;
  }
}

/** What an onboarding or a rotation presents as its proof. */
export type ControlProof =
  | { method: "REGISTRY_CONTACT_CHALLENGE"; challengeId: string }
  | { method: "VETTING_PROVIDER_ASSERTION" | "OPERATOR_ATTESTED"; attestation: ControlAttestation }
  | { method: "SIM_STUB_TOKEN"; token: string };

export interface ControlPolicy {
  /** Verifier keys this venue trusts. Empty means it runs its own challenges and accepts nobody's word. */
  verifiers: ControlVerifierKey[];
  /** Methods this venue will accept at all. */
  accept: ControlMethod[];
  /** How old a verifier's attestation may be when presented. */
  maxAgeMs: number;
}

export const DEFAULT_CONTROL_POLICY: ControlPolicy = {
  verifiers: [],
  accept: ["REGISTRY_CONTACT_CHALLENGE"],
  maxAgeMs: 7 * 24 * 60 * 60_000,
};

/** A satisfied challenge, as the venue's own store reports it. */
export interface SatisfiedChallenge { challengeId: string; usdot: string; subjectKid: string; satisfiedAt: string; sentTo: string; consumedAt?: string }

export interface ControlContext {
  policy: ControlPolicy;
  usdot: string;
  /** Thumbprint of the key being bound. Everything must agree about this. */
  subjectKid: string;
  now: Date;
  /** The venue's record of its own challenges. */
  challenge?: (id: string) => SatisfiedChallenge | undefined;
  /** Has this attestation id been presented before? */
  seen?: (jti: string) => boolean;
  /** SIM only: the readable token the mock registry serves. */
  stubToken?: string;
}

export type ControlVerdict = { ok: true; method: ControlMethod; verifierId?: string; verifiedAt: string; jti?: string } | { ok: false; reasonCode: ReasonCode; evidence: Record<string, unknown> };

/**
 * The whole decision, in one place, in the order the checks matter: is this
 * method allowed here at all, does the proof exist, is it about this entity,
 * is it about THIS KEY, is it fresh, has it been used, and did someone this
 * venue trusts actually say it.
 */
export function evaluateControl(proof: ControlProof | undefined, ctx: ControlContext): ControlVerdict {
  const p = ctx.policy;
  if (!proof) return { ok: false, reasonCode: "CONTROL_PROOF_MISSING", evidence: { usdot: ctx.usdot, accepted: p.accept } };
  if (!p.accept.includes(proof.method)) return { ok: false, reasonCode: "CONTROL_METHOD_NOT_ACCEPTED", evidence: { presented: proof.method, accepted: p.accept } };

  if (proof.method === "SIM_STUB_TOKEN") {
    // Only reachable when the operator put this venue in SIM_MODE; the policy above is what keeps it out of production.
    if (!ctx.stubToken || proof.token !== ctx.stubToken) return { ok: false, reasonCode: "ONBOARDING_PROOF_OF_CONTROL_FAILED", evidence: { usdot: ctx.usdot, method: proof.method } };
    return { ok: true, method: proof.method, verifiedAt: ctx.now.toISOString() };
  }

  if (proof.method === "REGISTRY_CONTACT_CHALLENGE") {
    const ch = ctx.challenge?.(proof.challengeId);
    if (!ch) return { ok: false, reasonCode: "CONTROL_CHALLENGE_FAILED", evidence: { challengeId: proof.challengeId, why: "no satisfied challenge with that id" } };
    if (ch.consumedAt) return { ok: false, reasonCode: "CONTROL_PROOF_REPLAYED", evidence: { challengeId: ch.challengeId, consumedAt: ch.consumedAt } };
    if (ch.usdot !== ctx.usdot) return { ok: false, reasonCode: "CONTROL_CHALLENGE_FAILED", evidence: { challengeId: ch.challengeId, challengeFor: ch.usdot, presentedFor: ctx.usdot, why: "a challenge proves control of the entity it was sent about, and no other" } };
    if (ch.subjectKid !== ctx.subjectKid) return { ok: false, reasonCode: "CONTROL_PROOF_NOT_BOUND_TO_KEY", evidence: { challengeId: ch.challengeId, boundTo: ch.subjectKid, presented: ctx.subjectKid, why: "the code went to the contact point for a different key; whoever holds this key did not receive it" } };
    return { ok: true, method: proof.method, verifiedAt: ch.satisfiedAt };
  }

  const a = proof.attestation;
  if (!a || a.schema !== "freight-venue/control-attestation/v1") return { ok: false, reasonCode: "CONTROL_PROOF_MISSING", evidence: { presented: proof.method, why: "no attestation, or not a control attestation" } };
  if (a.method !== proof.method) return { ok: false, reasonCode: "CONTROL_METHOD_NOT_ACCEPTED", evidence: { presented: proof.method, attests: a.method } };
  if (a.usdot !== ctx.usdot) return { ok: false, reasonCode: "CONTROL_CHALLENGE_FAILED", evidence: { attestationFor: a.usdot, presentedFor: ctx.usdot } };
  if (a.subjectKid !== ctx.subjectKid) return { ok: false, reasonCode: "CONTROL_PROOF_NOT_BOUND_TO_KEY", evidence: { boundTo: a.subjectKid, presented: ctx.subjectKid, verifierId: a.verifierId, why: "the verifier vouched for a different key than the one being registered" } };
  const v = p.verifiers.find((x) => x.verifierId === a.verifierId);
  if (!v) return { ok: false, reasonCode: "CONTROL_VERIFIER_UNTRUSTED", evidence: { verifierId: a.verifierId, pinned: p.verifiers.map((x) => x.verifierId), why: "this venue pins no key for that verifier, so its word is somebody's signature and not a proof" } };
  if (v.methods && !v.methods.includes(a.method)) return { ok: false, reasonCode: "CONTROL_METHOD_NOT_ACCEPTED", evidence: { verifierId: a.verifierId, method: a.method, mayAssert: v.methods } };
  if (v.publicKey.kid && a.kid !== v.publicKey.kid) return { ok: false, reasonCode: "CONTROL_VERIFIER_UNTRUSTED", evidence: { verifierId: a.verifierId, signedWith: a.kid, pinned: v.publicKey.kid } };
  if (!verifyControlAttestation(a, v.publicKey)) return { ok: false, reasonCode: "CONTROL_VERIFIER_UNTRUSTED", evidence: { verifierId: a.verifierId, why: "the signature does not verify under the pinned key" } };
  const verifiedAt = new Date(a.verifiedAt).getTime();
  const expires = new Date(a.expiresAt).getTime();
  if (!Number.isFinite(verifiedAt) || !Number.isFinite(expires)) return { ok: false, reasonCode: "CONTROL_PROOF_EXPIRED", evidence: { verifiedAt: a.verifiedAt, expiresAt: a.expiresAt, why: "undated" } };
  if (ctx.now.getTime() > expires) return { ok: false, reasonCode: "CONTROL_PROOF_EXPIRED", evidence: { expiresAt: a.expiresAt, now: ctx.now.toISOString() } };
  if (ctx.now.getTime() - verifiedAt > p.maxAgeMs) return { ok: false, reasonCode: "CONTROL_PROOF_EXPIRED", evidence: { verifiedAt: a.verifiedAt, ageMs: ctx.now.getTime() - verifiedAt, maxAgeMs: p.maxAgeMs, why: "control proven too long ago to still mean anything" } };
  if (ctx.seen?.(a.jti)) return { ok: false, reasonCode: "CONTROL_PROOF_REPLAYED", evidence: { jti: a.jti, verifierId: a.verifierId } };
  return { ok: true, method: a.method, verifierId: a.verifierId, verifiedAt: a.verifiedAt, jti: a.jti };
}

export const kidOf = (jwk: OkpJwk): string => jwk.kid ?? jwkThumbprint(jwk);
