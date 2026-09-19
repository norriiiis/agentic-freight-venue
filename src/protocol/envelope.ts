/**
 * Message signing. Two signatures can ride on a Message:
 *   metadata.sig      — the originating agent's detached JWS (proves who said it)
 *   metadata.venueSig — the venue's detached JWS over the same surface + sig
 *                        (proves the venue verified and routed it)
 * Agents only accept envelopes carrying a valid venueSig. This is what makes
 * direct agent-to-agent contact impossible by construction: an agent's inbound
 * endpoint rejects anything the venue did not sign.
 */
import { randomUUID } from "node:crypto";
import type { Message, Part } from "./a2a";
import { FREIGHT_EXTENSION_URI, agentSigningSurface, venueSigningSurface } from "./a2a";
import { importPublicKey, jwsHeader, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";
import { sha256Hex } from "./canonical";

/** What the venue attaches to a forwarded message: attested facts about the sender, for the recipient's mandate check. */
export interface VenueAttachment {
  taskId: string;
  contextId: string;
  round: number;
  forwardedAt: string;
  counterparty: {
    agentId: string;
    credentialId: string;
    entity: { usdot: string; mc?: string; legalName: string; entityType: string };
    publicKey: OkpJwk;
    insurance: { bipdUsd: number; cargoUsd: number; bondUsd: number };
    verifiedAt: string;
  };
  /** Present when the venue has already quoted a guarantee for this commitment. */
  guaranteeAvailable?: boolean;
}

export interface SignedMeta {
  credentialId: string;
  senderAgentId: string;
  nonce: string;
  ts: string;
  sig?: string;
  venueSig?: string;
  venue?: VenueAttachment;
  [k: string]: unknown;
}

export function buildMessage(opts: {
  role: "user" | "agent";
  data: Record<string, unknown>;
  taskId?: string;
  contextId?: string;
  senderAgentId: string;
  credentialId: string;
  extraParts?: Part[];
}): Message {
  const meta: SignedMeta = {
    credentialId: opts.credentialId,
    senderAgentId: opts.senderAgentId,
    nonce: randomUUID(),
    ts: new Date().toISOString(),
  };
  return {
    kind: "message",
    role: opts.role,
    parts: [{ kind: "data", data: opts.data }, ...(opts.extraParts ?? [])],
    messageId: randomUUID(),
    taskId: opts.taskId,
    contextId: opts.contextId,
    extensions: [FREIGHT_EXTENSION_URI],
    metadata: meta,
  };
}

/** Agent signs: detached JWS over the message digest input. */
export function signMessage(m: Message, kp: KeyPair): Message {
  const digest = { messageDigest: sha256Hex(agentSigningSurface(m)) };
  const sig = signJws(digest, kp, { typ: "a2a-msg+jws" }, true);
  return { ...m, metadata: { ...(m.metadata ?? {}), sig } };
}

export function verifyMessageSignature(m: Message, senderPublicKey: OkpJwk): { ok: boolean; error?: string; kid?: string } {
  const sig = (m.metadata as SignedMeta | undefined)?.sig;
  if (!sig) return { ok: false, error: "missing metadata.sig" };
  const digest = { messageDigest: sha256Hex(agentSigningSurface(m)) };
  const res = verifyJws(sig, importPublicKey(senderPublicKey), digest);
  return { ok: res.ok, error: res.error, kid: jwsHeader(sig)?.kid };
}

/** Venue countersigns a verified message before forwarding. Covers the agent's sig too. */
export function venueSignMessage(m: Message, venueKp: KeyPair, attachment?: VenueAttachment): Message {
  const meta = { ...((m.metadata ?? {}) as SignedMeta), ...(attachment ? { venue: attachment } : {}) };
  const withAttachment = { ...m, metadata: meta };
  const surface = { messageDigest: sha256Hex(venueSigningSurface(withAttachment)) };
  const venueSig = signJws(surface, venueKp, { typ: "a2a-venue+jws" }, true);
  return { ...withAttachment, metadata: { ...meta, venueSig } };
}

export function verifyVenueSignature(m: Message, venuePublicKey: OkpJwk): { ok: boolean; error?: string } {
  const meta = (m.metadata ?? {}) as SignedMeta;
  if (!meta.venueSig) return { ok: false, error: "missing metadata.venueSig" };
  const surface = { messageDigest: sha256Hex(venueSigningSurface(m)) };
  const res = verifyJws(meta.venueSig, importPublicKey(venuePublicKey), surface);
  return { ok: res.ok, error: res.error };
}
