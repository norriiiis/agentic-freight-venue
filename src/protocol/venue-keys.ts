/**
 * Venue key hierarchy.
 *
 *   ROOT key        — offline, held by the venue OPERATOR, rotated by ceremony.
 *                     This is what agents and verifiers pin.
 *   OPERATIONAL key — held by the venue process; signs credentials, messages,
 *                     ledger entries, attestations. Certified by the root.
 *
 * Rotating the operational key needs a root-signed certificate for the new
 * key; the venue process cannot certify its own successor. A compromise is a
 * root-signed revocation with `compromisedAt`, after which anything the old
 * key signed is untrusted until re-signed by a trusted key.
 */
import { importPublicKey, jwkThumbprint, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";

export interface VenueKeyCert {
  schema: "freight-venue/venue-key-cert/v1";
  kid: string;
  publicKey: OkpJwk;
  seq: number;          // 0 for the first operational key
  validFrom: string;
  issuedBy: string;     // root kid
  reason: "INITIAL" | "ROTATION" | "COMPROMISE";
  rootSignature: string; // detached JWS by the root over the cert sans this field
}

export interface VenueKeyRevocation {
  schema: "freight-venue/venue-key-revocation/v1";
  kid: string;
  at: string;
  reason: "ROTATION" | "COMPROMISE";
  /** Signatures by this key at or after this time are untrusted (COMPROMISE only). */
  compromisedAt?: string;
  issuedBy: string;
  rootSignature: string;
}

/** The published, self-contained key history. Pin the root; everything else verifies from it. */
export interface VenueKeyHistory {
  venueId: string;
  rootPublicKey: OkpJwk;
  certs: VenueKeyCert[];
  revocations: VenueKeyRevocation[];
  asOf: string;
}

export function signCert(root: KeyPair, publicKey: OkpJwk, seq: number, reason: VenueKeyCert["reason"], now = new Date()): VenueKeyCert {
  const unsigned: Omit<VenueKeyCert, "rootSignature"> = { schema: "freight-venue/venue-key-cert/v1", kid: jwkThumbprint(publicKey), publicKey: { kty: "OKP", crv: "Ed25519", x: publicKey.x, kid: jwkThumbprint(publicKey) }, seq, validFrom: now.toISOString(), issuedBy: root.kid, reason };
  return { ...unsigned, rootSignature: signJws(unsigned, root, { typ: "venue-key-cert+jws" }, true) };
}

export function verifyCert(cert: VenueKeyCert, rootPublicKey: OkpJwk): boolean {
  const { rootSignature, ...unsigned } = cert;
  if (cert.issuedBy !== (rootPublicKey.kid ?? jwkThumbprint(rootPublicKey))) return false;
  if (cert.kid !== jwkThumbprint(cert.publicKey)) return false;
  return verifyJws(rootSignature, importPublicKey(rootPublicKey), unsigned).ok;
}

export function signRevocation(root: KeyPair, kid: string, reason: VenueKeyRevocation["reason"], compromisedAt?: string, now = new Date()): VenueKeyRevocation {
  const unsigned: Omit<VenueKeyRevocation, "rootSignature"> = { schema: "freight-venue/venue-key-revocation/v1", kid, at: now.toISOString(), reason, compromisedAt, issuedBy: root.kid };
  return { ...unsigned, rootSignature: signJws(unsigned, root, { typ: "venue-key-revocation+jws" }, true) };
}

export function verifyRevocation(r: VenueKeyRevocation, rootPublicKey: OkpJwk): boolean {
  const { rootSignature, ...unsigned } = r;
  if (r.issuedBy !== (rootPublicKey.kid ?? jwkThumbprint(rootPublicKey))) return false;
  return verifyJws(rootSignature, importPublicKey(rootPublicKey), unsigned).ok;
}

/**
 * A resolver that answers "which public key has this kid, and was it
 * trustworthy at time t?" — built from a pinned root and a history whose
 * every cert and revocation is checked against that root. Unverifiable
 * entries are ignored, never trusted.
 */
export interface VenueKeyResolver {
  rootPublicKey: OkpJwk;
  key(kid: string): OkpJwk | undefined;
  cert(kid: string): VenueKeyCert | undefined;
  /** undefined = trusted; otherwise why not. */
  untrustedAt(kid: string, at: Date): string | undefined;
  add(cert: VenueKeyCert): boolean;
  revoke(r: VenueKeyRevocation): boolean;
  kids(): string[];
}

export function makeResolver(rootPublicKey: OkpJwk, history?: Pick<VenueKeyHistory, "certs" | "revocations">): VenueKeyResolver {
  const root = { ...rootPublicKey, kid: rootPublicKey.kid ?? jwkThumbprint(rootPublicKey) };
  const certs = new Map<string, VenueKeyCert>();
  const revs = new Map<string, VenueKeyRevocation>();
  const r: VenueKeyResolver = {
    rootPublicKey: root,
    key: (kid) => certs.get(kid)?.publicKey,
    cert: (kid) => certs.get(kid),
    untrustedAt: (kid, at) => {
      const c = certs.get(kid);
      if (!c) return `unknown venue key ${kid.slice(0, 12)}…`;
      if (at < new Date(c.validFrom)) return `signature predates the key's certificate (${c.validFrom})`;
      const rv = revs.get(kid);
      if (rv?.compromisedAt && at >= new Date(rv.compromisedAt)) return `venue key declared compromised as of ${rv.compromisedAt}`;
      return undefined;
    },
    add: (c) => {
      if (!verifyCert(c, root)) return false;
      certs.set(c.kid, c);
      return true;
    },
    revoke: (rv) => {
      if (!verifyRevocation(rv, root)) return false;
      revs.set(rv.kid, rv);
      return true;
    },
    kids: () => [...certs.keys()],
  };
  for (const c of history?.certs ?? []) r.add(c);
  for (const rv of history?.revocations ?? []) r.revoke(rv);
  return r;
}
