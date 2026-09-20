/**
 * Venue key hierarchy.
 *
 *   ROOT key        — offline, held by the venue OPERATOR. What agents and
 *                     verifiers pin. Rotates by PRE-ROTATION: every root
 *                     establishment commits to the hash of the NEXT root,
 *                     generated at the same ceremony and kept even more
 *                     offline. A rotation reveals that key (it must match the
 *                     commitment) and commits to a new next. A thief holding
 *                     the current root cannot rotate — they do not hold the
 *                     pre-committed successor. This is KERI's pre-rotation.
 *   OPERATIONAL key — held by the venue process; signs credentials, messages,
 *                     ledger entries, attestations. Certified by a root.
 *
 * Trust is evaluated from whatever root a verifier pinned: the root log is
 * walked forward from that root, each step proven by the commitment and the
 * new root's own signature. Certificates issued by any root on that walk are
 * accepted unless the issuing root was declared compromised before the
 * certificate was signed.
 */
import { canonicalize, sha256Hex } from "./canonical";
import { importPublicKey, jwkThumbprint, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";

// ---- root events ------------------------------------------------------------

export interface RootEvent {
  schema: "freight-venue/root-event/v1";
  seq: number;
  rootKid: string;
  rootPublicKey: OkpJwk;
  previousRootKid?: string;
  /** sha256 of the canonical public JWK (kty, crv, x) of the NEXT root, which the operator already holds offline. */
  nextRootCommitment: string;
  at: string;
  reason: "ESTABLISHMENT" | "ROTATION" | "COMPROMISE";
  /** COMPROMISE: the previous root is untrusted for anything it signed at or after this time. */
  compromisedAt?: string;
  /** Detached JWS by the root this event establishes (the NEW root). Its authority is the previous event's commitment. */
  signature: string;
  /** Optional countersignature by the previous root — evidence of a planned handover, never required (the previous root may be the compromised one). */
  previousRootSignature?: string;
}

export function rootCommitment(nextRootPublicKey: OkpJwk): string {
  return sha256Hex(canonicalize({ crv: nextRootPublicKey.crv, kty: nextRootPublicKey.kty, x: nextRootPublicKey.x }));
}

export function signRootEvent(newRoot: KeyPair, fields: Omit<RootEvent, "schema" | "rootKid" | "rootPublicKey" | "signature" | "previousRootSignature">, previousRoot?: KeyPair): RootEvent {
  const unsigned: Omit<RootEvent, "signature" | "previousRootSignature"> = { schema: "freight-venue/root-event/v1", rootKid: newRoot.kid, rootPublicKey: { kty: "OKP", crv: "Ed25519", x: newRoot.publicJwk.x, kid: newRoot.kid }, ...fields };
  const signature = signJws(unsigned, newRoot, { typ: "venue-root-event+jws" }, true);
  const previousRootSignature = previousRoot ? signJws(unsigned, previousRoot, { typ: "venue-root-event+jws" }, true) : undefined;
  return { ...unsigned, signature, previousRootSignature };
}

/** Is this event well-formed and self-signed? (Its AUTHORITY is checked by walkRootLog against the previous commitment.) */
export function verifyRootEventSelf(e: RootEvent): boolean {
  const { signature, previousRootSignature: _p, ...unsigned } = e;
  if (e.rootKid !== jwkThumbprint(e.rootPublicKey)) return false;
  return verifyJws(signature, importPublicKey(e.rootPublicKey), unsigned).ok;
}

export interface RootWalk {
  /** Every root reachable from the pinned one, with the time from which it is untrusted (if a successor declared it compromised). */
  roots: Map<string, { publicKey: OkpJwk; seq: number; untrustedFrom?: string }>;
  current: { kid: string; publicKey: OkpJwk; seq: number; nextRootCommitment: string };
  /** Events that were rejected (bad commitment, bad signature, broken link) — never trusted. */
  rejected: { seq: number; why: string }[];
}

/**
 * Walk a root log from a pinned root — forward to successors and backward to
 * predecessors. Forward: each next event must link to the current root, its
 * new key must match the current root's commitment, and it must be signed by
 * the new key. Backward: the pinned root's own event names its predecessor,
 * and the predecessor's commitment must match the pinned root — a two-way
 * link, so a trusted root vouches for its ancestry (needed to verify things
 * signed under earlier roots). A predecessor that a successor declared
 * compromised is untrusted from that time. The pinned root need not be the
 * first in the log; a verifier may have pinned a later one.
 */
export function walkRootLog(pinnedRoot: OkpJwk, log: RootEvent[]): RootWalk | undefined {
  const pinnedKid = pinnedRoot.kid ?? jwkThumbprint(pinnedRoot);
  const sorted = [...log].sort((a, b) => a.seq - b.seq);
  const start = sorted.find((e) => e.rootKid === pinnedKid && e.rootPublicKey.x === pinnedRoot.x && verifyRootEventSelf(e));
  const roots: RootWalk["roots"] = new Map();
  const rejected: RootWalk["rejected"] = [];
  if (!start) {
    // The pinned root has no establishment event in this log: trust it alone, with no successors.
    return { roots: new Map([[pinnedKid, { publicKey: pinnedRoot, seq: -1 }]]), current: { kid: pinnedKid, publicKey: pinnedRoot, seq: -1, nextRootCommitment: "" }, rejected };
  }
  roots.set(start.rootKid, { publicKey: start.rootPublicKey, seq: start.seq });
  // backward
  let child = start;
  while (child.previousRootKid) {
    const parent = sorted.find((e) => e.rootKid === child.previousRootKid && e.seq === child.seq - 1);
    if (!parent || !verifyRootEventSelf(parent) || rootCommitment(child.rootPublicKey) !== parent.nextRootCommitment) {
      rejected.push({ seq: child.seq - 1, why: "predecessor event missing, unsigned, or its commitment does not match" });
      break;
    }
    roots.set(parent.rootKid, { publicKey: parent.rootPublicKey, seq: parent.seq, untrustedFrom: child.reason === "COMPROMISE" ? child.compromisedAt : undefined });
    child = parent;
  }
  // forward
  let cur = start;
  for (const e of sorted.filter((x) => x.seq > start.seq)) {
    if (e.previousRootKid !== cur.rootKid) { rejected.push({ seq: e.seq, why: "does not link to the current root" }); continue; }
    if (rootCommitment(e.rootPublicKey) !== cur.nextRootCommitment) { rejected.push({ seq: e.seq, why: "new root does not match the pre-committed successor" }); continue; }
    if (!verifyRootEventSelf(e)) { rejected.push({ seq: e.seq, why: "not signed by the new root" }); continue; }
    if (e.reason === "COMPROMISE" && e.compromisedAt) roots.get(cur.rootKid)!.untrustedFrom = e.compromisedAt;
    roots.set(e.rootKid, { publicKey: e.rootPublicKey, seq: e.seq });
    cur = e;
  }
  return { roots, current: { kid: cur.rootKid, publicKey: cur.rootPublicKey, seq: cur.seq, nextRootCommitment: cur.nextRootCommitment }, rejected };
}

// ---- operational key certificates ------------------------------------------

export interface VenueKeyCert {
  schema: "freight-venue/venue-key-cert/v1";
  kid: string;
  publicKey: OkpJwk;
  seq: number;
  /** Start of the key's tenure. A re-certification after a root compromise carries the ORIGINAL validFrom: the operator affirms the whole tenure. */
  validFrom: string;
  /** When this certificate was signed (the moment that matters for "was the issuing root trusted?"). */
  issuedAt: string;
  issuedBy: string;     // root kid
  reason: "INITIAL" | "ROTATION" | "COMPROMISE" | "RECERTIFICATION";
  rootSignature: string;
}

export interface VenueKeyRevocation {
  schema: "freight-venue/venue-key-revocation/v1";
  kid: string;
  at: string;
  reason: "ROTATION" | "COMPROMISE";
  compromisedAt?: string;
  issuedBy: string;
  rootSignature: string;
}

export interface VenueKeyHistory {
  venueId: string;
  /** The CURRENT root. Verifiers who pinned an earlier root reach it through rootLog. */
  rootPublicKey: OkpJwk;
  rootLog: RootEvent[];
  certs: VenueKeyCert[];
  revocations: VenueKeyRevocation[];
  asOf: string;
}

export function signCert(root: KeyPair, publicKey: OkpJwk, seq: number, reason: VenueKeyCert["reason"], now = new Date(), validFrom = now): VenueKeyCert {
  const kid = jwkThumbprint(publicKey);
  const unsigned: Omit<VenueKeyCert, "rootSignature"> = { schema: "freight-venue/venue-key-cert/v1", kid, publicKey: { kty: "OKP", crv: "Ed25519", x: publicKey.x, kid }, seq, validFrom: validFrom.toISOString(), issuedAt: now.toISOString(), issuedBy: root.kid, reason };
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

// ---- resolver ----------------------------------------------------------------

export interface VenueKeyResolver {
  /** The root the verifier pinned. */
  rootPublicKey: OkpJwk;
  /** The current root after walking the log (== pinned if no rotation is known). */
  currentRoot: OkpJwk;
  key(kid: string): OkpJwk | undefined;
  cert(kid: string): VenueKeyCert | undefined;
  /** undefined = trusted at that time; otherwise why not. */
  untrustedAt(kid: string, at: Date): string | undefined;
  add(cert: VenueKeyCert): boolean;
  revoke(r: VenueKeyRevocation): boolean;
  /** Extend the root walk with more events (e.g. from a freshly fetched history). Returns true if the current root changed. */
  extendRoots(log: RootEvent[]): boolean;
  rootTrusted(kid: string): boolean;
  kids(): string[];
  rootKids(): string[];
}

export function makeResolver(pinnedRoot: OkpJwk, history?: Partial<Pick<VenueKeyHistory, "certs" | "revocations" | "rootLog">>): VenueKeyResolver {
  const pinned = { ...pinnedRoot, kid: pinnedRoot.kid ?? jwkThumbprint(pinnedRoot) };
  let walk = walkRootLog(pinned, history?.rootLog ?? [])!;
  const seenLog: RootEvent[] = [...(history?.rootLog ?? [])];
  const certs = new Map<string, VenueKeyCert[]>();
  const revs = new Map<string, VenueKeyRevocation>();

  const certTrusted = (c: VenueKeyCert): boolean => {
    const issuer = walk.roots.get(c.issuedBy);
    if (!issuer) return false;
    if (issuer.untrustedFrom && new Date(c.issuedAt) >= new Date(issuer.untrustedFrom)) return false;
    return true;
  };
  const r: VenueKeyResolver = {
    rootPublicKey: pinned,
    get currentRoot() { return walk.current.publicKey; },
    key: (kid) => certs.get(kid)?.find(certTrusted)?.publicKey,
    cert: (kid) => certs.get(kid)?.find(certTrusted),
    untrustedAt: (kid, at) => {
      const all = certs.get(kid) ?? [];
      if (all.length === 0) return `unknown venue key ${kid.slice(0, 12)}…`;
      const usable = all.filter(certTrusted);
      if (usable.length === 0) return `venue key ${kid.slice(0, 12)}… certified only by a root declared compromised before the certificate was signed`;
      if (!usable.some((c) => at >= new Date(c.validFrom))) return `signature predates the key's certificate (${usable.map((c) => c.validFrom).join(", ")})`;
      const rv = revs.get(kid);
      if (rv?.compromisedAt && at >= new Date(rv.compromisedAt)) return `venue key declared compromised as of ${rv.compromisedAt}`;
      return undefined;
    },
    add: (c) => {
      const issuer = walk.roots.get(c.issuedBy);
      if (!issuer || !verifyCert(c, issuer.publicKey)) return false;
      const list = certs.get(c.kid) ?? [];
      if (!list.some((x) => x.rootSignature === c.rootSignature)) list.push(c);
      certs.set(c.kid, list);
      return true;
    },
    revoke: (rv) => {
      const issuer = walk.roots.get(rv.issuedBy);
      if (!issuer || !verifyRevocation(rv, issuer.publicKey)) return false;
      if (issuer.untrustedFrom && new Date(rv.at) >= new Date(issuer.untrustedFrom)) return false;
      revs.set(rv.kid, rv);
      return true;
    },
    extendRoots: (log) => {
      for (const e of log) if (!seenLog.some((x) => x.seq === e.seq && x.rootKid === e.rootKid)) seenLog.push(e);
      const before = walk.current.kid;
      walk = walkRootLog(pinned, seenLog)!;
      return walk.current.kid !== before;
    },
    rootTrusted: (kid) => walk.roots.has(kid),
    kids: () => [...certs.keys()].filter((k) => r.key(k) !== undefined),
    rootKids: () => [...walk.roots.entries()].sort((a, b) => a[1].seq - b[1].seq).map(([k]) => k),
  };
  for (const c of history?.certs ?? []) r.add(c);
  for (const rv of history?.revocations ?? []) r.revoke(rv);
  return r;
}
