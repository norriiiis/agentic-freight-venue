/**
 * Real cryptography: Ed25519 keypairs and a minimal JWS (RFC 7515) implementation
 * with `alg: EdDSA`, compact serialization, and optional detached payloads.
 *
 * Nothing here is mocked. Signatures produced here verify with any standard
 * Ed25519/JWS library.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, KeyObject } from "node:crypto";
import { canonicalize, sha256Hex } from "./canonical";

export interface OkpJwk {
  [k: string]: unknown;
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  d?: string;
  kid?: string;
}

export interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicJwk: OkpJwk;
  kid: string;
}

export function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}
export function fromB64url(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

/** RFC 7638 JWK thumbprint for an OKP key — a stable public key identifier. */
export function jwkThumbprint(jwk: OkpJwk): string {
  return sha256Hex(canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }));
}

export function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as OkpJwk;
  const kid = jwkThumbprint(publicJwk);
  return { privateKey, publicKey, publicJwk: { ...publicJwk, kid }, kid };
}

export function exportPrivateJwk(kp: KeyPair): OkpJwk {
  return { ...(kp.privateKey.export({ format: "jwk" }) as OkpJwk), kid: kp.kid };
}

export function importKeyPair(privateJwk: OkpJwk): KeyPair {
  const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
  const publicKey = createPublicKey(privateKey);
  const publicJwk = publicKey.export({ format: "jwk" }) as OkpJwk;
  const kid = jwkThumbprint(publicJwk);
  return { privateKey, publicKey, publicJwk: { ...publicJwk, kid }, kid };
}

export function importPublicKey(jwk: OkpJwk): KeyObject {
  const { d: _d, kid: _kid, ...pub } = jwk;
  return createPublicKey({ key: pub, format: "jwk" });
}

export function signBytes(data: Buffer, privateKey: KeyObject): Buffer {
  return sign(null, data, privateKey);
}
export function verifyBytes(data: Buffer, sig: Buffer, publicKey: KeyObject): boolean {
  try {
    return verify(null, data, publicKey, sig);
  } catch {
    return false;
  }
}

export interface JwsHeader {
  alg: "EdDSA";
  kid: string;
  typ?: string;
  /** Optional embedded public key (used on Agent Cards so they are self-describing). */
  jwk?: OkpJwk;
  /** Whether the payload is detached (RFC 7797 style, b64=false semantics simplified). */
  detached?: boolean;
  [k: string]: unknown;
}

/**
 * Sign an object. Returns compact JWS `header.payload.signature`.
 * With `detached: true`, the payload segment is empty and the caller must
 * supply the payload again at verification time.
 */
export function signJws(payload: unknown, kp: KeyPair, headerExtra: Partial<JwsHeader> = {}, detached = false): string {
  const header: JwsHeader = { alg: "EdDSA", kid: kp.kid, ...headerExtra, ...(detached ? { detached: true } : {}) };
  const h = b64url(canonicalize(header));
  const p = b64url(canonicalize(payload));
  const signingInput = Buffer.from(`${h}.${p}`, "utf8");
  const sig = b64url(signBytes(signingInput, kp.privateKey));
  return detached ? `${h}..${sig}` : `${h}.${p}.${sig}`;
}

export interface JwsVerifyResult {
  ok: boolean;
  header?: JwsHeader;
  payload?: unknown;
  error?: string;
}

/**
 * Verify a compact JWS against a known public key. For detached JWS, pass the
 * payload object in `detachedPayload`.
 */
export function verifyJws(jws: string, publicKey: KeyObject, detachedPayload?: unknown): JwsVerifyResult {
  const parts = jws.split(".");
  if (parts.length !== 3) return { ok: false, error: "malformed JWS" };
  const [h, pSeg, s] = parts as [string, string, string];
  let header: JwsHeader;
  try {
    header = JSON.parse(fromB64url(h).toString("utf8"));
  } catch {
    return { ok: false, error: "malformed JWS header" };
  }
  if (header.alg !== "EdDSA") return { ok: false, error: `unsupported alg ${header.alg}` };
  const p = pSeg === "" ? b64url(canonicalize(detachedPayload)) : pSeg;
  const signingInput = Buffer.from(`${h}.${p}`, "utf8");
  const ok = verifyBytes(signingInput, fromB64url(s), publicKey);
  if (!ok) return { ok: false, header, error: "signature does not verify" };
  const payload = pSeg === "" ? detachedPayload : JSON.parse(fromB64url(p).toString("utf8"));
  return { ok: true, header, payload };
}

export function jwsHeader(jws: string): JwsHeader | undefined {
  try {
    return JSON.parse(fromB64url(jws.split(".")[0] ?? "").toString("utf8"));
  } catch {
    return undefined;
  }
}
