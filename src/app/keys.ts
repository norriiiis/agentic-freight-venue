/**
 * Custody of a principal's signing key — the key whose whole purpose is that
 * the agent does not hold it.
 *
 * Hosting it here is a real weakening of that claim, and the honest statement
 * of what remains is: the agent process cannot widen its own mandate, and a
 * compromised agent cannot sign a new one; but the operator of this
 * application could. The console says so on the page where it matters. The
 * alternative — a client-held signer — is the `external` store below, which
 * holds no private material at all and leaves signing to the client.
 *
 * Why not AWS KMS: this protocol is Ed25519 end to end, and AWS KMS, Azure Key
 * Vault and GCP KMS all sign ECDSA/RSA only. HashiCorp Vault's transit engine
 * does Ed25519, so that is the managed option; `local` is envelope encryption
 * under a master key this process is given, which is software custody and is
 * labelled as such everywhere it appears.
 */
import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";
import { exportPrivateJwk, generateKeyPair, importKeyPair, signBytes, type OkpJwk, type RemoteSigner } from "../protocol/crypto";
import type { AppDb } from "./db";

export type StoreKind = "local" | "vault" | "external";

export interface PrincipalKeyStore {
  readonly kind: StoreKind;
  /** How this custody should be described to the person whose key it is. One sentence, no euphemism. */
  readonly disclosure: string;
  create(orgId: string): Promise<{ kid: string; publicJwk: OkpJwk }>;
  signer(orgId: string): Promise<RemoteSigner>;
}

const b64 = (b: Buffer) => b.toString("base64");

/** AES-256-GCM envelope encryption under APP_MASTER_KEY. Software custody, held beside the application database. */
export class LocalEncryptedKeyStore implements PrincipalKeyStore {
  readonly kind = "local" as const;
  readonly disclosure = "Held by this application, encrypted at rest under a master key held by its operator. The agent cannot reach it; the operator of this service can.";
  constructor(private readonly db: AppDb, private readonly masterKey: Buffer) {
    if (masterKey.length !== 32) throw new Error("APP_MASTER_KEY must decode to exactly 32 bytes");
  }
  private wrap(jwk: OkpJwk): string {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.masterKey, iv);
    const ct = Buffer.concat([c.update(JSON.stringify(jwk), "utf8"), c.final()]);
    return `v1.${b64(iv)}.${b64(c.getAuthTag())}.${b64(ct)}`;
  }
  private unwrap(wrapped: string): OkpJwk {
    const [v, iv, tag, ct] = wrapped.split(".");
    if (v !== "v1" || !iv || !tag || !ct) throw new Error("principal key: unrecognised wrapping");
    const d = createDecipheriv("aes-256-gcm", this.masterKey, Buffer.from(iv, "base64"));
    d.setAuthTag(Buffer.from(tag, "base64"));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(ct, "base64")), d.final()]).toString("utf8")) as OkpJwk;
  }
  async create(orgId: string) {
    const kp = generateKeyPair();
    this.db.run("INSERT INTO principal_keys (org_id, kid, public_jwk, store, wrapped, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      orgId, kp.kid, JSON.stringify(kp.publicJwk), this.kind, this.wrap(exportPrivateJwk(kp)), new Date().toISOString());
    return { kid: kp.kid, publicJwk: kp.publicJwk };
  }
  async signer(orgId: string): Promise<RemoteSigner> {
    const row = this.db.principalKey(orgId);
    if (!row || !row.wrapped) throw new Error(`no principal key in custody for ${orgId}`);
    const kp = importKeyPair(this.unwrap(row.wrapped));
    return { kid: kp.kid, publicJwk: kp.publicJwk, sign: async (data) => signBytes(data, kp.privateKey) };
  }
}

/** HashiCorp Vault transit (ed25519). The private half never leaves Vault; this process can only ask it to sign. */
export class VaultTransitKeyStore implements PrincipalKeyStore {
  readonly kind = "vault" as const;
  readonly disclosure = "Held in HashiCorp Vault. The private half never reaches this application, which can only ask Vault to sign; every signature is in Vault's own audit log.";
  constructor(private readonly db: AppDb, private readonly opts: { addr: string; token: string; mount?: string; fetchImpl?: typeof fetch }) {}
  private get base() { return `${this.opts.addr.replace(/\/$/, "")}/v1/${this.opts.mount ?? "transit"}`; }
  private async call(path: string, body?: unknown): Promise<Record<string, unknown>> {
    const f = this.opts.fetchImpl ?? fetch;
    const res = await f(`${this.base}${path}`, { method: body ? "POST" : "GET", headers: { "x-vault-token": this.opts.token, "content-type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) });
    if (!res.ok) throw new Error(`vault ${path}: HTTP ${res.status}`);
    return ((await res.json()) as { data?: Record<string, unknown> }).data ?? {};
  }
  private keyName(orgId: string) { return `principal-${orgId}`; }
  async create(orgId: string) {
    await this.call(`/keys/${this.keyName(orgId)}`, { type: "ed25519" });
    const data = await this.call(`/keys/${this.keyName(orgId)}`);
    const keys = data.keys as Record<string, { public_key: string }> | undefined;
    const latest = keys ? keys[String(Math.max(...Object.keys(keys).map(Number)))] : undefined;
    if (!latest) throw new Error("vault returned no public key");
    const publicJwk: OkpJwk = { kty: "OKP", crv: "Ed25519", x: Buffer.from(latest.public_key, "base64").toString("base64url") };
    const kid = (await import("../protocol/crypto")).jwkThumbprint(publicJwk);
    publicJwk.kid = kid;
    this.db.run("INSERT INTO principal_keys (org_id, kid, public_jwk, store, wrapped, created_at) VALUES (?, ?, ?, ?, NULL, ?)",
      orgId, kid, JSON.stringify(publicJwk), this.kind, new Date().toISOString());
    return { kid, publicJwk };
  }
  async signer(orgId: string): Promise<RemoteSigner> {
    const row = this.db.principalKey(orgId);
    if (!row) throw new Error(`no principal key for ${orgId}`);
    const publicJwk = JSON.parse(row.publicJwk) as OkpJwk;
    const name = this.keyName(orgId);
    const call = this.call.bind(this);
    return {
      kid: row.kid,
      publicJwk,
      async sign(data: Buffer) {
        const out = await call(`/sign/${name}`, { input: data.toString("base64") });
        const sig = String(out.signature ?? "");
        const raw = sig.split(":").pop() ?? "";
        return Buffer.from(raw, "base64");
      },
    };
  }
}

/**
 * The client holds its own key; this application holds only the public half
 * and the signatures the client sends back. Nothing here can sign, which is
 * the point — onboarding gains a step where the client runs `npm run mandate`
 * and uploads the result.
 */
export class ExternalKeyStore implements PrincipalKeyStore {
  readonly kind = "external" as const;
  readonly disclosure = "Held by you. This application has your public key and nothing else: it cannot sign a mandate, and neither can your agent.";
  constructor(private readonly db: AppDb) {}
  async create(): Promise<{ kid: string; publicJwk: OkpJwk }> {
    throw new Error("this principal holds its own key: register the public half instead of asking the service to make one");
  }
  /** Record a client-supplied public key. */
  register(orgId: string, publicJwk: OkpJwk, kid: string) {
    this.db.run("INSERT INTO principal_keys (org_id, kid, public_jwk, store, wrapped, created_at) VALUES (?, ?, ?, ?, NULL, ?)",
      orgId, kid, JSON.stringify(publicJwk), this.kind, new Date().toISOString());
  }
  async signer(): Promise<RemoteSigner> {
    throw new Error("this principal signs for itself; the application cannot");
  }
}

export function keyStoreFromEnv(db: AppDb, env: NodeJS.ProcessEnv = process.env): PrincipalKeyStore {
  const kind = (env.APP_KEY_STORE ?? "local") as StoreKind;
  if (kind === "vault") {
    if (!env.VAULT_ADDR || !env.VAULT_TOKEN) throw new Error("APP_KEY_STORE=vault needs VAULT_ADDR and VAULT_TOKEN");
    return new VaultTransitKeyStore(db, { addr: env.VAULT_ADDR, token: env.VAULT_TOKEN, mount: env.VAULT_TRANSIT_MOUNT });
  }
  if (kind === "external") return new ExternalKeyStore(db);
  const raw = env.APP_MASTER_KEY;
  if (!raw) throw new Error("APP_MASTER_KEY is required (32 bytes, base64) — generate one with: openssl rand -base64 32");
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) throw new Error(`APP_MASTER_KEY decoded to ${key.length} bytes; 32 required`);
  return new LocalEncryptedKeyStore(db, key);
}

/** Constant-time compare for tokens that gate anything. */
export function tokenEq(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
