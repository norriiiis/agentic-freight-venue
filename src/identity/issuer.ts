/**
 * Credential issuance and revocation. The issuer holds the venue's identity
 * signing key. A credential is a signed binding: (agent key) <-> (registry
 * entity), with evidence of what was checked at issuance, an expiry, and a
 * revocation status maintained here.
 */
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { signJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import type { Credential, RevocationEntry } from "../protocol/types";
import type { ReasonCode } from "../protocol/reasons";
import { authorityActive, insuranceStatus, type MockRegistry } from "./registry";
import type { VettingProvider } from "./vetting";

export interface IssueRequest {
  agentId: string;
  publicKey: OkpJwk;
  claimed: { usdot: string; mc?: string };
  proofOfControl: { method: string; token: string };
}

export type IssueResult =
  | { ok: true; credential: Credential }
  | { ok: false; reasonCode: ReasonCode; evidence: Record<string, unknown> };

export class CredentialIssuer {
  private issued = new Map<string, Credential>();
  private revocations = new Map<string, RevocationEntry>();
  private readonly dir: string;

  constructor(
    private readonly venueId: string,
    private readonly kp: KeyPair,
    private readonly registry: MockRegistry,
    private readonly vetting: VettingProvider,
    dataDir: string,
    private readonly validityDays = 90,
  ) {
    this.dir = join(dataDir, "identity");
    mkdirSync(this.dir, { recursive: true });
    this.load();
  }

  get issuerPublicKey(): OkpJwk {
    return this.kp.publicJwk;
  }

  private load() {
    const c = join(this.dir, "credentials.json");
    const r = join(this.dir, "revocations.json");
    if (existsSync(c)) for (const x of JSON.parse(readFileSync(c, "utf8")) as Credential[]) this.issued.set(x.credentialId, x);
    if (existsSync(r)) for (const x of JSON.parse(readFileSync(r, "utf8")) as RevocationEntry[]) this.revocations.set(x.credentialId, x);
  }
  private persist() {
    writeFileSync(join(this.dir, "credentials.json"), JSON.stringify([...this.issued.values()], null, 2));
    writeFileSync(join(this.dir, "revocations.json"), JSON.stringify([...this.revocations.values()], null, 2));
  }

  async issue(req: IssueRequest, now = new Date()): Promise<IssueResult> {
    const rec = this.registry.get(req.claimed.usdot);
    if (!rec || (req.claimed.mc && rec.mc !== req.claimed.mc)) {
      return { ok: false, reasonCode: "ONBOARDING_ENTITY_NOT_FOUND", evidence: { claimed: req.claimed } };
    }
    if (!authorityActive(rec, now)) {
      return { ok: false, reasonCode: "AUTHORITY_NOT_ACTIVE", evidence: { usdot: rec.usdot, operatingStatus: rec.operatingStatus, authorities: rec.authorities } };
    }
    const ins = insuranceStatus(rec, now);
    if (!ins.ok) {
      return { ok: false, reasonCode: ins.reasonCode!, evidence: { usdot: rec.usdot, insurance: ins } };
    }
    // STUB proof of control: production would challenge the FMCSA-registered
    // email/phone, or accept a vetting provider's verified-identity assertion.
    if (req.proofOfControl.token !== rec._proofOfControlToken) {
      return { ok: false, reasonCode: "ONBOARDING_PROOF_OF_CONTROL_FAILED", evidence: { usdot: rec.usdot, method: req.proofOfControl.method } };
    }
    const existing = [...this.issued.values()].find(
      (c) => c.subject.entity.usdot === rec.usdot && !this.revocations.has(c.credentialId) && new Date(c.expiresAt) > now && c.subject.publicKey.x !== req.publicKey.x,
    );
    if (existing) {
      return { ok: false, reasonCode: "ONBOARDING_KEY_ALREADY_BOUND", evidence: { usdot: rec.usdot, existingCredentialId: existing.credentialId } };
    }
    const vet = await this.vetting.assess(rec.usdot);
    if (vet.block) {
      return { ok: false, reasonCode: "ONBOARDING_PROOF_OF_CONTROL_FAILED", evidence: { usdot: rec.usdot, vetting: vet } };
    }

    const unsigned: Omit<Credential, "issuerSignature"> = {
      credentialId: `cred_${randomUUID()}`,
      schema: "freight-venue/agent-credential/v1",
      subject: {
        agentId: req.agentId,
        entity: { usdot: rec.usdot, mc: rec.mc, legalName: rec.legalName, entityType: rec.entityType },
        publicKey: { kty: "OKP", crv: "Ed25519", x: req.publicKey.x, kid: req.publicKey.kid },
      },
      issuer: { venueId: this.venueId, kid: this.kp.kid },
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.validityDays * 86_400_000).toISOString(),
      evidence: {
        registrySnapshotHash: this.registry.snapshotHash(rec.usdot),
        registryCheckedAt: now.toISOString(),
        insuranceCheckedAt: ins.asOf,
        vettingProvider: vet.provider,
        vettingFlags: vet.flags,
        proofOfControl: req.proofOfControl.method,
      },
    };
    const credential: Credential = { ...unsigned, issuerSignature: signJws(unsigned, this.kp, { typ: "agent-credential+jws" }, true) };
    this.issued.set(credential.credentialId, credential);
    this.persist();
    return { ok: true, credential };
  }

  revoke(credentialId: string, reason: string, evidence?: Record<string, unknown>, now = new Date()): RevocationEntry | undefined {
    if (!this.issued.has(credentialId)) return undefined;
    const entry: RevocationEntry = { credentialId, revokedAt: now.toISOString(), reason, evidence };
    this.revocations.set(credentialId, entry);
    this.persist();
    return entry;
  }

  get(credentialId: string): Credential | undefined {
    return this.issued.get(credentialId);
  }
  revocation(credentialId: string): RevocationEntry | undefined {
    return this.revocations.get(credentialId);
  }
  revocationList(): RevocationEntry[] {
    return [...this.revocations.values()];
  }
  credentialsFor(usdot: string): Credential[] {
    return [...this.issued.values()].filter((c) => c.subject.entity.usdot === usdot);
  }
}
