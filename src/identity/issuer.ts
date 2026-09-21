/**
 * Credential issuance and revocation. The issuer holds the venue's identity
 * signing key. A credential is a signed binding: (agent key) <-> (registry
 * entity), with evidence of what was checked at issuance, an expiry, and a
 * revocation status maintained here.
 */
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { importPublicKey, jwkThumbprint, signJws, verifyJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import type { Credential, CredentialStatusEntry, RotationAuthorization, RotationClaims } from "../protocol/types";
import type { ReasonCode } from "../protocol/reasons";
import { authorityActive, insuranceStatus, type RegistryRecord, type RegistryView } from "../protocol/registry";
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

export interface RotateRequest {
  credentialId: string;
  newPublicKey: OkpJwk;
  authorization: RotationAuthorization;
  claims: RotationClaims;
  /** Principal key registered for this agent (from the mandate envelope), if any. */
  principalPublicKey?: OkpJwk;
}

export type RotateResult =
  | { ok: true; credential: Credential; superseded: CredentialStatusEntry }
  | { ok: false; reasonCode: ReasonCode; evidence: Record<string, unknown> };

export class CredentialIssuer {
  private issued = new Map<string, Credential>();
  private statuses = new Map<string, CredentialStatusEntry>();
  private readonly dir: string;

  private readonly signer: () => KeyPair;
  constructor(
    private readonly venueId: string,
    signer: KeyPair | (() => KeyPair),
    private readonly registry: RegistryView,
    private readonly vetting: VettingProvider,
    dataDir: string,
    private readonly validityDays = 90,
    /** How long a routinely-rotated credential is still accepted for in-flight messages. */
    private readonly rotationGraceMs = 10 * 60_000,
    /** How fresh the registry's signed word must be at issuance. */
    private readonly registryMaxAgeMs = 60_000,
  ) {
    this.signer = typeof signer === "function" ? signer : () => signer;
    this.dir = join(dataDir, "identity");
    mkdirSync(this.dir, { recursive: true });
    this.load();
  }

  /** The CURRENT issuing key. Older credentials name their own issuer kid; verify them with a resolver, not this. */
  get issuerPublicKey(): OkpJwk {
    return this.signer().publicJwk;
  }
  private get kp(): KeyPair {
    return this.signer();
  }

  private load() {
    const c = join(this.dir, "credentials.json");
    const r = join(this.dir, "credential-status.json");
    if (existsSync(c)) for (const x of JSON.parse(readFileSync(c, "utf8")) as Credential[]) this.issued.set(x.credentialId, x);
    if (existsSync(r)) for (const x of JSON.parse(readFileSync(r, "utf8")) as CredentialStatusEntry[]) this.statuses.set(x.credentialId, x);
  }
  private persist() {
    writeFileSync(join(this.dir, "credentials.json"), JSON.stringify([...this.issued.values()], null, 2));
    writeFileSync(join(this.dir, "credential-status.json"), JSON.stringify([...this.statuses.values()], null, 2));
  }

  /** Is this credential currently usable (unexpired, not revoked, not superseded-outside-grace)? */
  private isLive(c: Credential, now: Date): boolean {
    if (new Date(c.expiresAt) <= now) return false;
    const st = this.statuses.get(c.credentialId);
    if (!st) return true;
    if (st.status === "REVOKED") return false;
    return !st.compromisedAt && !!st.graceUntil && new Date(st.graceUntil) > now;
  }

  async issue(req: IssueRequest, now = new Date()): Promise<IssueResult> {
    // The registry's word, fresh: a credential binds a key to what the REGISTRY says, not to what the venue remembers.
    if (this.registry.refresh) {
      try {
        await this.registry.refresh(req.claimed.usdot, this.registryMaxAgeMs, now);
      } catch (e) {
        return { ok: false, reasonCode: "REGISTRY_UNAVAILABLE", evidence: { claimed: req.claimed, error: (e as Error).message } };
      }
    }
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
      (c) => c.subject.entity.usdot === rec.usdot && !this.statuses.has(c.credentialId) && new Date(c.expiresAt) > now && c.subject.publicKey.x !== req.publicKey.x,
    );
    if (existing) {
      return { ok: false, reasonCode: "ONBOARDING_KEY_ALREADY_BOUND", evidence: { usdot: rec.usdot, existingCredentialId: existing.credentialId, howToRotate: "venue/rotate with PRINCIPAL authorization or PROOF_OF_CONTROL" } };
    }
    const vet = await this.vetting.assess(rec.usdot);
    if (vet.block) {
      return { ok: false, reasonCode: "ONBOARDING_PROOF_OF_CONTROL_FAILED", evidence: { usdot: rec.usdot, vetting: vet } };
    }

    const credential = this.mint(req.agentId, rec, req.publicKey, { insuranceCheckedAt: ins.asOf, vettingProvider: vet.provider, vettingFlags: vet.flags, proofOfControl: req.proofOfControl.method }, now);
    this.issued.set(credential.credentialId, credential);
    this.persist();
    return { ok: true, credential };
  }

  /** The signed registry word a credential was issued against (a mirror); absent for a bare store. */
  private registryRef(usdot: string): Credential["evidence"]["registry"] {
    const a = this.registry.attestation?.(usdot);
    return a ? { registryId: a.registryId, kid: a.kid, asOf: a.asOf } : undefined;
  }

  private mint(agentId: string, rec: RegistryRecord, publicKey: OkpJwk, ev: { insuranceCheckedAt: string; vettingProvider: string; vettingFlags: string[]; proofOfControl: string }, now: Date, supersedes?: string): Credential {
    const kid = publicKey.kid ?? jwkThumbprint(publicKey);
    const unsigned: Omit<Credential, "issuerSignature"> = {
      credentialId: `cred_${randomUUID()}`,
      schema: "freight-venue/agent-credential/v1",
      subject: {
        agentId,
        entity: { usdot: rec.usdot, mc: rec.mc, legalName: rec.legalName, entityType: rec.entityType },
        publicKey: { kty: "OKP", crv: "Ed25519", x: publicKey.x, kid },
      },
      issuer: { venueId: this.venueId, kid: this.kp.kid },
      issuedAt: now.toISOString(),
      signedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.validityDays * 86_400_000).toISOString(),
      supersedes,
      evidence: { registrySnapshotHash: this.registry.snapshotHash(rec.usdot), registryCheckedAt: now.toISOString(), registry: this.registryRef(rec.usdot), ...ev },
    };
    return { ...unsigned, issuerSignature: signJws(unsigned, this.kp, { typ: "agent-credential+jws" }, true) };
  }

  /**
   * Rotate the key behind a credential. The new credential keeps the agent id,
   * entity and lineage; the old one becomes SUPERSEDED. Authority comes from
   * the principal key (registered in the mandate envelope) or from proof of
   * control against the registry — never from the agent's current key alone,
   * so a stolen agent key cannot rebind itself to the thief.
   */
  async rotate(req: RotateRequest, now = new Date()): Promise<RotateResult> {
    const old = this.issued.get(req.credentialId);
    if (!old) return { ok: false, reasonCode: "CREDENTIAL_UNKNOWN", evidence: { credentialId: req.credentialId } };
    const oldStatus = this.statuses.get(old.credentialId);
    if (oldStatus?.status === "SUPERSEDED" && oldStatus.supersededBy) {
      return { ok: false, reasonCode: "CREDENTIAL_SUPERSEDED", evidence: { credentialId: old.credentialId, supersededBy: oldStatus.supersededBy, note: "rotate the current credential in the lineage" } };
    }
    const newKid = jwkThumbprint(req.newPublicKey);
    const c = req.claims;
    if (c.credentialId !== old.credentialId || c.newKid !== newKid || Math.abs(now.getTime() - new Date(c.ts).getTime()) > 5 * 60_000) {
      return { ok: false, reasonCode: "ROTATION_UNAUTHORIZED", evidence: { error: "claims do not match request (credentialId / newKid / ts)", claims: c, newKid } };
    }
    if (newKid === old.subject.publicKey.kid && c.reason !== "RENEWAL") {
      return { ok: false, reasonCode: "ROTATION_UNAUTHORIZED", evidence: { error: "new key equals current key; use reason RENEWAL to extend without rotating" } };
    }
    // ---- authority ----
    const a = req.authorization;
    if (a.kind === "CURRENT_KEY_ONLY") {
      const sig = verifyJws(a.jws, importPublicKey(old.subject.publicKey), c);
      return { ok: false, reasonCode: "ROTATION_UNAUTHORIZED", evidence: { presented: "CURRENT_KEY_ONLY", currentKeySignatureValid: sig.ok, why: "an agent key must not be able to rebind itself; a thief holding it would lock the principal out", accepted: ["PRINCIPAL", "PROOF_OF_CONTROL"] } };
    }
    if (a.kind === "PRINCIPAL") {
      if (!req.principalPublicKey) return { ok: false, reasonCode: "ROTATION_UNAUTHORIZED", evidence: { presented: "PRINCIPAL", error: "no principal key registered for this agent (no mandate envelope); use PROOF_OF_CONTROL" } };
      const sig = verifyJws(a.jws, importPublicKey(req.principalPublicKey), c);
      if (!sig.ok) return { ok: false, reasonCode: "ROTATION_UNAUTHORIZED", evidence: { presented: "PRINCIPAL", error: sig.error, principalKid: req.principalPublicKey.kid } };
    }
    if (a.kind === "PROOF_OF_CONTROL") {
      const rec0 = this.registry.get(old.subject.entity.usdot);
      if (!rec0 || a.token !== rec0._proofOfControlToken) return { ok: false, reasonCode: "ROTATION_UNAUTHORIZED", evidence: { presented: "PROOF_OF_CONTROL", error: "proof of control failed" } };
    }
    // ---- same standing checks as onboarding (a rotation is a re-issuance) ----
    if (this.registry.refresh) {
      try {
        await this.registry.refresh(old.subject.entity.usdot, this.registryMaxAgeMs, now);
      } catch (e) {
        return { ok: false, reasonCode: "REGISTRY_UNAVAILABLE", evidence: { usdot: old.subject.entity.usdot, error: (e as Error).message } };
      }
    }
    const rec = this.registry.get(old.subject.entity.usdot);
    if (!rec) return { ok: false, reasonCode: "ONBOARDING_ENTITY_NOT_FOUND", evidence: { usdot: old.subject.entity.usdot } };
    if (!authorityActive(rec, now)) return { ok: false, reasonCode: "AUTHORITY_NOT_ACTIVE", evidence: { usdot: rec.usdot, operatingStatus: rec.operatingStatus } };
    const ins = insuranceStatus(rec, now);
    if (!ins.ok) return { ok: false, reasonCode: ins.reasonCode!, evidence: { usdot: rec.usdot, insurance: ins } };
    const vet = await this.vetting.assess(rec.usdot);
    if (vet.block) return { ok: false, reasonCode: "ONBOARDING_PROOF_OF_CONTROL_FAILED", evidence: { usdot: rec.usdot, vetting: vet } };

    const credential = this.mint(old.subject.agentId, rec, req.newPublicKey, { insuranceCheckedAt: ins.asOf, vettingProvider: vet.provider, vettingFlags: vet.flags, proofOfControl: `rotation:${a.kind}` }, now, old.credentialId);
    const compromise = c.reason === "COMPROMISE";
    const superseded: CredentialStatusEntry = {
      credentialId: old.credentialId,
      status: "SUPERSEDED",
      at: now.toISOString(),
      reason: c.reason,
      supersededBy: credential.credentialId,
      graceUntil: compromise ? now.toISOString() : new Date(now.getTime() + this.rotationGraceMs).toISOString(),
      compromisedAt: compromise ? (c.compromisedAt ?? now.toISOString()) : undefined,
      evidence: { authorizedBy: a.kind, newKid },
    };
    this.issued.set(credential.credentialId, credential);
    this.statuses.set(old.credentialId, superseded);
    this.persist();
    return { ok: true, credential, superseded };
  }

  revoke(credentialId: string, reason: string, evidence?: Record<string, unknown>, now = new Date()): CredentialStatusEntry | undefined {
    if (!this.issued.has(credentialId)) return undefined;
    const entry: CredentialStatusEntry = { credentialId, status: "REVOKED", at: now.toISOString(), reason, evidence };
    this.statuses.set(credentialId, entry);
    this.persist();
    return entry;
  }

  get(credentialId: string): Credential | undefined {
    return this.issued.get(credentialId);
  }
  /** Non-ACTIVE status (REVOKED or SUPERSEDED), if any. */
  status(credentialId: string): CredentialStatusEntry | undefined {
    return this.statuses.get(credentialId);
  }
  /** @deprecated use status(); kept so call sites that only care about revocation read naturally. */
  revocation(credentialId: string): CredentialStatusEntry | undefined {
    return this.statuses.get(credentialId);
  }
  /** The published status list: what an offline verifier needs to judge old signatures. */
  statusList(): CredentialStatusEntry[] {
    return [...this.statuses.values()];
  }
  /** Status list signed by the current venue key (kid in the JWS header), so a copy can be trusted offline. */
  signedStatusList(): { venueId: string; kid: string; asOf: string; entries: CredentialStatusEntry[]; signature: string } {
    const body = { venueId: this.venueId, kid: this.kp.kid, asOf: new Date().toISOString(), entries: this.statusList() };
    return { ...body, signature: signJws(body, this.kp, { typ: "credential-status+jws" }, true) };
  }

  /**
   * After a venue-key compromise: every credential this venue issued under the
   * compromised key at or after `compromisedAt` is re-signed under the current
   * key. Same id, same subject, same evidence — only the issuer signature
   * changes. The venue's own records, not the signature, say which credentials
   * are genuine; re-signing lets OFFLINE verifiers trust them again.
   */
  reissueUnder(compromisedKid: string, compromisedAt: Date, now = new Date()): Credential[] {
    const out: Credential[] = [];
    for (const c of this.issued.values()) {
      if (c.issuer.kid !== compromisedKid || new Date(c.issuedAt) < compromisedAt) continue;
      const { issuerSignature: _old, ...unsigned } = c;
      const reissued: Omit<Credential, "issuerSignature"> = { ...unsigned, issuer: { venueId: this.venueId, kid: this.kp.kid }, signedAt: now.toISOString(), evidence: { ...c.evidence, reissued: { fromKid: compromisedKid, at: now.toISOString(), reason: "venue key compromise" } } as Credential["evidence"] };
      const next: Credential = { ...reissued, issuerSignature: signJws(reissued, this.kp, { typ: "agent-credential+jws" }, true) };
      this.issued.set(next.credentialId, next);
      out.push(next);
    }
    if (out.length) this.persist();
    return out;
  }
  /** Walk the lineage forward to the credential that currently represents this agent. */
  currentInLineage(credentialId: string): Credential | undefined {
    let c = this.issued.get(credentialId);
    const seen = new Set<string>();
    while (c) {
      const st = this.statuses.get(c.credentialId);
      if (!st?.supersededBy || seen.has(c.credentialId)) return c;
      seen.add(c.credentialId);
      c = this.issued.get(st.supersededBy);
    }
    return undefined;
  }
  credentialsFor(usdot: string): Credential[] {
    return [...this.issued.values()].filter((c) => c.subject.entity.usdot === usdot);
  }
}
