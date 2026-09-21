import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "../src/protocol/crypto";
import { buildMessage, signMessage } from "../src/protocol/envelope";
import { MockRegistry } from "../src/registry/store";
import { StubVettingProvider } from "../src/identity/vetting";
import { CredentialIssuer } from "../src/identity/issuer";
import { liveCheck, verifyCredential, verifyPresentation } from "../src/identity/verifier";

const FIXTURE = join(import.meta.dirname, "../src/identity/fixtures/registry.json");

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "fv-identity-"));
  const regPath = join(dir, "registry.json");
  copyFileSync(FIXTURE, regPath);
  const registry = new MockRegistry(regPath);
  const venueKp = generateKeyPair();
  const issuer = new CredentialIssuer("venue-test", venueKp, registry, new StubVettingProvider(registry), dir, 90);
  return { dir, registry, venueKp, issuer };
}

describe("identity: issuance binds an agent key to a registry entity", () => {
  let ctx: ReturnType<typeof setup>;
  beforeEach(() => { ctx = setup(); });

  it("issues a credential for a real, insured, authorized carrier with proof of control", async () => {
    const agent = generateKeyPair();
    const r = await ctx.issuer.issue({ agentId: "carrier-1", publicKey: agent.publicJwk, claimed: { usdot: "2751903", mc: "MC-0938251" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.credential.subject.entity.legalName).toBe("PRAIRIE WIND TRANSPORT INC");
    expect(verifyCredential(r.credential, { issuerPublicKey: ctx.venueKp.publicJwk }).ok).toBe(true);
  });

  it("refuses an entity not in the registry", async () => {
    const r = await ctx.issuer.issue({ agentId: "x", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "9999999" }, proofOfControl: { method: "stub", token: "x" } });
    expect(r).toMatchObject({ ok: false, reasonCode: "ONBOARDING_ENTITY_NOT_FOUND" });
  });

  it("refuses a real entity without proof of control (the cheap spoof)", async () => {
    const r = await ctx.issuer.issue({ agentId: "spoof", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "2751903", mc: "MC-0938251" }, proofOfControl: { method: "stub", token: "guess" } });
    expect(r).toMatchObject({ ok: false, reasonCode: "ONBOARDING_PROOF_OF_CONTROL_FAILED" });
  });

  it("refuses to bind a second key to an entity that already has a live credential", async () => {
    const a = await ctx.issuer.issue({ agentId: "c1", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "2751903" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } });
    expect(a.ok).toBe(true);
    const b = await ctx.issuer.issue({ agentId: "c2", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "2751903" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } });
    expect(b).toMatchObject({ ok: false, reasonCode: "ONBOARDING_KEY_ALREADY_BOUND" });
  });

  it("refuses when insurance is lapsed at issuance", async () => {
    ctx.registry.update("2751903", { insurance: ctx.registry.get("2751903")!.insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: "2026-09-01" } : f)) });
    const r = await ctx.issuer.issue({ agentId: "c", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "2751903" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } });
    expect(r).toMatchObject({ ok: false, reasonCode: "INSURANCE_LAPSED" });
  });

  it("refuses when authority is not active", async () => {
    ctx.registry.update("2751903", { operatingStatus: "OUT_OF_SERVICE", outOfServiceDate: "2026-08-15" });
    const r = await ctx.issuer.issue({ agentId: "c", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "2751903" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } });
    expect(r).toMatchObject({ ok: false, reasonCode: "AUTHORITY_NOT_ACTIVE" });
  });
});

describe("identity: verification catches expiry, revocation, forgery, and key mismatch", () => {
  let ctx: ReturnType<typeof setup>;
  beforeEach(() => { ctx = setup(); });

  async function issued(agentKp = generateKeyPair()) {
    const r = await ctx.issuer.issue({ agentId: "carrier-1", publicKey: agentKp.publicJwk, claimed: { usdot: "2751903" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } });
    if (!r.ok) throw new Error(r.reasonCode);
    return { cred: r.credential, agentKp };
  }

  it("expired credential is refused", async () => {
    const { cred } = await issued();
    const later = new Date(Date.now() + 91 * 86_400_000);
    expect(verifyCredential(cred, { issuerPublicKey: ctx.venueKp.publicJwk, now: later })).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_EXPIRED" });
  });

  it("revoked credential is refused with the revocation as evidence", async () => {
    const { cred } = await issued();
    const rev = ctx.issuer.revoke(cred.credentialId, "insurer filed cancellation");
    const v = verifyCredential(cred, { issuerPublicKey: ctx.venueKp.publicJwk, revocation: rev });
    expect(v).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_REVOKED" });
    expect(v.evidence.revocation).toMatchObject({ status: "REVOKED", reason: "insurer filed cancellation" });
  });

  it("credential signed by a different issuer is refused", async () => {
    const { cred } = await issued();
    expect(verifyCredential(cred, { issuerPublicKey: generateKeyPair().publicJwk })).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_ISSUER_INVALID" });
  });

  it("tampered credential (entity swapped) is refused", async () => {
    const { cred } = await issued();
    const forged = { ...cred, subject: { ...cred.subject, entity: { ...cred.subject.entity, usdot: "4102217" } } };
    expect(verifyCredential(forged, { issuerPublicKey: ctx.venueKp.publicJwk })).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_ISSUER_INVALID" });
  });

  it("spoofer with a genuine credential but the wrong private key is refused: IDENTITY_KEY_MISMATCH", async () => {
    const { cred } = await issued();
    const attacker = generateKeyPair();
    const m = signMessage(buildMessage({ role: "user", data: { type: "TENDER" }, senderAgentId: "carrier-1", credentialId: cred.credentialId }), attacker);
    const v = verifyPresentation(m, cred, { agentId: "carrier-1", usdot: "2751903" });
    expect(v).toMatchObject({ ok: false, reasonCode: "IDENTITY_KEY_MISMATCH" });
    expect(v.evidence.presentedKid).toBe(attacker.kid);
    expect(v.evidence.credentialBoundKid).toBe(cred.subject.publicKey.kid);
  });

  it("genuine holder whose message claims a different entity is refused: CREDENTIAL_ENTITY_MISMATCH", async () => {
    const { cred, agentKp } = await issued();
    const m = signMessage(buildMessage({ role: "user", data: {}, senderAgentId: "carrier-1", credentialId: cred.credentialId }), agentKp);
    expect(verifyPresentation(m, cred, { agentId: "carrier-1", usdot: "4102217" })).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_ENTITY_MISMATCH" });
  });

  it("live check catches insurance lapsing AFTER issuance", async () => {
    const { cred } = await issued();
    expect(liveCheck(ctx.registry, cred).ok).toBe(true);
    ctx.registry.update("2751903", { insurance: ctx.registry.get("2751903")!.insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: "2026-09-10" } : f)) });
    const v = liveCheck(ctx.registry, cred);
    expect(v).toMatchObject({ ok: false, reasonCode: "INSURANCE_LAPSED" });
    expect(v.evidence.snapshotChangedSinceIssuance).toBe(true);
    expect((v.evidence.lapsedFilings as unknown[]).length).toBe(1);
  });

  it("live check enforces the counterparty's required minimum above statutory", async () => {
    const r = await ctx.issuer.issue({ agentId: "redline", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "4102217" }, proofOfControl: { method: "stub", token: "poc-redline-9b04" } });
    if (!r.ok) throw new Error(r.reasonCode);
    expect(liveCheck(ctx.registry, r.credential, { requiredBipdUsd: 1_000_000 })).toMatchObject({ ok: false, reasonCode: "INSURANCE_BELOW_MINIMUM" });
  });
});

import { signatureTrustedAt } from "../src/identity/verifier";
import { signJws } from "../src/protocol/crypto";
import type { RotationClaims } from "../src/protocol/types";

describe("identity: key rotation", () => {
  let ctx: ReturnType<typeof setup>;
  beforeEach(() => { ctx = setup(); });

  async function onboarded() {
    const agentKp = generateKeyPair();
    const principal = generateKeyPair();
    // issued ten minutes ago, so tests can place signatures in the past
    const r = await ctx.issuer.issue({ agentId: "carrier-1", publicKey: agentKp.publicJwk, claimed: { usdot: "2751903" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } }, new Date(Date.now() - 10 * 60_000));
    if (!r.ok) throw new Error(r.reasonCode);
    return { cred: r.credential, agentKp, principal };
  }
  const claimsFor = (credentialId: string, newKp: ReturnType<typeof generateKeyPair>, reason: RotationClaims["reason"] = "ROTATION", compromisedAt?: string): RotationClaims => ({ credentialId, newKid: newKp.kid, ts: new Date().toISOString(), reason, compromisedAt });

  it("principal-authorized rotation issues a successor, supersedes the old with a grace window, keeps lineage", async () => {
    const { cred, principal } = await onboarded();
    const next = generateKeyPair();
    const claims = claimsFor(cred.credentialId, next);
    const r = await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next.publicJwk, authorization: { kind: "PRINCIPAL", jws: signJws(claims, principal, {}, true) }, claims, principalPublicKey: principal.publicJwk });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.credential.supersedes).toBe(cred.credentialId);
    expect(r.credential.subject.agentId).toBe("carrier-1");
    expect(r.credential.subject.publicKey.kid).toBe(next.kid);
    expect(r.superseded).toMatchObject({ status: "SUPERSEDED", reason: "ROTATION", supersededBy: r.credential.credentialId });
    expect(r.superseded.compromisedAt).toBeUndefined();
    expect(new Date(r.superseded.graceUntil!).getTime()).toBeGreaterThan(Date.now());
    expect(ctx.issuer.currentInLineage(cred.credentialId)?.credentialId).toBe(r.credential.credentialId);
    // old credential: accepted inside grace, refused after
    expect(verifyCredential(cred, { issuerPublicKey: ctx.venueKp.publicJwk, status: r.superseded }).ok).toBe(true);
    expect(verifyCredential(cred, { issuerPublicKey: ctx.venueKp.publicJwk, status: r.superseded, now: new Date(Date.now() + 11 * 60_000) })).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_SUPERSEDED" });
  });

  it("the agent's own current key cannot authorize rotation, even with a valid signature", async () => {
    const { cred, agentKp, principal } = await onboarded();
    const next = generateKeyPair();
    const claims = claimsFor(cred.credentialId, next);
    const r = await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next.publicJwk, authorization: { kind: "CURRENT_KEY_ONLY", jws: signJws(claims, agentKp, {}, true) }, claims, principalPublicKey: principal.publicJwk });
    expect(r).toMatchObject({ ok: false, reasonCode: "ROTATION_UNAUTHORIZED", evidence: { currentKeySignatureValid: true } });
    expect(ctx.issuer.status(cred.credentialId)).toBeUndefined();
  });

  it("a signature by some other key claiming to be the principal is refused; tampered claims are refused", async () => {
    const { cred, principal } = await onboarded();
    const next = generateKeyPair();
    const claims = claimsFor(cred.credentialId, next);
    const impostor = generateKeyPair();
    expect(await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next.publicJwk, authorization: { kind: "PRINCIPAL", jws: signJws(claims, impostor, {}, true) }, claims, principalPublicKey: principal.publicJwk })).toMatchObject({ ok: false, reasonCode: "ROTATION_UNAUTHORIZED" });
    const other = generateKeyPair();
    expect(await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: other.publicJwk, authorization: { kind: "PRINCIPAL", jws: signJws(claims, principal, {}, true) }, claims, principalPublicKey: principal.publicJwk })).toMatchObject({ ok: false, reasonCode: "ROTATION_UNAUTHORIZED" });
  });

  it("proof of control rotates without the principal key (principal key lost); wrong token is refused", async () => {
    const { cred } = await onboarded();
    const next = generateKeyPair();
    const claims = claimsFor(cred.credentialId, next);
    expect(await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next.publicJwk, authorization: { kind: "PROOF_OF_CONTROL", method: "stub", token: "guess" }, claims })).toMatchObject({ ok: false, reasonCode: "ROTATION_UNAUTHORIZED" });
    const r = await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next.publicJwk, authorization: { kind: "PROOF_OF_CONTROL", method: "stub", token: "poc-prairie-2c91" }, claims });
    expect(r.ok).toBe(true);
  });

  it("compromise rotation: no grace, compromisedAt recorded, old signatures judged by time", async () => {
    const { cred, principal } = await onboarded();
    const T = new Date(Date.now() - 60_000).toISOString();
    const next = generateKeyPair();
    const claims = claimsFor(cred.credentialId, next, "COMPROMISE", T);
    const r = await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next.publicJwk, authorization: { kind: "PRINCIPAL", jws: signJws(claims, principal, {}, true) }, claims, principalPublicKey: principal.publicJwk });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.superseded.compromisedAt).toBe(T);
    expect(verifyCredential(cred, { issuerPublicKey: ctx.venueKp.publicJwk, status: r.superseded })).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_SUPERSEDED" });
    expect(signatureTrustedAt(cred, new Date(Date.now() - 120_000), r.superseded).ok).toBe(true);   // signed before T
    expect(signatureTrustedAt(cred, new Date(Date.now() - 30_000), r.superseded)).toMatchObject({ ok: false, reasonCode: "COMMITMENT_UNDER_COMPROMISED_KEY" }); // signed after T
  });

  it("a superseded credential cannot be rotated again; the successor can", async () => {
    const { cred, principal } = await onboarded();
    const next = generateKeyPair();
    const c1 = claimsFor(cred.credentialId, next);
    const r1 = await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next.publicJwk, authorization: { kind: "PRINCIPAL", jws: signJws(c1, principal, {}, true) }, claims: c1, principalPublicKey: principal.publicJwk });
    if (!r1.ok) throw new Error(r1.reasonCode);
    const next2 = generateKeyPair();
    const c2 = claimsFor(cred.credentialId, next2);
    expect(await ctx.issuer.rotate({ credentialId: cred.credentialId, newPublicKey: next2.publicJwk, authorization: { kind: "PRINCIPAL", jws: signJws(c2, principal, {}, true) }, claims: c2, principalPublicKey: principal.publicJwk })).toMatchObject({ ok: false, reasonCode: "CREDENTIAL_SUPERSEDED" });
    const c3 = claimsFor(r1.credential.credentialId, next2);
    expect((await ctx.issuer.rotate({ credentialId: r1.credential.credentialId, newPublicKey: next2.publicJwk, authorization: { kind: "PRINCIPAL", jws: signJws(c3, principal, {}, true) }, claims: c3, principalPublicKey: principal.publicJwk })).ok).toBe(true);
  });

  it("onboarding a second key for an entity still says ALREADY_BOUND and points at rotation", async () => {
    await onboarded();
    const b = await ctx.issuer.issue({ agentId: "c2", publicKey: generateKeyPair().publicJwk, claimed: { usdot: "2751903" }, proofOfControl: { method: "stub", token: "poc-prairie-2c91" } });
    expect(b).toMatchObject({ ok: false, reasonCode: "ONBOARDING_KEY_ALREADY_BOUND", evidence: { howToRotate: expect.stringContaining("venue/rotate") } });
  });
});
