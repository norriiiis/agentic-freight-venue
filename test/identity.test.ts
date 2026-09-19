import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "../src/protocol/crypto";
import { buildMessage, signMessage } from "../src/protocol/envelope";
import { MockRegistry } from "../src/identity/registry";
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
    expect(v.evidence.revocation).toMatchObject({ reason: "insurer filed cancellation" });
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
