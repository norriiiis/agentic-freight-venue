/**
 * Proof of control: the gate nothing downstream repairs.
 *
 * Each test here is an attack the old stub allowed. A token any caller could
 * read proved only that the caller could reach the registry — so these assert
 * the three properties that replaced it: a proof is about one key, it is good
 * once, and somebody named said it.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { generateKeyPair } from "../src/protocol/crypto";
import { DEFAULT_CONTROL_POLICY, evaluateControl, signControlAttestation, verifyControlAttestation, type ControlAttestation, type ControlPolicy, type ControlProof } from "../src/protocol/control";
import { ControlStore } from "../src/identity/control-store";

const tmp = () => mkdtempSync(join(tmpdir(), "control-"));
const NOW = new Date("2026-10-03T12:00:00Z");
const verifier = generateKeyPair();
const theirKey = generateKeyPair();
const myKey = generateKeyPair();

const policy = (over: Partial<ControlPolicy> = {}): ControlPolicy => ({
  ...DEFAULT_CONTROL_POLICY,
  accept: ["REGISTRY_CONTACT_CHALLENGE", "OPERATOR_ATTESTED", "VETTING_PROVIDER_ASSERTION"],
  verifiers: [{ verifierId: "a-vetting-provider", publicKey: verifier.publicJwk, methods: ["OPERATOR_ATTESTED", "VETTING_PROVIDER_ASSERTION"] }],
  ...over,
});

const attest = (over: Partial<Parameters<typeof signControlAttestation>[2]> = {}): ControlAttestation =>
  signControlAttestation(verifier, "a-vetting-provider", {
    usdot: "2751903", subjectKid: theirKey.kid, method: "OPERATOR_ATTESTED",
    evidence: { note: "called the number on the record", operator: "R. Hale" },
    verifiedAt: NOW.toISOString(), expiresAt: new Date(NOW.getTime() + 86_400_000).toISOString(), jti: `cta_${randomUUID()}`,
    ...over,
  });

describe("a challenge proves control of the contact point, and of one key", () => {
  const setup = () => {
    const store = new ControlStore(tmp(), { cooldownMs: 0 });
    const issued = store.issue({ usdot: "2751903", subjectKid: theirKey.kid, sentTo: "dispatch@prairie.example", channel: "file" }, NOW);
    return { store, issued };
  };
  const ctx = (store: ControlStore, over: Record<string, unknown> = {}) => ({
    policy: policy(), usdot: "2751903", subjectKid: theirKey.kid, now: NOW,
    challenge: (id: string) => store.satisfied(id), seen: (j: string) => store.seen(j), ...over,
  });

  it("is worth nothing until the code comes back", () => {
    const { store, issued } = setup();
    const proof: ControlProof = { method: "REGISTRY_CONTACT_CHALLENGE", challengeId: issued.challengeId };
    expect(evaluateControl(proof, ctx(store))).toMatchObject({ ok: false, reasonCode: "CONTROL_CHALLENGE_FAILED" });
    expect(store.verify(issued.challengeId, issued.code, NOW).ok).toBe(true);
    expect(evaluateControl(proof, ctx(store))).toMatchObject({ ok: true, method: "REGISTRY_CONTACT_CHALLENGE" });
  });

  it("refuses a code that is close but wrong, and dies after a handful of guesses", () => {
    const { store, issued } = setup();
    const wrong = String((Number(issued.code) + 1) % 1_000_000).padStart(6, "0");
    for (let i = 0; i < 4; i++) expect(store.verify(issued.challengeId, wrong, NOW)).toMatchObject({ ok: false, attemptsLeft: 4 - i });
    expect(store.verify(issued.challengeId, wrong, NOW)).toMatchObject({ ok: false, attemptsLeft: 0 });
    // and now the right code is no use either: the challenge is closed
    expect(store.verify(issued.challengeId, issued.code, NOW)).toMatchObject({ ok: false, why: expect.stringContaining("closed") });
  });

  it("is about ONE key: a challenge answered for my key does not register yours", () => {
    const { store, issued } = setup();
    store.verify(issued.challengeId, issued.code, NOW);
    const proof: ControlProof = { method: "REGISTRY_CONTACT_CHALLENGE", challengeId: issued.challengeId };
    const v = evaluateControl(proof, ctx(store, { subjectKid: myKey.kid }));
    expect(v).toMatchObject({ ok: false, reasonCode: "CONTROL_PROOF_NOT_BOUND_TO_KEY" });
    expect((v as unknown as { evidence: { boundTo: string } }).evidence.boundTo).toBe(theirKey.kid);
  });

  it("is about ONE entity: a challenge for my USDOT does not register yours", () => {
    const { store, issued } = setup();
    store.verify(issued.challengeId, issued.code, NOW);
    expect(evaluateControl({ method: "REGISTRY_CONTACT_CHALLENGE", challengeId: issued.challengeId }, ctx(store, { usdot: "3312874" })))
      .toMatchObject({ ok: false, reasonCode: "CONTROL_CHALLENGE_FAILED" });
  });

  it("is spent once", () => {
    const { store, issued } = setup();
    store.verify(issued.challengeId, issued.code, NOW);
    const proof: ControlProof = { method: "REGISTRY_CONTACT_CHALLENGE", challengeId: issued.challengeId };
    expect(evaluateControl(proof, ctx(store))).toMatchObject({ ok: true });
    store.consume({ challengeId: issued.challengeId }, NOW);
    expect(evaluateControl(proof, ctx(store))).toMatchObject({ ok: false, reasonCode: "CONTROL_PROOF_REPLAYED" });
  });

  it("expires, and will not be re-sent to the same carrier on demand", () => {
    const store = new ControlStore(tmp(), { ttlMs: 60_000, cooldownMs: 10 * 60_000 });
    const issued = store.issue({ usdot: "2751903", subjectKid: theirKey.kid, sentTo: "dispatch@prairie.example", channel: "file" }, NOW);
    expect(store.verify(issued.challengeId, issued.code, new Date(NOW.getTime() + 61_000))).toMatchObject({ ok: false, why: expect.stringContaining("expired") });
    expect(store.cooldownRemainingMs("2751903", NOW)).toBe(10 * 60_000);
    expect(store.cooldownRemainingMs("3312874", NOW)).toBe(0);
  });

  it("survives a restart: a challenge answered before a crash is still answered after it", () => {
    const dir = tmp();
    const a = new ControlStore(dir, { cooldownMs: 0 });
    const issued = a.issue({ usdot: "2751903", subjectKid: theirKey.kid, sentTo: "x@y.example", channel: "file" }, NOW);
    a.verify(issued.challengeId, issued.code, NOW);
    const b = new ControlStore(dir, { cooldownMs: 0 });
    expect(b.satisfied(issued.challengeId)).toMatchObject({ usdot: "2751903", subjectKid: theirKey.kid });
  });
});

describe("a verifier's word counts only if the venue pinned it", () => {
  const base = { policy: policy(), usdot: "2751903", subjectKid: theirKey.kid, now: NOW, seen: () => false };

  it("accepts a pinned verifier's attestation about this key", () => {
    const v = evaluateControl({ method: "OPERATOR_ATTESTED", attestation: attest() }, base);
    expect(v).toMatchObject({ ok: true, method: "OPERATOR_ATTESTED", verifierId: "a-vetting-provider" });
  });

  it("refuses a verifier nobody pinned, and a signature that is not theirs", () => {
    const stranger = generateKeyPair();
    const theirs = signControlAttestation(stranger, "someone-else", { usdot: "2751903", subjectKid: theirKey.kid, method: "OPERATOR_ATTESTED", evidence: {}, verifiedAt: NOW.toISOString(), expiresAt: new Date(NOW.getTime() + 86_400_000).toISOString(), jti: "cta_1" });
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: theirs }, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_VERIFIER_UNTRUSTED" });
    // the right verifier id, signed by the wrong key
    const forged = signControlAttestation(stranger, "a-vetting-provider", { usdot: "2751903", subjectKid: theirKey.kid, method: "OPERATOR_ATTESTED", evidence: {}, verifiedAt: NOW.toISOString(), expiresAt: new Date(NOW.getTime() + 86_400_000).toISOString(), jti: "cta_2" });
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: forged }, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_VERIFIER_UNTRUSTED" });
    // tampered after signing
    const tampered = { ...attest(), subjectKid: myKey.kid };
    expect(verifyControlAttestation(tampered, verifier.publicJwk)).toBe(false);
  });

  it("refuses a verifier speaking outside what it may assert", () => {
    const p = policy({ verifiers: [{ verifierId: "a-vetting-provider", publicKey: verifier.publicJwk, methods: ["VETTING_PROVIDER_ASSERTION"] }] });
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: attest() }, { ...base, policy: p })).toMatchObject({ ok: false, reasonCode: "CONTROL_METHOD_NOT_ACCEPTED" });
  });

  it("refuses an attestation about another key, another entity, or one that has gone stale", () => {
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: attest({ subjectKid: myKey.kid }) }, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_PROOF_NOT_BOUND_TO_KEY" });
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: attest({ usdot: "3312874" }) }, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_CHALLENGE_FAILED" });
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: attest() }, { ...base, now: new Date(NOW.getTime() + 2 * 86_400_000) })).toMatchObject({ ok: false, reasonCode: "CONTROL_PROOF_EXPIRED" });
    const old = attest({ verifiedAt: new Date(NOW.getTime() - 30 * 86_400_000).toISOString(), expiresAt: new Date(NOW.getTime() + 86_400_000).toISOString() });
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: old }, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_PROOF_EXPIRED" });
  });

  it("refuses one that has already been spent", () => {
    const a = attest();
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: a }, { ...base, seen: (j: string) => j === a.jti })).toMatchObject({ ok: false, reasonCode: "CONTROL_PROOF_REPLAYED" });
  });
});

describe("the venue's policy decides what counts, not the caller", () => {
  it("refuses a method it does not accept, and the simulator's shortcut by default", () => {
    const base = { policy: DEFAULT_CONTROL_POLICY, usdot: "2751903", subjectKid: theirKey.kid, now: NOW, stubToken: "poc-prairie-2c91" };
    expect(DEFAULT_CONTROL_POLICY.accept).toEqual(["REGISTRY_CONTACT_CHALLENGE"]);
    expect(evaluateControl({ method: "SIM_STUB_TOKEN", token: "poc-prairie-2c91" }, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_METHOD_NOT_ACCEPTED" });
    expect(evaluateControl({ method: "OPERATOR_ATTESTED", attestation: attest() }, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_METHOD_NOT_ACCEPTED" });
    expect(evaluateControl(undefined, base)).toMatchObject({ ok: false, reasonCode: "CONTROL_PROOF_MISSING" });
  });

  it("accepts the simulator's token only where it was switched on", () => {
    const sim = policy({ accept: ["SIM_STUB_TOKEN"] });
    const base = { policy: sim, usdot: "2751903", subjectKid: theirKey.kid, now: NOW, stubToken: "poc-prairie-2c91" };
    expect(evaluateControl({ method: "SIM_STUB_TOKEN", token: "poc-prairie-2c91" }, base)).toMatchObject({ ok: true });
    expect(evaluateControl({ method: "SIM_STUB_TOKEN", token: "guess" }, base)).toMatchObject({ ok: false, reasonCode: "ONBOARDING_PROOF_OF_CONTROL_FAILED" });
  });
});
