import { describe, it, expect } from "vitest";
import { clockFromEnv, DEFAULT_CLOCK } from "../src/protocol/clock";
import { generateKeyPair } from "../src/protocol/crypto";
import { insurerAttestationProblems, signInsurerAttestation } from "../src/protocol/registry";

describe("clock policy: every tolerance in one place", () => {
  it("defaults are the documented ones; the environment overrides each; nonsense is refused", () => {
    expect(clockFromEnv({})).toEqual(DEFAULT_CLOCK);
    const c = clockFromEnv({ VENUE_CLOCK_SKEW_MS: "5000", VENUE_ROTATION_GRACE_MS: "0", VENUE_WITNESS_STALENESS_MS: "" });
    expect(c.skewMs).toBe(5000);
    expect(c.rotationGraceMs).toBe(0);
    expect(c.witnessStalenessMs).toBe(DEFAULT_CLOCK.witnessStalenessMs);
    expect(() => clockFromEnv({ VENUE_CLOCK_SKEW_MS: "soon" })).toThrow(/not a non-negative number of milliseconds/);
    expect(() => clockFromEnv({ VENUE_MSG_MAX_AGE_MS: "-1" })).toThrow();
    expect(clockFromEnv({ REG_CLOCK_SKEW_MS: "7" }, "REG_").skewMs).toBe(7);
  });
});

describe("a party's own check on its insurer's word, before presenting it", () => {
  const insurer = generateKeyPair();
  const now = new Date("2026-09-21T12:00:00Z");
  const policy = { usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01" };
  const good = signInsurerAttestation(insurer, "great-plains-mutual", policy, now);
  const pin = { insurerId: "great-plains-mutual", publicKey: insurer.publicJwk };

  it("passes a genuine word about this party, with or without a pinned insurer key", () => {
    expect(insurerAttestationProblems(good, { usdot: "2751903", now })).toEqual([]);
    expect(insurerAttestationProblems(good, { usdot: "2751903", insurer: pin, now })).toEqual([]);
  });
  it("refuses a word about someone else, a lapsed one, or one from the future — no registry needed", () => {
    expect(insurerAttestationProblems(good, { usdot: "3312874", now })).toEqual(["attestation is about USDOT 2751903, not this party (3312874)"]);
    const lapsed = signInsurerAttestation(insurer, "great-plains-mutual", { ...policy, cancellation: { filedDate: "2026-08-01", effectiveDate: "2026-09-01" } }, now);
    expect(insurerAttestationProblems(lapsed, { usdot: "2751903", now })).toEqual(["coverage cancelled effective 2026-09-01: this word attests a lapse, not coverage"]);
    const pending = signInsurerAttestation(insurer, "great-plains-mutual", { ...policy, cancellation: { filedDate: "2026-09-20", effectiveDate: "2026-10-20" } }, now);
    expect(insurerAttestationProblems(pending, { usdot: "2751903", now })).toEqual([]); // a pending cancellation is the venue's business (through-delivery), not a lapse
    const future = signInsurerAttestation(insurer, "great-plains-mutual", policy, new Date(now.getTime() + 10 * 60_000));
    expect(insurerAttestationProblems(future, { usdot: "2751903", now })[0]).toMatch(/is in the future/);
    expect(insurerAttestationProblems(future, { usdot: "2751903", now, skewMs: 11 * 60_000 })).toEqual([]);
    expect(insurerAttestationProblems({ ...good, schema: "freight-venue/coi/v0" as never }, { usdot: "2751903", now })[0]).toMatch(/schema/);
  });
  it("with the insurer's key pinned, refuses another insurer's word, a rotated key, and a forged signature", () => {
    const thief = generateKeyPair();
    const forged = signInsurerAttestation(thief, "great-plains-mutual", policy, now);
    expect(insurerAttestationProblems(forged, { usdot: "2751903", insurer: pin, now })).toEqual([`signed with kid ${thief.kid}, not the pinned insurer key ${insurer.kid} (a rotated key needs a new pin from the insurer, not from the venue)`]);
    const other = signInsurerAttestation(thief, "acme-surety", policy, now);
    expect(insurerAttestationProblems(other, { usdot: "2751903", insurer: pin, now })).toEqual(["signed by insurer acme-surety, not the principal's pinned insurer great-plains-mutual"]);
    const tampered = { ...good, coverageToUsd: 5_000_000 };
    expect(insurerAttestationProblems(tampered, { usdot: "2751903", insurer: pin, now })).toEqual(["signature does not verify under the pinned insurer key"]);
    // without a pin, the tampered word passes the party's own check — the venue's filer-of-record check is what catches it
    expect(insurerAttestationProblems(tampered, { usdot: "2751903", now })).toEqual([]);
  });
});
