import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UnderwritingEngine } from "../src/underwriting/engine";
import { DEFAULT_PARAMS } from "../src/underwriting/types";
import { adjudicate, newClaim, reserveAvailable, type Claim, type ClaimContext } from "../src/underwriting/claims";

const tmp = () => mkdtempSync(join(tmpdir(), "claims-"));
const NOW = new Date("2026-09-25T12:00:00Z");
const guarantee = { guaranteeId: "g1", commitmentId: "cmt_1", beneficiaryUsdot: "3312874", coveredAmountUsd: 2215, status: "CLAIMABLE" };
const commitment: ClaimContext["commitment"] = { status: "COMPLETED", deliveryWindowEnd: "2026-09-24T17:00:00Z", lifecycle: [{ event: "PICKED_UP", at: "2026-09-23T15:30:00Z", by: "2751903" }] };
const claim = (over: Partial<Claim> = {}): Claim => ({ ...newClaim({ guaranteeId: "g1", commitmentId: "cmt_1", claimantUsdot: "3312874", peril: "IDENTITY_FRAUD", amountUsd: 5000, evidence: {} }, NOW), ...over });
const ctx = (over: Partial<ClaimContext> = {}): ClaimContext => ({ guarantee, commitment, now: NOW, claimWindowDays: 90, ...over });

describe("claims: adjudicated by declared rules, each a line of the basis", () => {
  it("covers a beneficiary's in-scope claim within the window, capped at the covered amount", () => {
    const d = adjudicate(claim(), ctx())!;
    expect(d.covered).toBe(true);
    expect(d.payoutUsd).toBe(2215);
    expect(d.basis).toEqual([
      "claimant is the beneficiary",
      "guarantee claimable",
      "peril IDENTITY_FRAUD is in scope",
      "within the 90-day claim window",
      "payout capped at the covered amount: min(5000, 2215) = 2215",
    ]);
    expect(d.decidedBy).toBe("rules");
  });
  it("denies with the rule that denied it", () => {
    expect(adjudicate(claim(), ctx({ guarantee: undefined }))!.reasonCode).toBe("CLAIM_NO_GUARANTEE");
    expect(adjudicate(claim({ claimantUsdot: "2751903" }), ctx())!.reasonCode).toBe("CLAIM_NOT_BENEFICIARY");
    expect(adjudicate(claim(), ctx({ guarantee: { ...guarantee, status: "RELEASED", releaseReason: "claim window closed" } }))!.reasonCode).toBe("CLAIM_GUARANTEE_RELEASED");
    expect(adjudicate(claim({ peril: "NON_PERFORMANCE" }), ctx())!.reasonCode).toBe("CLAIM_PERIL_NOT_IN_SCOPE");
    expect(adjudicate(claim(), ctx({ now: new Date("2026-12-24T12:00:00Z") }))!.reasonCode).toBe("CLAIM_WINDOW_CLOSED");
    expect(adjudicate(claim(), ctx({ now: new Date("2026-12-23T16:00:00Z") }))!.covered).toBe(true); // the window's last hour
    const overrode = adjudicate(claim(), ctx({ commitment: { ...commitment, voidedAt: "2026-09-23T10:00:00Z" } }))!;
    expect(overrode.reasonCode).toBe("PRINCIPAL_OVERRODE_REFUSAL");
    expect(overrode.basis.at(-1)).toMatch(/pickup recorded after the commitment was voided/);
    // a void AFTER pickup is not the principal overriding anything
    expect(adjudicate(claim(), ctx({ commitment: { ...commitment, voidedAt: "2026-09-23T20:00:00Z" } }))!.covered).toBe(true);
  });
  it("a denied decision keeps the basis it built up to the failing rule", () => {
    const d = adjudicate(claim({ peril: "THEFT" }), ctx())!;
    expect(d.basis.slice(0, 2)).toEqual(["claimant is the beneficiary", "guarantee claimable"]);
    expect(d.payoutUsd).toBe(0);
  });
});

describe("reserve: premiums in, payouts out, over declared capital; never paid from nothing", () => {
  const setup = (initialCapitalUsd: number) => {
    const dir = tmp();
    const u = new UnderwritingEngine(dir, { ...DEFAULT_PARAMS, initialCapitalUsd });
    const inputs = { usdot: "2751903", authorityAgeDays: 3000, safetyRating: "SATISFACTORY" as const, powerUnits: 42, bipdUsd: 1_000_000, requiredBipdUsd: 1_000_000, vettingFlags: [], credentialAgeDays: 10, registrySnapshotChangedSinceIssuance: false, history: u.historyFor("2751903"), amountUsd: 2215 };
    const q = u.quote(inputs, "3312874", "2026-09-23");
    if (q.decision !== "GUARANTEED") throw new Error("expected a guarantee");
    const g = u.attach({ guaranteeId: q.guarantee.guaranteeId, counterpartyUsdot: "2751903", beneficiaryUsdot: "3312874", coveredAmountUsd: 2215, premiumUsd: q.guarantee.premiumUsd, day: "2026-09-23" }, "cmt_1");
    return { dir, u, g, premium: q.guarantee.premiumUsd };
  };
  const file = (u: UnderwritingEngine, guaranteeId: string, over: Partial<{ claimantUsdot: string; peril: string; amountUsd: number }> = {}, now = NOW) =>
    u.fileClaim({ guaranteeId, commitmentId: "cmt_1", claimantUsdot: "3312874", peril: "IDENTITY_FRAUD", amountUsd: 5000, evidence: {}, ...over }, commitment, now);

  it("earns the premium at attach; completion makes the guarantee CLAIMABLE and counts toward history", () => {
    const { u, g, premium } = setup(250_000);
    expect(u.reserveView().premiumsUsd).toBeCloseTo(premium);
    expect(g.status).toBe("ATTACHED");
    const c = u.complete(g.guaranteeId, "2026-09-24T17:00:00Z", NOW)!;
    expect(c.status).toBe("CLAIMABLE");
    expect(c.claimWindowEndsAt).toBe("2026-12-23T17:00:00.000Z");
    expect(u.historyFor("2751903").loadsCompleted).toBe(1);
    expect(u.reserveView().exposureUsd).toBe(2215); // still on the books until the window closes
    expect(u.complete(g.guaranteeId, "2026-09-24T17:00:00Z", NOW)!.completedAt).toBe(c.completedAt); // idempotent
  });
  it("pays a covered claim from the reserve, releases the guarantee, and counts the paid claim", () => {
    const { u, g, premium } = setup(250_000);
    u.complete(g.guaranteeId, "2026-09-24T17:00:00Z", NOW);
    const c = file(u, g.guaranteeId);
    expect(c.status).toBe("PAID");
    expect(c.paidAt).toBe(NOW.toISOString());
    const r = u.reserveView();
    expect(r.payoutsUsd).toBe(2215);
    expect(r.availableUsd).toBeCloseTo(250_000 + premium - 2215);
    expect(r.exposureUsd).toBe(0);
    expect(u.allGuarantees()[0]!.status).toBe("RELEASED");
    expect(u.historyFor("2751903").claimsPaid).toBe(1);
    // a second claim on the released guarantee is denied by rule
    expect(file(u, g.guaranteeId).decision!.reasonCode).toBe("CLAIM_GUARANTEE_RELEASED");
  });
  it("DEFERS when the reserve cannot pay, and settles when capital arrives", () => {
    const { u, g } = setup(100);
    u.complete(g.guaranteeId, "2026-09-24T17:00:00Z", NOW);
    const c = file(u, g.guaranteeId);
    expect(c.status).toBe("DEFERRED");
    expect(c.decision!.covered).toBe(true);
    expect(u.reserveView().payoutsUsd).toBe(0);
    expect(u.allGuarantees()[0]!.status).toBe("CLAIMABLE");
    expect(u.settleDeferred(NOW)).toEqual([]); // nothing changed, nothing paid
    u.addCapital(10_000);
    const paid = u.settleDeferred(new Date("2026-09-26T12:00:00Z"));
    expect(paid.map((x) => x.claimId)).toEqual([c.claimId]);
    expect(u.claim(c.claimId)!.status).toBe("PAID");
    expect(u.reserveView().payoutsUsd).toBe(2215);
    expect(u.allGuarantees()[0]!.status).toBe("RELEASED");
  });
  it("a closed claim window releases the guarantee — unless a claim is still open on it", () => {
    const { u, g } = setup(100);
    u.complete(g.guaranteeId, "2026-09-24T17:00:00Z", NOW);
    expect(u.expireClaimWindows(new Date("2026-12-23T16:59:59Z"))).toEqual([]);
    file(u, g.guaranteeId); // DEFERRED: the reserve is short
    expect(u.expireClaimWindows(new Date("2027-01-01T00:00:00Z"))).toEqual([]); // held open by the deferred claim
    u.addCapital(10_000);
    u.settleDeferred();
    expect(u.allGuarantees()[0]!.status).toBe("RELEASED"); // paid → released
    const { u: u2, g: g2 } = setup(250_000);
    u2.complete(g2.guaranteeId, "2026-09-24T17:00:00Z", NOW);
    const expired = u2.expireClaimWindows(new Date("2027-01-01T00:00:00Z"));
    expect(expired.map((x) => x.guaranteeId)).toEqual([g2.guaranteeId]);
    expect(u2.allGuarantees()[0]!.releaseReason).toBe("claim window closed");
    expect(u2.reserveView().exposureUsd).toBe(0);
  });
  it("ops can override the rules with a reason on the record; the payout is still capped", () => {
    const { u, g } = setup(250_000);
    u.complete(g.guaranteeId, "2026-09-24T17:00:00Z", NOW);
    const denied = file(u, g.guaranteeId, { peril: "NON_PERFORMANCE" });
    expect(denied.status).toBe("DENIED");
    const over = u.decideClaim(denied.claimId, { covered: true, why: "carrier admitted the load was re-brokered through the venue", payoutUsd: 9999 }, NOW)!;
    expect(over.status).toBe("PAID");
    expect(over.decision!.decidedBy).toBe("ops");
    expect(over.decision!.payoutUsd).toBe(2215);
    expect(over.decision!.basis).toEqual(["ops: carrier admitted the load was re-brokered through the venue"]);
    // a paid claim cannot be re-decided
    expect(u.decideClaim(denied.claimId, { covered: false, why: "changed my mind" })!.status).toBe("PAID");
  });
  it("claims and the reserve survive a restart", () => {
    const { dir, u, g } = setup(100);
    u.complete(g.guaranteeId, "2026-09-24T17:00:00Z", NOW);
    const c = file(u, g.guaranteeId);
    const u2 = new UnderwritingEngine(dir);
    expect(u2.claim(c.claimId)!.status).toBe("DEFERRED");
    expect(u2.reserveView().initialCapitalUsd).toBe(100);
    expect(reserveAvailable(u2.reserveView())).toBeCloseTo(u.reserveView().availableUsd);
    u2.addCapital(5000);
    expect(u2.settleDeferred()).toHaveLength(1);
    expect(new UnderwritingEngine(dir).claim(c.claimId)!.status).toBe("PAID");
  });
});
