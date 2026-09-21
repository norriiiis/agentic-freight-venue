import { describe, it, expect } from "vitest";
import { mkdtempSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QcMobileUpstream, mapLiInsuranceRows, mapQcMobileCarrier, mergeQcAndLi } from "../src/registry/upstream";
import { RegistryService } from "../src/registry/service";
import { insurerOfRecord, standing, verifyAttestation } from "../src/protocol/registry";
import { generateKeyPair, signJws } from "../src/protocol/crypto";

const QC = { dotNumber: 2751903, legalName: "PRAIRIE WIND TRANSPORT INC", allowedToOperate: "Y" as const, statusCode: "A", commonAuthorityStatus: "A", contractAuthorityStatus: "A", brokerAuthorityStatus: "N", bipdInsuranceOnFile: "1000", bipdInsuranceRequired: "Y" as const, bipdRequiredAmount: "750", cargoInsuranceOnFile: "100", phyStreet: "1820 S Industrial Rd", phyCity: "Salina", phyState: "KS", phyZipcode: "67401", phone: "(785) 555-0193", safetyRating: "S", totalDrivers: 47, totalPowerUnits: 42, carrierOperation: { carrierOperationCode: "A", carrierOperationDesc: "Interstate" }, snapshotDate: "2026-09-20" };
const AUTH = [{ carrierAuthority: { authority: "COMMON", docketNumber: "MC-0938251", commonAuthorityStatus: "A" } }];
const LI = [
  { form: "91X", type: "BIPD/Primary", insuranceCarrier: "Great Plains Mutual Insurance Co", policySurety: "TRK-0092817-24", postedDate: "07/01/2025", coverageFrom: "$0", coverageTo: "$1,000,000", effectiveDate: "07/01/2025", filerId: "great-plains-mutual" },
  { form: "34", type: "Cargo", insuranceCarrier: "Great Plains Mutual Insurance Co", policySurety: "CGO-0092817-24", coverageFrom: 0, coverageTo: 100, effectiveDate: "2025-07-01" },
];

describe("upstream adapters: FMCSA's data, in the shapes it actually comes in", () => {
  it("QCMobile → record: identity, authority, status, safety; insurance only as a summary that cannot name the insurer of record", () => {
    const r = mapQcMobileCarrier(QC, AUTH);
    expect(r).toMatchObject({ usdot: "2751903", mc: "MC-0938251", entityType: "CARRIER", operatingStatus: "AUTHORIZED", safetyRating: "SATISFACTORY", powerUnits: 42 });
    expect(r.authorities.map((a) => `${a.type}:${a.status}`)).toEqual(["COMMON:ACTIVE", "CONTRACT:ACTIVE", "BROKER:INACTIVE"]);
    expect(r.insurance.find((f) => f.type === "BIPD")?.coverageToUsd).toBe(1_000_000);
    expect(standing(r, new Date("2026-09-21T00:00:00Z")).ok).toBe(true);
    // A COI presented against a summary-only record is not of record: the summary has no policy numbers.
    const coi = { schema: "freight-venue/insurer-attestation/v1" as const, insurerId: "great-plains-mutual", usdot: "2751903", policyNumber: "TRK-0092817-24", type: "BIPD" as const, form: "BMC-91X" as const, coverageToUsd: 1_000_000, effectiveDate: "2025-07-01", noticeDays: 30, asOf: "", kid: "", signature: "" };
    expect(insurerOfRecord(coi, [r]).ok).toBe(false);
    // Merged with L&I rows, it is.
    const merged = mergeQcAndLi(r, mapLiInsuranceRows(LI));
    expect(insurerOfRecord(coi, [merged]).ok).toBe(true);
    expect(merged.insurance[0]).toMatchObject({ form: "BMC-91X", insurer: "Great Plains Mutual Insurance Co", policyNumber: "TRK-0092817-24", coverageToUsd: 1_000_000, effectiveDate: "2025-07-01", filerId: "great-plains-mutual" });
    expect(merged.insurance[1]).toMatchObject({ type: "CARGO", coverageToUsd: 100_000 });
  });

  it("L&I rows: cancellation dates carry the notice date (the insurer's act) and the posted date (the registry's)", () => {
    const [f] = mapLiInsuranceRows([{ ...LI[0]!, cancellationDate: "10/20/2026", cancellationNoticeDate: "09/20/2026", postedDate: "09/21/2026" }]);
    expect(f).toMatchObject({ cancellationDate: "2026-10-20", cancellationFiledDate: "2026-09-20", cancellationReceivedDate: "2026-09-21" });
  });

  it("a mirror on a real upstream signs the time it last READ the upstream, and never advances it on a failed sync", async () => {
    const dir = mkdtempSync(join(tmpdir(), "fv-up-"));
    copyFileSync(join(import.meta.dirname, "../src/identity/fixtures/registry.json"), join(dir, "records.json"));
    let failNext = false;
    const fakeFetch: typeof fetch = async (url) => {
      if (failNext) return new Response("down", { status: 503 });
      const u = String(url);
      if (u.includes("/authority")) return Response.json({ content: AUTH });
      return Response.json({ content: { carrier: QC } });
    };
    const up = new QcMobileUpstream("k", "https://qc.example", async () => LI, fakeFetch);
    const svc = new RegistryService("fmcsa-qc", dir, join(dir, "records.json"), { upstream: up, syncMaxAgeMs: 50 });
    const t0 = new Date();
    const a1 = await svc.attest("2751903", t0);
    expect(verifyAttestation(a1, svc.kp.publicJwk)).toBe(true);
    expect(a1.upstreamAsOf).toBe(t0.toISOString());
    expect(a1.record?.insurance[0]?.policyNumber).toBe("TRK-0092817-24");
    // Upstream down after the cache expires: the mirror still answers, but its sync claim stays at the last real read.
    await new Promise((r) => setTimeout(r, 60));
    failNext = true;
    const t1 = new Date();
    const a2 = await svc.attest("2751903", t1);
    expect(a2.asOf).toBe(t1.toISOString());
    expect(a2.upstreamAsOf).toBe(t0.toISOString());
    expect(svc.status().syncFailures).toBe(1);
    void signJws; void generateKeyPair;
  });
});
