import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, TEMPLATES } from "../src/mandate/cli";
import { validateLimits, describeLimits } from "../src/mandate/validate";
import { verifyMandate, verifyEnvelope } from "../src/mandate/sign";
import type { Mandate } from "../src/mandate/types";
import type { MandateEnvelope } from "../src/protocol/types";

const run = (argv: string[], now?: Date) => { const lines: string[] = []; const code = main(argv, (l) => lines.push(l), now); return { code, text: lines.join("\n") }; };
const tmp = () => mkdtempSync(join(tmpdir(), "mandate-cli-"));

describe("validateLimits: a mandate a principal could have meant", () => {
  it("accepts both templates and every fixture-shaped mandate", () => {
    expect(validateLimits(TEMPLATES.broker)).toEqual([]);
    expect(validateLimits(TEMPLATES.carrier)).toEqual([]);
  });
  it("names each incoherence", () => {
    const p = validateLimits({ ...TEMPLATES.broker, minRatePerLoadUsd: 5000, allowedLaneRegions: ["TX", "Texas"], allowedEquipment: ["VAN", "TANKER"], maxDailyExposureUsd: 3000, paymentTermsDays: { min: 30, max: 10 }, maxNegotiationRounds: 0, bonus: true });
    expect(p).toEqual(expect.arrayContaining([
      expect.stringMatching(/minRatePerLoadUsd \(5000\) is above maxRatePerLoadUsd \(3200\)/),
      expect.stringMatching(/"Texas" is not a USPS state code/),
      expect.stringMatching(/"TANKER" is not one of/),
      expect.stringMatching(/maxRatePerLoadUsd \(3200\) is above maxDailyExposureUsd \(3000\)/),
      expect.stringMatching(/paymentTermsDays must satisfy/),
      expect.stringMatching(/maxNegotiationRounds must be an integer/),
      expect.stringMatching(/unknown limit "bonus"/),
    ]));
    expect(validateLimits({ ...TEMPLATES.carrier, minRatePerLoadUsd: undefined, minRatePerMileUsd: undefined })).toContain("no rate bound at all: set a per-load or per-mile ceiling or floor");
    expect(validateLimits({ ...TEMPLATES.broker, maxRatePerLoadUsd: 20_000 })).toEqual([expect.stringMatching(/above maxPerCounterpartyExposureUsd \(12000\)/)]);
    expect(validateLimits({ ...TEMPLATES.carrier, maxPerCounterpartyExposureUsd: 20_000, maxDailyExposureUsd: 15_000 })).toEqual([]); // exposure accumulates across days
    expect(validateLimits("nope")).toEqual(["limits must be an object"]);
  });
  it("describes the limits in plain language", () => {
    const d = describeLimits(TEMPLATES.broker);
    expect(d).toContain("rate per load: no less than $900 and no more than $3,200");
    expect(d).toContain("counterparty must carry $1,000,000 insurance, with its insurer's signed attestation");
    expect(d).toContain("may tender loads (act as a broker)");
    expect(describeLimits(TEMPLATES.carrier)).toContain("may not tender loads");
  });
});

describe("mandate cli: keygen → issue → show/verify", () => {
  it("issues a mandate and envelope the agent runtime would accept, and keeps the private key out of them", () => {
    const dir = tmp();
    const key = join(dir, "principal.key.json");
    const kg = run(["keygen", "--out", key]);
    expect(kg.code).toBe(0);
    expect(existsSync(key)).toBe(true);
    expect(existsSync(join(dir, "principal.pub.json"))).toBe(true);
    expect(run(["keygen", "--out", key]).code).toBe(2); // refuses to overwrite without --force
    const limits = join(dir, "limits.json");
    writeFileSync(limits, run(["template", "--role", "broker"]).text);
    const disclose = join(dir, "disclose.json");
    writeFileSync(disclose, JSON.stringify({ maxRatePerLoadUsd: 3500 })); // the venue sees a coarser ceiling
    const now = new Date("2026-09-21T12:00:00Z");
    const is = run(["issue", "--key", key, "--principal", "Northline Logistics — VP Operations", "--agent", "northline-broker-agent", "--limits", limits, "--disclose", disclose, "--days", "14", "--out-dir", dir], now);
    expect(is.code).toBe(0);
    expect(is.text).toMatch(/valid 2026-09-21 → 2026-10-05/);
    expect(is.text).toMatch(/kept private from the venue: .*maxRatePerMileUsd.*mayTender/);
    const m = JSON.parse(readFileSync(join(dir, "mandate.json"), "utf8")) as Mandate;
    const e = JSON.parse(readFileSync(join(dir, "envelope.json"), "utf8")) as MandateEnvelope;
    expect(verifyMandate(m, now).ok).toBe(true);
    expect(verifyEnvelope(e, now).ok).toBe(true);
    expect(m.principal.publicKey.kid).toBe(JSON.parse(readFileSync(join(dir, "principal.pub.json"), "utf8")).kid);
    expect(JSON.stringify(m)).not.toContain('"d"'); // no private scalar anywhere in what the agent gets
    expect(JSON.stringify(e)).not.toContain('"d"');
    expect(e.limits.maxRatePerLoadUsd).toBe(3500);
    expect(m.limits.maxRatePerLoadUsd).toBe(3200);
    // show + verify
    const sh = run(["show", join(dir, "mandate.json"), "--envelope", join(dir, "envelope.json")], now);
    expect(sh.code).toBe(0);
    expect(sh.text).toMatch(/signature valid/);
    expect(sh.text).toMatch(/envelope discloses maxRatePerLoadUsd=3500 while the mandate holds 3200/);
    expect(sh.text).not.toMatch(/TIGHTER/);
    expect(run(["verify", join(dir, "mandate.json"), "--principal-public", join(dir, "principal.pub.json")], now).code).toBe(0);
    // expired, or a different principal pinned
    expect(run(["verify", join(dir, "mandate.json")], new Date("2026-11-01T00:00:00Z")).text).toMatch(/NOT VALID: mandate expired/);
    run(["keygen", "--out", join(dir, "other.key.json")]);
    expect(run(["verify", join(dir, "mandate.json"), "--principal-public", join(dir, "other.pub.json")], now).text).toMatch(/not the pinned principal/);
    // a tampered mandate
    writeFileSync(join(dir, "mandate.json"), JSON.stringify({ ...m, limits: { ...m.limits, maxRatePerLoadUsd: 9000 } }));
    expect(run(["verify", join(dir, "mandate.json")], now).code).toBe(1);
  });
  it("refuses to sign incoherent limits and says why; warns when the envelope is tighter than the mandate", () => {
    const dir = tmp();
    const key = join(dir, "p.key.json");
    run(["keygen", "--out", key]);
    const limits = join(dir, "limits.json");
    writeFileSync(limits, JSON.stringify({ ...TEMPLATES.carrier, allowedEquipment: [] }));
    const r = run(["issue", "--key", key, "--principal", "X", "--agent", "a", "--limits", limits, "--out-dir", dir]);
    expect(r.code).toBe(2);
    expect(r.text).toMatch(/refusing to issue: 1 problem/);
    expect(r.text).toMatch(/allowedEquipment is required/);
    expect(existsSync(join(dir, "mandate.json"))).toBe(false);
    writeFileSync(limits, JSON.stringify(TEMPLATES.broker));
    writeFileSync(join(dir, "d.json"), JSON.stringify({ maxRatePerLoadUsd: 2000 }));
    expect(run(["issue", "--key", key, "--principal", "X", "--agent", "a", "--limits", limits, "--disclose", join(dir, "d.json"), "--out-dir", dir]).code).toBe(0);
    expect(run(["show", join(dir, "mandate.json"), "--envelope", join(dir, "envelope.json")]).text).toMatch(/TIGHTER than the mandate/);
    expect(run(["issue", "--key", key, "--agent", "a", "--limits", limits]).text).toMatch(/--principal is required/);
    expect(run([]).code).toBe(2);
  });
});
