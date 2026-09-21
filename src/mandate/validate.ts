/**
 * Is this a mandate a principal could have meant? Signatures prove who said
 * it; this checks that what was said is coherent — the ceiling above the
 * floor, the equipment real, the lane codes states, the exposure caps
 * positive — so an agent never starts on limits that cannot be evaluated
 * and a principal is told at issue time, not at the first refused load.
 */
import type { MandateLimits } from "./types";

const EQUIPMENT = ["VAN", "REEFER", "FLATBED", "STEP_DECK", "POWER_ONLY"];
const STATES = "AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY".split(" ");

export function validateLimits(l: unknown): string[] {
  const p: string[] = [];
  if (!l || typeof l !== "object") return ["limits must be an object"];
  const x = l as Record<string, unknown>;
  const money = (k: string, required = false) => {
    const v = x[k];
    if (v === undefined) { if (required) p.push(`${k} is required`); return undefined; }
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0) { p.push(`${k} must be a non-negative number`); return undefined; }
    return v;
  };
  const bool = (k: string, required = false) => {
    const v = x[k];
    if (v === undefined) { if (required) p.push(`${k} is required (true or false)`); return; }
    if (typeof v !== "boolean") p.push(`${k} must be true or false`);
  };
  const minLoad = money("minRatePerLoadUsd"), maxLoad = money("maxRatePerLoadUsd");
  const minMile = money("minRatePerMileUsd"), maxMile = money("maxRatePerMileUsd");
  if (minLoad !== undefined && maxLoad !== undefined && minLoad > maxLoad) p.push(`minRatePerLoadUsd (${minLoad}) is above maxRatePerLoadUsd (${maxLoad})`);
  if (minMile !== undefined && maxMile !== undefined && minMile > maxMile) p.push(`minRatePerMileUsd (${minMile}) is above maxRatePerMileUsd (${maxMile})`);
  if (minLoad === undefined && maxLoad === undefined && minMile === undefined && maxMile === undefined) p.push("no rate bound at all: set a per-load or per-mile ceiling or floor");
  const lanes = x.allowedLaneRegions;
  if (lanes !== undefined) {
    if (!Array.isArray(lanes) || !lanes.every((s) => typeof s === "string")) p.push("allowedLaneRegions must be a list of USPS state codes");
    else for (const s of lanes) if (!STATES.includes(s)) p.push(`allowedLaneRegions: "${s}" is not a USPS state code`);
  }
  const eq = x.allowedEquipment;
  if (!Array.isArray(eq) || !eq.length) p.push("allowedEquipment is required and must list at least one type");
  else for (const e of eq) if (!EQUIPMENT.includes(String(e))) p.push(`allowedEquipment: "${e}" is not one of ${EQUIPMENT.join(", ")}`);
  bool("hazmatPermitted", true);
  money("requiredCounterpartyInsuranceUsd", true);
  const perCp = money("maxPerCounterpartyExposureUsd", true), daily = money("maxDailyExposureUsd", true);
  // per-counterparty exposure accumulates across days, so it may legitimately exceed the daily cap; but a rate ceiling above either cap is a ceiling that can never be reached
  if (maxLoad !== undefined && perCp !== undefined && maxLoad > perCp) p.push(`maxRatePerLoadUsd (${maxLoad}) is above maxPerCounterpartyExposureUsd (${perCp}); loads priced above the cap could never be committed, so the ceiling is not the ceiling`);
  if (maxLoad !== undefined && daily !== undefined && maxLoad > daily) p.push(`maxRatePerLoadUsd (${maxLoad}) is above maxDailyExposureUsd (${daily}); loads priced above the cap could never be committed, so the ceiling is not the ceiling`);
  bool("requireGuarantee", true);
  bool("requireInsurerAttestation");
  bool("requireInsurerUndertaking");
  bool("mayTender", true);
  const rounds = x.maxNegotiationRounds;
  if (typeof rounds !== "number" || !Number.isInteger(rounds) || rounds < 1 || rounds > 100) p.push("maxNegotiationRounds must be an integer from 1 to 100");
  const terms = x.paymentTermsDays as { min?: unknown; max?: unknown } | undefined;
  if (!terms || typeof terms !== "object" || typeof terms.min !== "number" || typeof terms.max !== "number") p.push("paymentTermsDays must be { min, max } in days");
  else if (terms.min < 0 || terms.max < terms.min || terms.max > 365) p.push(`paymentTermsDays must satisfy 0 <= min <= max <= 365 (got ${terms.min}..${terms.max})`);
  const known = new Set(["minRatePerLoadUsd", "maxRatePerLoadUsd", "minRatePerMileUsd", "maxRatePerMileUsd", "allowedLaneRegions", "allowedEquipment", "hazmatPermitted", "requiredCounterpartyInsuranceUsd", "maxPerCounterpartyExposureUsd", "maxDailyExposureUsd", "requireGuarantee", "requireInsurerAttestation", "requireInsurerUndertaking", "mayTender", "maxNegotiationRounds", "paymentTermsDays"]);
  for (const k of Object.keys(x)) if (!known.has(k)) p.push(`unknown limit "${k}" — the engine would ignore it, which is never what a principal means`);
  return p;
}

/** Plain-language rendering of what a mandate lets the agent do — what a principal reads before signing. */
export function describeLimits(l: MandateLimits): string[] {
  const out: string[] = [];
  const usd = (n: number) => `$${n.toLocaleString("en-US")}`;
  const rate = [l.minRatePerLoadUsd !== undefined ? `no less than ${usd(l.minRatePerLoadUsd)}` : "", l.maxRatePerLoadUsd !== undefined ? `no more than ${usd(l.maxRatePerLoadUsd)}` : ""].filter(Boolean).join(" and ");
  const mile = [l.minRatePerMileUsd !== undefined ? `at least $${l.minRatePerMileUsd.toFixed(2)}/mi` : "", l.maxRatePerMileUsd !== undefined ? `at most $${l.maxRatePerMileUsd.toFixed(2)}/mi` : ""].filter(Boolean).join(" and ");
  if (rate) out.push(`rate per load: ${rate}`);
  if (mile) out.push(`rate per mile: ${mile}`);
  out.push(`equipment: ${l.allowedEquipment.join(", ")}${l.hazmatPermitted ? " (hazmat permitted)" : " (no hazmat)"}`);
  out.push(l.allowedLaneRegions?.length ? `lanes: both ends in ${l.allowedLaneRegions.join(", ")}` : "lanes: anywhere");
  out.push(`counterparty must carry ${usd(l.requiredCounterpartyInsuranceUsd)} insurance${l.requireInsurerUndertaking ? ", with its insurer's signed undertaking" : l.requireInsurerAttestation ? ", with its insurer's signed attestation" : ""}`);
  out.push(`exposure: at most ${usd(l.maxPerCounterpartyExposureUsd)} open with any one counterparty, ${usd(l.maxDailyExposureUsd)} committed per day`);
  out.push(l.requireGuarantee ? "commits only when the venue guarantee attaches" : "may commit unguaranteed");
  out.push(l.mayTender ? "may tender loads (act as a broker)" : "may not tender loads");
  out.push(`negotiates at most ${l.maxNegotiationRounds} rounds; payment terms ${l.paymentTermsDays.min}–${l.paymentTermsDays.max} days`);
  return out;
}
