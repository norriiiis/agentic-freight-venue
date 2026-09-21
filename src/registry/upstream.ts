/**
 * Upstream sources a registry mirror syncs from. The mock file store is one;
 * FMCSA's public data is the real one, in two parts that do not come from
 * the same place:
 *
 *   QCMobile (mobile.fmcsa.dot.gov/qc/services, needs a webKey): carrier
 *   identity, operating status, authority status, safety rating, fleet, and
 *   insurance ON FILE as amounts — not the filings themselves.
 *
 *   Licensing & Insurance (li-public.fmcsa.dot.gov): the insurance history —
 *   form, type, insurer, policy number, coverage, effective and cancellation
 *   dates, and the date each filing was posted. There is no public API; the
 *   vetting providers that mirror it export the table. `mapLiInsuranceRows`
 *   takes those rows.
 *
 * A mirror's `upstreamAsOf` is the time its last sync SUCCEEDED — the claim
 * every accountability check is built on — so an adapter that failed to
 * reach the upstream must not advance it.
 */
import type { InsuranceFiling, RegistryRecord } from "../protocol/registry";
import type { MockRegistry } from "./store";

export interface UpstreamSource {
  id: string;
  /** One entity's public record as the upstream shows it now; `null` for not found. Throws if the upstream cannot be reached. */
  record(usdot: string): Promise<RegistryRecord | null>;
}

/** The mock store as an upstream (the simulator's FMCSA). */
export class FileUpstream implements UpstreamSource {
  readonly id = "file";
  constructor(private readonly store: MockRegistry) {}
  async record(usdot: string): Promise<RegistryRecord | null> {
    return this.store.publicRecord(usdot);
  }
}

// ------------------------------------------------------------------ QCMobile

/** The fields of a QCMobile carrier object this adapter reads (others are ignored). */
export interface QcCarrier {
  dotNumber: number | string;
  legalName: string;
  dbaName?: string | null;
  allowedToOperate?: "Y" | "N";
  statusCode?: string;
  oosDate?: string | null;
  commonAuthorityStatus?: "A" | "I" | "N" | string;
  contractAuthorityStatus?: string;
  brokerAuthorityStatus?: string;
  bipdInsuranceOnFile?: string | number | null;
  bipdInsuranceRequired?: "Y" | "N" | "u";
  bipdRequiredAmount?: string | number | null;
  bondInsuranceOnFile?: string | number | null;
  cargoInsuranceOnFile?: string | number | null;
  phyStreet?: string;
  phyCity?: string;
  phyState?: string;
  phyZipcode?: string;
  phone?: string;
  safetyRating?: "S" | "C" | "U" | "N" | string | null;
  totalDrivers?: number;
  totalPowerUnits?: number;
  carrierOperation?: { carrierOperationCode?: string; carrierOperationDesc?: string };
  snapshotDate?: string;
  mcs150Outdated?: "Y" | "N";
}
export interface QcAuthorityRow {
  carrierAuthority?: { authority?: string; docketNumber?: string; commonAuthorityStatus?: string; contractAuthorityStatus?: string; brokerAuthorityStatus?: string; applicantID?: string };
}

const usd = (v: string | number | null | undefined) => (v === null || v === undefined || v === "" ? 0 : Number(v) * 1000);
const rating = (r: QcCarrier["safetyRating"]): RegistryRecord["safetyRating"] => (r === "S" ? "SATISFACTORY" : r === "C" ? "CONDITIONAL" : r === "U" ? "UNSATISFACTORY" : "NONE");

/**
 * QCMobile → RegistryRecord. Authority and status are authoritative here;
 * insurance is a SUMMARY (amounts on file, no policy numbers, no filer) and
 * is marked as such — a record built from QCMobile alone cannot say who the
 * insurer of record is. Merge with `mapLiInsuranceRows` for the filings.
 */
export function mapQcMobileCarrier(c: QcCarrier, authority: QcAuthorityRow[] = [], snapshotDate = c.snapshotDate ?? new Date().toISOString().slice(0, 10)): RegistryRecord {
  const auths: RegistryRecord["authorities"] = [];
  const st = (s: string | undefined): RegistryRecord["authorities"][number]["status"] => (s === "A" ? "ACTIVE" : s === "I" ? "INACTIVE" : s === "N" ? "INACTIVE" : "PENDING");
  const mc = authority.map((a) => a.carrierAuthority?.docketNumber).find((d) => d && /^MC/i.test(d));
  if (c.commonAuthorityStatus) auths.push({ type: "COMMON", status: st(c.commonAuthorityStatus), grantDate: snapshotDate });
  if (c.contractAuthorityStatus) auths.push({ type: "CONTRACT", status: st(c.contractAuthorityStatus), grantDate: snapshotDate });
  if (c.brokerAuthorityStatus) auths.push({ type: "BROKER", status: st(c.brokerAuthorityStatus), grantDate: snapshotDate });
  const hasBroker = auths.some((a) => a.type === "BROKER" && a.status === "ACTIVE");
  const hasCarrier = auths.some((a) => a.type !== "BROKER" && a.status === "ACTIVE");
  const insurance: InsuranceFiling[] = [];
  const summary = (type: InsuranceFiling["type"], form: InsuranceFiling["form"], amount: number) => amount > 0 && insurance.push({ type, form, insurer: "(summary: see L&I insurance history)", policyNumber: `QCMOBILE-SUMMARY-${type}`, coverageFromUsd: 0, coverageToUsd: amount, effectiveDate: snapshotDate });
  summary("BIPD", "BMC-91X", usd(c.bipdInsuranceOnFile));
  summary("CARGO", "BMC-34", usd(c.cargoInsuranceOnFile));
  summary("BOND", "BMC-84", usd(c.bondInsuranceOnFile));
  return {
    usdot: String(c.dotNumber),
    mc: mc ? mc.toUpperCase().replace(/^MC-?/, "MC-") : undefined,
    legalName: c.legalName,
    dbaName: c.dbaName ?? undefined,
    entityType: hasBroker && hasCarrier ? "CARRIER_BROKER" : hasBroker ? "BROKER" : "CARRIER",
    operatingStatus: c.oosDate ? "OUT_OF_SERVICE" : c.allowedToOperate === "Y" ? "AUTHORIZED" : "NOT_AUTHORIZED",
    outOfServiceDate: c.oosDate ?? undefined,
    physicalAddress: { street: c.phyStreet ?? "", city: c.phyCity ?? "", state: c.phyState ?? "", zip: c.phyZipcode ?? "" },
    phone: c.phone ?? "",
    email: "",
    authorities: auths,
    insurance,
    safetyRating: rating(c.safetyRating),
    powerUnits: c.totalPowerUnits ?? 0,
    drivers: c.totalDrivers ?? 0,
    mcs150Date: snapshotDate,
    carrierOperation: c.carrierOperation?.carrierOperationCode === "B" ? "INTRASTATE" : "INTERSTATE",
    cargoCarried: [],
  };
}

// ------------------------------------------------------------ L&I filings

/** One row of the L&I "Insurance History" table, as vetting providers export it. Dates as MM/DD/YYYY or ISO. */
export interface LiInsuranceRow {
  form: string;            // "91X", "34", "84", "85", "91"
  type: string;            // "BIPD/Primary", "Cargo", "Bond", "Trust Fund"
  insuranceCarrier: string;
  policySurety: string;
  postedDate?: string;     // when FMCSA posted the filing
  coverageFrom?: string | number;
  coverageTo?: string | number;
  effectiveDate: string;
  cancellationDate?: string;
  /** Vetting providers that track the notice separately: when the insurer's cancellation notice was dated. */
  cancellationNoticeDate?: string;
  /** The filer account, when the export carries it. */
  filerId?: string;
}

const iso = (d: string | undefined): string | undefined => {
  if (!d) return undefined;
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(d.trim());
  return m ? `${m[3]}-${m[1]!.padStart(2, "0")}-${m[2]!.padStart(2, "0")}` : d.slice(0, 10);
};
const money = (v: string | number | undefined) => (v === undefined || v === "" ? 0 : Number(String(v).replace(/[$,]/g, "")) * (String(v).includes(",") || Number(v) > 100_000 ? 1 : 1000));

export function mapLiInsuranceRows(rows: LiInsuranceRow[]): InsuranceFiling[] {
  return rows.map((r) => {
    const t = r.type.toUpperCase();
    const type: InsuranceFiling["type"] = t.startsWith("BIPD") ? "BIPD" : t.startsWith("CARGO") ? "CARGO" : t.startsWith("TRUST") ? "TRUST_FUND" : "BOND";
    const f = r.form.toUpperCase().replace(/^BMC-?/, "");
    const form: InsuranceFiling["form"] = f === "91X" ? "BMC-91X" : f === "91" ? "BMC-91" : f === "34" ? "BMC-34" : f === "85" ? "BMC-85" : "BMC-84";
    const cancellation = iso(r.cancellationDate);
    return {
      type,
      form,
      insurer: r.insuranceCarrier.trim(),
      filerId: r.filerId,
      policyNumber: r.policySurety.trim(),
      coverageFromUsd: money(r.coverageFrom),
      coverageToUsd: money(r.coverageTo),
      effectiveDate: iso(r.effectiveDate)!,
      cancellationDate: cancellation,
      cancellationFiledDate: cancellation ? iso(r.cancellationNoticeDate) ?? iso(r.postedDate) : undefined,
      cancellationReceivedDate: cancellation ? iso(r.postedDate) : undefined,
    };
  });
}

/** Merge: QCMobile's identity/authority/status with L&I's filings, when both are available. */
export function mergeQcAndLi(qc: RegistryRecord, li: InsuranceFiling[]): RegistryRecord {
  return li.length ? { ...qc, insurance: li } : qc;
}

/**
 * The real thing, minus the parts nobody publishes as an API. Needs an
 * FMCSA webKey (free registration). `liRows` is a hook for whatever exports
 * the L&I history — without it the record's insurance is a summary and the
 * insurer-of-record checks will refuse it, which is the honest result.
 */
export class QcMobileUpstream implements UpstreamSource {
  readonly id = "fmcsa-qcmobile";
  constructor(private readonly webKey: string, private readonly baseUrl = "https://mobile.fmcsa.dot.gov/qc/services", private readonly liRows?: (usdot: string) => Promise<LiInsuranceRow[]>, private readonly fetchImpl: typeof fetch = fetch) {}
  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}${path.includes("?") ? "&" : "?"}webKey=${encodeURIComponent(this.webKey)}`);
    if (res.status === 404) return { content: null } as T;
    if (!res.ok) throw new Error(`QCMobile ${path}: HTTP ${res.status}`);
    return (await res.json()) as T;
  }
  async record(usdot: string): Promise<RegistryRecord | null> {
    const c = await this.get<{ content: { carrier: QcCarrier } | null }>(`/carriers/${encodeURIComponent(usdot)}`);
    if (!c.content?.carrier) return null;
    const a = await this.get<{ content: QcAuthorityRow[] | null }>(`/carriers/${encodeURIComponent(usdot)}/authority`).catch(() => ({ content: null }));
    const rec = mapQcMobileCarrier(c.content.carrier, a.content ?? []);
    const li = this.liRows ? await this.liRows(usdot).catch(() => []) : [];
    return mergeQcAndLi(rec, mapLiInsuranceRows(li));
  }
}
