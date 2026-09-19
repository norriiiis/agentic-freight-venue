/**
 * Mock of the public carrier registry (FMCSA Licensing & Insurance + SAFER).
 *
 * The identity root of this system is NOT something the venue invents: it is
 * the USDOT/MC number and the insurance filings that carriers and brokers are
 * legally required to keep on public record. The venue *binds* an agent key to
 * that public identity; it does not mint identity.
 *
 * STUB: in production this reads FMCSA's L&I / QCMobile APIs (or a vetting
 * provider's normalized feed). Here it is a JSON file with the same shape.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { hashObject } from "../protocol/canonical";
import type { EntityType } from "../protocol/types";

export type FilingType = "BIPD" | "CARGO" | "BOND" | "TRUST_FUND";
export type FilingForm = "BMC-91" | "BMC-91X" | "BMC-34" | "BMC-84" | "BMC-85";

export interface InsuranceFiling {
  type: FilingType;
  form: FilingForm;
  insurer: string;
  policyNumber: string;
  coverageFromUsd: number;
  coverageToUsd: number;
  effectiveDate: string;      // ISO date
  cancellationDate?: string;  // ISO date; insurer-filed cancellation, effective on this date
}

export interface AuthorityRecord {
  type: "COMMON" | "CONTRACT" | "BROKER";
  status: "ACTIVE" | "INACTIVE" | "PENDING" | "REVOKED";
  grantDate: string;
  revokedDate?: string;
}

export interface RegistryRecord {
  usdot: string;
  mc?: string;
  legalName: string;
  dbaName?: string;
  entityType: EntityType;
  operatingStatus: "AUTHORIZED" | "NOT_AUTHORIZED" | "OUT_OF_SERVICE";
  outOfServiceDate?: string;
  physicalAddress: { street: string; city: string; state: string; zip: string };
  phone: string;
  email: string; // FMCSA-registered contact; proof-of-control anchor
  authorities: AuthorityRecord[];
  insurance: InsuranceFiling[];
  safetyRating: "SATISFACTORY" | "CONDITIONAL" | "UNSATISFACTORY" | "NONE";
  powerUnits: number;
  drivers: number;
  mcs150Date: string;
  carrierOperation: "INTERSTATE" | "INTRASTATE";
  cargoCarried: string[];
  /** STUB for proof-of-control: token the registry contact would receive by email. */
  _proofOfControlToken: string;
  /** STUB for vetting-provider signal (Highway / MyCarrierPortal / Carrier Assure would supply these). */
  _vettingFlags: string[];
}

/** Statutory minimums (49 CFR 387): general freight $750k BIPD; hazmat higher; broker bond $75k. */
export const STATUTORY_MIN = {
  BIPD_GENERAL_FREIGHT: 750_000,
  BIPD_HAZMAT: 1_000_000,
  BROKER_BOND: 75_000,
} as const;

export class MockRegistry {
  private records = new Map<string, RegistryRecord>();
  constructor(private readonly path: string) {
    this.reload();
  }
  reload() {
    const arr: RegistryRecord[] = JSON.parse(readFileSync(this.path, "utf8"));
    this.records = new Map(arr.map((r) => [r.usdot, r]));
  }
  persist() {
    writeFileSync(this.path, JSON.stringify([...this.records.values()], null, 2));
  }
  get(usdot: string): RegistryRecord | undefined {
    return this.records.get(usdot);
  }
  byMc(mc: string): RegistryRecord | undefined {
    return [...this.records.values()].find((r) => r.mc === mc);
  }
  all(): RegistryRecord[] {
    return [...this.records.values()];
  }
  snapshotHash(usdot: string): string {
    const r = this.records.get(usdot);
    if (!r) return "";
    const { _proofOfControlToken: _t, _vettingFlags: _f, ...pub } = r;
    return hashObject(pub);
  }
  /** SIM-ONLY mutation hooks (an insurer filing a cancellation, FMCSA revoking authority). */
  update(usdot: string, patch: Partial<RegistryRecord>) {
    const r = this.records.get(usdot);
    if (!r) throw new Error(`registry: ${usdot} not found`);
    this.records.set(usdot, { ...r, ...patch });
    this.persist();
  }
}

export interface InsuranceStatus {
  ok: boolean;
  reasonCode?: "INSURANCE_LAPSED" | "INSURANCE_BELOW_MINIMUM";
  bipdCoverageUsd: number;
  cargoCoverageUsd: number;
  bondUsd: number;
  activeFilings: InsuranceFiling[];
  lapsedFilings: InsuranceFiling[];
  asOf: string;
}

function filingActive(f: InsuranceFiling, asOf: Date): boolean {
  const eff = new Date(f.effectiveDate);
  if (eff > asOf) return false;
  if (f.cancellationDate && new Date(f.cancellationDate) <= asOf) return false;
  return true;
}

/** Evaluate an entity's insurance posture as of a moment in time. */
export function insuranceStatus(rec: RegistryRecord, asOf: Date, opts: { hazmat?: boolean; requiredBipdUsd?: number } = {}): InsuranceStatus {
  const active = rec.insurance.filter((f) => filingActive(f, asOf));
  const lapsed = rec.insurance.filter((f) => !filingActive(f, asOf));
  const sum = (t: FilingType) => active.filter((f) => f.type === t).reduce((a, f) => Math.max(a, f.coverageToUsd), 0);
  const bipd = sum("BIPD");
  const cargo = sum("CARGO");
  const bond = Math.max(sum("BOND"), sum("TRUST_FUND"));
  const base: InsuranceStatus = { ok: true, bipdCoverageUsd: bipd, cargoCoverageUsd: cargo, bondUsd: bond, activeFilings: active, lapsedFilings: lapsed, asOf: asOf.toISOString() };

  const isCarrier = rec.entityType === "CARRIER" || rec.entityType === "CARRIER_BROKER";
  const isBroker = rec.entityType === "BROKER" || rec.entityType === "CARRIER_BROKER";
  if (isCarrier) {
    const required = Math.max(opts.requiredBipdUsd ?? 0, opts.hazmat ? STATUTORY_MIN.BIPD_HAZMAT : STATUTORY_MIN.BIPD_GENERAL_FREIGHT);
    if (bipd === 0 && rec.insurance.some((f) => f.type === "BIPD")) return { ...base, ok: false, reasonCode: "INSURANCE_LAPSED" };
    if (bipd < required) return { ...base, ok: false, reasonCode: "INSURANCE_BELOW_MINIMUM" };
  }
  if (isBroker) {
    if (bond === 0 && rec.insurance.some((f) => f.type === "BOND" || f.type === "TRUST_FUND")) return { ...base, ok: false, reasonCode: "INSURANCE_LAPSED" };
    if (bond < STATUTORY_MIN.BROKER_BOND) return { ...base, ok: false, reasonCode: "INSURANCE_BELOW_MINIMUM" };
  }
  return base;
}

export function authorityActive(rec: RegistryRecord, asOf: Date): boolean {
  if (rec.operatingStatus !== "AUTHORIZED") return false;
  if (rec.outOfServiceDate && new Date(rec.outOfServiceDate) <= asOf) return false;
  return rec.authorities.some((a) => a.status === "ACTIVE" && new Date(a.grantDate) <= asOf && !(a.revokedDate && new Date(a.revokedDate) <= asOf));
}

export function hasBrokerAuthority(rec: RegistryRecord, asOf: Date): boolean {
  return rec.authorities.some((a) => a.type === "BROKER" && a.status === "ACTIVE" && new Date(a.grantDate) <= asOf);
}
