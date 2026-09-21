/**
 * The public carrier registry (FMCSA Licensing & Insurance + SAFER) as the
 * protocol sees it: record shapes, the standing evaluation every party runs
 * over a record, and the registry's SIGNED word about a record at a moment.
 *
 * The identity root of this system is NOT something the venue invents: it is
 * the USDOT/MC number and the insurance filings that carriers and brokers are
 * legally required to keep on public record. Insurers file cancellations with
 * the registry (BMC-35, 30 days ahead) — they are under no obligation to tell
 * a venue. So a venue that waits to be told will not be, and a verifier that
 * trusts "the venue checked" is trusting the venue.
 *
 * A RegistryAttestation fixes both: the registry (or, in production, a
 * vetting provider that mirrors it — FMCSA itself does not sign) signs the
 * record together with its own clock. The venue must hold a FRESH one for
 * both parties at commitment and embeds them in the artifact; the standing
 * question — "was this carrier insured when the deal was struck?" — is then
 * answerable from the registry's word alone, by anyone, with no cooperation
 * from the venue. The venue's evidence shows what it knew and when.
 */
import { hashObject } from "./canonical";
import { importPublicKey, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";
import type { ReasonCode } from "./reasons";
import type { EntityType } from "./types";

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

/** The public record. Everything here is what the registry publishes; nothing is the venue's. */
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
}

/**
 * What arrives out of band, never in an attestation: the token a proof-of-
 * control challenge to the registered contact would yield, and a vetting
 * provider's flags. STUBS — see registry/store.ts.
 */
export interface OutOfBand {
  _proofOfControlToken?: string;
  _vettingFlags?: string[];
}

/** Statutory minimums (49 CFR 387): general freight $750k BIPD; hazmat higher; broker bond $75k. */
export const STATUTORY_MIN = {
  BIPD_GENERAL_FREIGHT: 750_000,
  BIPD_HAZMAT: 1_000_000,
  BROKER_BOND: 75_000,
} as const;

/** The hash every party computes over a public record — the store, the attestation, and a credential's evidence agree on it. */
export function recordHash(rec: RegistryRecord | null): string {
  if (!rec) return "";
  const { _proofOfControlToken: _t, _vettingFlags: _f, ...pub } = rec as RegistryRecord & OutOfBand;
  return hashObject(pub);
}

// ------------------------------------------------------------- standing

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

export interface Standing {
  ok: boolean;
  reasonCode?: ReasonCode;
  evidence: Record<string, unknown>;
  insurance?: InsuranceStatus;
  brokerAuthority?: boolean;
}

/**
 * Is this entity in good standing at `at` — and, if `through` is given, will
 * its insurance still be in force then? The registry knows cancellations
 * ahead of time (an insurer must file 30 days out), which is precisely what
 * a notice-driven design cannot know: a filing that cancels between the
 * commitment and delivery is INSURANCE_CANCELLATION_PENDING, refused now.
 * The venue runs this before every step; a verifier reruns it over the
 * attested record in the artifact.
 */
export function standing(rec: RegistryRecord | null, at: Date, opts: { hazmat?: boolean; requiredBipdUsd?: number; through?: Date } = {}): Standing {
  if (!rec) return { ok: false, reasonCode: "ONBOARDING_ENTITY_NOT_FOUND", evidence: {} };
  if (!authorityActive(rec, at)) {
    return { ok: false, reasonCode: "AUTHORITY_NOT_ACTIVE", evidence: { usdot: rec.usdot, operatingStatus: rec.operatingStatus, outOfServiceDate: rec.outOfServiceDate, authorities: rec.authorities, at: at.toISOString() } };
  }
  const ins = insuranceStatus(rec, at, opts);
  const lapsedDigest = (s: InsuranceStatus) => s.lapsedFilings.map((f) => ({ type: f.type, form: f.form, insurer: f.insurer, policyNumber: f.policyNumber, cancellationDate: f.cancellationDate }));
  if (!ins.ok) {
    return { ok: false, reasonCode: ins.reasonCode, insurance: ins, evidence: { usdot: rec.usdot, asOf: ins.asOf, lapsedFilings: lapsedDigest(ins), activeBipdUsd: ins.bipdCoverageUsd, activeBondUsd: ins.bondUsd, requiredBipdUsd: opts.requiredBipdUsd } };
  }
  if (opts.through && opts.through > at) {
    const later = insuranceStatus(rec, opts.through, opts);
    if (!later.ok) {
      const pending = later.lapsedFilings.filter((f) => f.cancellationDate && new Date(f.cancellationDate) > at);
      return { ok: false, reasonCode: "INSURANCE_CANCELLATION_PENDING", insurance: ins, evidence: { usdot: rec.usdot, at: at.toISOString(), through: opts.through.toISOString(), cancellingBeforeThrough: lapsedDigest({ ...later, lapsedFilings: pending }), activeBipdUsdNow: ins.bipdCoverageUsd, activeBipdUsdThrough: later.bipdCoverageUsd } };
    }
  }
  return { ok: true, insurance: ins, brokerAuthority: hasBrokerAuthority(rec, at), evidence: { usdot: rec.usdot, at: at.toISOString(), bipdUsd: ins.bipdCoverageUsd, cargoUsd: ins.cargoCoverageUsd, bondUsd: ins.bondUsd, safetyRating: rec.safetyRating, through: opts.through?.toISOString() } };
}

// ---------------------------------------------------------- attestation

/** The registry's signed word: this record, as of this moment on the registry's clock. `record: null` is a signed "not found". */
export interface RegistryAttestation {
  schema: "freight-venue/registry-attestation/v1";
  registryId: string;
  usdot: string;
  asOf: string;
  record: RegistryRecord | null;
  recordHash: string;
  kid: string;
  /** Detached JWS by the registry key over the attestation sans this field. */
  signature: string;
}

export interface RegistryKey {
  registryId: string;
  publicKey: OkpJwk;
}

export function signAttestation(registry: KeyPair, registryId: string, usdot: string, record: RegistryRecord | null, now = new Date()): RegistryAttestation {
  const unsigned: Omit<RegistryAttestation, "signature"> = { schema: "freight-venue/registry-attestation/v1", registryId, usdot, asOf: now.toISOString(), record, recordHash: recordHash(record), kid: registry.kid };
  return { ...unsigned, signature: signJws(unsigned, registry, { typ: "registry-attestation+jws" }, true) };
}

export function verifyAttestation(a: RegistryAttestation, key: OkpJwk): boolean {
  if (a.schema !== "freight-venue/registry-attestation/v1") return false;
  const { signature, ...unsigned } = a;
  if (recordHash(a.record) !== a.recordHash) return false;
  if (a.record && a.record.usdot !== a.usdot) return false;
  try {
    return verifyJws(signature, importPublicKey(key), unsigned).ok;
  } catch {
    return false;
  }
}

/**
 * Was the registry's word fresh enough when the venue relied on it? `asOf` must
 * fall inside [reliedAt − maxAgeMs, reliedAt + skewMs]: older and later
 * cancellations were invisible; from the future and a clock is wrong.
 */
export function attestationFreshAt(a: RegistryAttestation, reliedAt: Date, maxAgeMs: number, skewMs = 60_000): { ok: boolean; ageMs: number } {
  const ageMs = reliedAt.getTime() - new Date(a.asOf).getTime();
  return { ok: ageMs <= maxAgeMs && ageMs >= -skewMs, ageMs };
}

/**
 * How the venue sees the registry: a store (the mock authority, in tests) or
 * a mirror of verified attestations (the venue process). `refresh` obtains a
 * signed attestation no older than `maxAgeMs` or throws — a venue that cannot
 * reach the registry cannot verify, and must not commit.
 */
export interface RegistryView {
  get(usdot: string): (RegistryRecord & OutOfBand) | undefined;
  snapshotHash(usdot: string): string;
  /** The latest verified attestation held for this entity (a store attests nothing). */
  attestation?(usdot: string): RegistryAttestation | undefined;
  refresh?(usdot: string, maxAgeMs: number, now?: Date): Promise<RegistryAttestation>;
}
