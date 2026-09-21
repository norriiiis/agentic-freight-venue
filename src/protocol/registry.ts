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
 *
 * One signer is one party to trust. Several vetting providers mirror the
 * same upstream independently of each other and of the venue; the venue
 * asks all it is configured with, needs a quorum to have answered, and
 * requires them to be UNANIMOUS that the party is in standing — a
 * cancellation is news that cannot be un-known, so the one mirror that has
 * the filing outranks the two that do not. A mirror that is stale or lying
 * can therefore only block, never cause, a commitment; and its signed word
 * beside its peers' signed word is the evidence it answers for.
 *
 * Independence among mirrors is configuration, not proof, so two more things
 * make collusion a losing game rather than a safe one. Every attestation
 * states when the mirror last synced its upstream (`upstreamAsOf`) — its
 * claim of currency, which freshness is judged on — and every cancellation
 * carries the date it was FILED. A mirror that claims a sync after a filing
 * date and serves a record without that filing has signed a falsehood, and
 * any later word showing the filing (another mirror's, its own, or the
 * insurer's) is a self-contained proof against it. And the ORIGIN of the
 * fact — the insurer, whose filing every mirror mirrors — can sign it
 * directly: an InsurerAttestation no set of mirrors can forge, whose
 * statutory notice period turns a point-in-time statement into a window
 * within which coverage cannot lawfully end.
 *
 * The origin's honesty is then the last thing left, and it is answered the
 * same three ways. Identity: the registry's filing names the insurer of
 * record and the policy, so an attestation from anyone else — however well
 * signed — is not the origin's word (INSURER_NOT_OF_RECORD). Accountability,
 * symmetric with the mirrors': an insurer that signs "no cancellation" after
 * the date the registry received its own filing has signed a falsehood, and
 * the mirrors' word is the proof (INSURER_FALSE_ATTESTATION). Liability: a
 * certificate of insurance famously "confers no rights"; an attestation can
 * instead carry an UNDERTAKING — the insurer's signed promise not to deny a
 * covered loss on the basis of any lapse it did not disclose here, through
 * the date it assures — and a principal or verifier can accept nothing
 * less. The protocol cannot make an insurer pay; it can make sure the only
 * word that satisfies the policy is one the insurer is liable for.
 *
 * Which key is the insurer's is a registry fact too. An insurer that files
 * with the registry is a registered FILER, and its filer registration —
 * legal name and signing keys, with their validity and any revocation — is
 * attested by the same mirrors under the same quorum, unanimity, freshness
 * and accountability as any record. So the binding of a key to the name on
 * a filing is nobody's configuration: not the venue operator's, who can be
 * fooled or dishonest, and not the verifier's, who need pin nothing beyond
 * the registries. A key the registries do not list for that filer at that
 * time signs nothing the origin said (INSURER_KEY_NOT_OF_RECORD).
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
  /** ISO date on the insurer's cancellation notice — when the insurer FILED it (statute requires ≥ 30 days before it takes effect). */
  cancellationFiledDate?: string;
  /** ISO date the registry received/published the notice; the same day as filed unless the registry lagged. Defaults to the filed date. */
  cancellationReceivedDate?: string;
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

/**
 * The registry's signed word: this record, as of this moment on the
 * registry's clock, from an upstream it last synced at `upstreamAsOf`.
 * `record: null` is a signed "not found". Freshness is judged on the sync
 * claim; a mirror that overstates it answers for the record it served.
 */
export interface RegistryAttestation {
  schema: "freight-venue/registry-attestation/v1";
  registryId: string;
  usdot: string;
  asOf: string;
  /** When this mirror last synced the upstream it mirrors — its claim of currency. Absent in attestations from before the field existed (then `asOf`). */
  upstreamAsOf?: string;
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

/** Which registry said what, and when — the reference a verdict or an attachment carries. */
export interface RegistryRef {
  registryId: string;
  kid: string;
  asOf: string;
}

export function registryRef(a: RegistryAttestation): RegistryRef {
  return { registryId: a.registryId, kid: a.kid, asOf: a.asOf };
}

/**
 * The facts standing depends on. Independent mirrors of one upstream may
 * differ in fields that do not matter here (an MCS-150 date, a fleet count);
 * they must not differ in these.
 */
export function standingProjection(rec: RegistryRecord | null): string {
  if (!rec) return "";
  return hashObject({ entityType: rec.entityType, operatingStatus: rec.operatingStatus, outOfServiceDate: rec.outOfServiceDate ?? null, authorities: rec.authorities, insurance: rec.insurance });
}

export function signAttestation(registry: KeyPair, registryId: string, usdot: string, record: RegistryRecord | null, now = new Date(), upstreamAsOf: Date = now): RegistryAttestation {
  const unsigned: Omit<RegistryAttestation, "signature"> = { schema: "freight-venue/registry-attestation/v1", registryId, usdot, asOf: now.toISOString(), upstreamAsOf: upstreamAsOf.toISOString(), record, recordHash: recordHash(record), kid: registry.kid };
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
 * Was the registry's word fresh enough when the venue relied on it? The
 * mirror's SYNC claim (`upstreamAsOf`) must be no older than maxAgeMs at
 * reliedAt — later filings were invisible to it — and its signing clock
 * (`asOf`) no further in the future than skewMs, or a clock is wrong.
 */
export function attestationFreshAt(a: { asOf: string; upstreamAsOf?: string }, reliedAt: Date, maxAgeMs: number, skewMs = 60_000): { ok: boolean; ageMs: number } {
  const ageMs = reliedAt.getTime() - new Date(a.upstreamAsOf ?? a.asOf).getTime();
  const signedAhead = new Date(a.asOf).getTime() - reliedAt.getTime();
  return { ok: ageMs <= maxAgeMs && ageMs >= -skewMs && signedAhead <= skewMs, ageMs };
}

// ------------------------------------------------------- filer directory

/** A key an insurer files (and signs attestations) under: valid from a moment, until revoked. */
export interface FilerKey {
  kid: string;
  publicKey: OkpJwk;
  validFrom: string;
  /** From when the key is no longer the filer's (for COMPROMISE, possibly in the past: signatures after it are suspect). */
  revokedAt?: string;
  /** When the registry recorded the revocation — what a mirror synced later is accountable for. Defaults to revokedAt. */
  declaredAt?: string;
  reason?: "ROTATION" | "COMPROMISE";
}

/** An insurer's registration with the registry: the name it files under and the keys it has signed under. */
export interface InsurerRegistration {
  insurerId: string;
  legalName: string;
  keys: FilerKey[];
  registeredAt: string;
}

/** The registry's signed word about a filer, on the same terms as its word about an entity. */
export interface FilerAttestation {
  schema: "freight-venue/filer-attestation/v1";
  registryId: string;
  insurerId: string;
  asOf: string;
  upstreamAsOf?: string;
  registration: InsurerRegistration | null;
  recordHash: string;
  kid: string;
  signature: string;
}

export function signFilerAttestation(registry: KeyPair, registryId: string, insurerId: string, registration: InsurerRegistration | null, now = new Date(), upstreamAsOf: Date = now): FilerAttestation {
  const unsigned: Omit<FilerAttestation, "signature"> = { schema: "freight-venue/filer-attestation/v1", registryId, insurerId, asOf: now.toISOString(), upstreamAsOf: upstreamAsOf.toISOString(), registration, recordHash: registration ? hashObject(registration) : "", kid: registry.kid };
  return { ...unsigned, signature: signJws(unsigned, registry, { typ: "filer-attestation+jws" }, true) };
}

export function verifyFilerAttestation(a: FilerAttestation, key: OkpJwk): boolean {
  if (a.schema !== "freight-venue/filer-attestation/v1") return false;
  const { signature, ...unsigned } = a;
  if ((a.registration ? hashObject(a.registration) : "") !== a.recordHash) return false;
  if (a.registration && a.registration.insurerId !== a.insurerId) return false;
  try {
    return verifyJws(signature, importPublicKey(key), unsigned).ok;
  } catch {
    return false;
  }
}

/** The filer's key `kid` as valid at `at`: registered by then and not revoked at or before it. */
export function filerKeyAt(reg: InsurerRegistration | null, kid: string, at: Date): FilerKey | undefined {
  return reg?.keys.find((k) => k.kid === kid && new Date(k.validFrom) <= at && !(k.revokedAt && new Date(k.revokedAt) <= at));
}

/**
 * Which key is the filer's, per the registries: every attestation must
 * show `kid` valid at `at` — unanimity, as for standing, because a
 * revocation is news that cannot be un-known. Names the dissent.
 */
export function filerKeyOfRecord(atts: FilerAttestation[], kid: string, at: Date): { ok: boolean; key?: FilerKey; legalName?: string; why?: string; showing: string[]; dissenting: string[] } {
  const showing: string[] = [];
  const dissenting: string[] = [];
  let key: FilerKey | undefined;
  let legalName: string | undefined;
  for (const a of atts) {
    const k = filerKeyAt(a.registration, kid, at);
    if (k) { showing.push(a.registryId); key ??= k; legalName ??= a.registration!.legalName; } else dissenting.push(a.registryId);
  }
  if (atts.length === 0) return { ok: false, why: "no registry word about this filer", showing, dissenting };
  if (dissenting.length) {
    const first = atts.find((a) => a.registryId === dissenting[0])!;
    const known = first.registration?.keys.find((k) => k.kid === kid);
    return { ok: false, key, legalName: legalName ?? first.registration?.legalName, why: !first.registration ? `${dissenting.join(", ")}: no such filer` : !known ? `${dissenting.join(", ")}: key ${kid.slice(0, 12)}… is not a key this filer registered` : known.revokedAt && new Date(known.revokedAt) <= at ? `${dissenting.join(", ")}: key ${kid.slice(0, 12)}… revoked ${known.revokedAt} (${known.reason ?? "revoked"}), signature at ${at.toISOString()}` : `${dissenting.join(", ")}: key ${kid.slice(0, 12)}… not yet valid at ${at.toISOString()} (from ${known.validFrom})`, showing, dissenting };
  }
  return { ok: true, key, legalName, showing, dissenting };
}

/** A key event somebody's signed word shows: a mirror claiming a later sync cannot honestly lack a revocation. */
export interface KeyEventEvidence { source: string; insurerId: string; kid: string; revokedAt: string; declaredAt: string; asOf: string }

export function keyEventsShownBy(a: FilerAttestation): KeyEventEvidence[] {
  return (a.registration?.keys ?? []).filter((k) => k.revokedAt).map((k) => ({ source: a.registryId, insurerId: a.insurerId, kid: k.kid, revokedAt: k.revokedAt!, declaredAt: k.declaredAt ?? k.revokedAt!, asOf: a.upstreamAsOf ?? a.asOf }));
}

/** A mirror that claims a sync after a revocation was DECLARED and still shows the key unrevoked has signed a falsehood. */
export function filerContradictedBy(x: FilerAttestation, evidence: KeyEventEvidence[]): { registryId: string; insurerId: string; claimedSyncAt: string; attestation: FilerAttestation; missing: KeyEventEvidence } | undefined {
  const sync = new Date(x.upstreamAsOf ?? x.asOf);
  for (const e of evidence) {
    if (e.insurerId !== x.insurerId || (e.source === x.registryId && e.asOf === (x.upstreamAsOf ?? x.asOf))) continue;
    if (new Date(e.declaredAt) >= sync) continue;
    const own = x.registration?.keys.find((k) => k.kid === e.kid);
    if (!own || (own.revokedAt && new Date(own.revokedAt) <= new Date(e.revokedAt))) continue;
    return { registryId: x.registryId, insurerId: x.insurerId, claimedSyncAt: sync.toISOString(), attestation: x, missing: e };
  }
  return undefined;
}

// ------------------------------------------------------- accountability

/**
 * A cancellation somebody's signed word shows. Two dates matter: when the
 * insurer FILED it (the insurer's own act — what the insurer is accountable
 * for) and when the registry RECEIVED it (what a mirror synced later is
 * accountable for). Dates, not instants: same-day ordering is not judged.
 */
export interface FilingEvidence {
  source: string;
  policyNumber: string;
  cancellationDate: string;
  cancellationFiledDate: string;
  cancellationReceivedDate: string;
  asOf: string;
}

const dayOf = (iso: string) => iso.slice(0, 10);

export function filingsShownBy(a: RegistryAttestation): FilingEvidence[] {
  return (a.record?.insurance ?? []).filter((f) => f.cancellationDate && f.cancellationFiledDate).map((f) => ({ source: a.registryId, policyNumber: f.policyNumber, cancellationDate: f.cancellationDate!, cancellationFiledDate: f.cancellationFiledDate!, cancellationReceivedDate: f.cancellationReceivedDate ?? f.cancellationFiledDate!, asOf: a.upstreamAsOf ?? a.asOf }));
}

/** A signed falsehood: attestation `x` claims a sync after a filing that its record lacks. Self-contained given the signers' keys. */
export interface FalseAttestationProof {
  registryId: string;
  usdot: string;
  claimedSyncAt: string;
  attestation: RegistryAttestation;
  missing: FilingEvidence;
}

/**
 * Is `x` contradicted by any filing evidence? A mirror may lag — an honest
 * lagging mirror says so in `upstreamAsOf`. What it may not do is claim a
 * sync at S and serve a record without a cancellation the registry received
 * before S. The proof names the filing and who showed it; who is lying is a
 * question the corroboration answers.
 */
export function contradictedBy(x: RegistryAttestation, evidence: FilingEvidence[]): FalseAttestationProof | undefined {
  const sync = new Date(x.upstreamAsOf ?? x.asOf);
  for (const e of evidence) {
    if (e.source === x.registryId && e.asOf === (x.upstreamAsOf ?? x.asOf)) continue;
    // A mirror answers for what the registry had published on an earlier day than its sync claim.
    if (e.cancellationReceivedDate >= dayOf(sync.toISOString())) continue;
    const own = x.record?.insurance.find((f) => f.policyNumber === e.policyNumber);
    if (!own) continue; // a policy this mirror never showed: not a contradiction, a different record — caught as disagreement
    if (own.cancellationDate && own.cancellationDate <= e.cancellationDate) continue;
    return { registryId: x.registryId, usdot: x.usdot, claimedSyncAt: sync.toISOString(), attestation: x, missing: e };
  }
  return undefined;
}

// ------------------------------------------------------- the origin's word

/**
 * The insurer's own signed word about its own filing — the fact every mirror
 * mirrors, from where it originates. No set of mirrors can forge it. Under
 * 49 CFR 387 an insurer must give the registry `noticeDays` (30) before a
 * cancellation takes effect, so a statement with no cancellation disclosed
 * assures coverage through asOf + noticeDays whatever any mirror says.
 */
/**
 * The insurer's signed promise, if it makes one: a covered loss during the
 * assured window will not be denied on the basis of any cancellation,
 * non-renewal or lapse this attestation did not disclose. Without it the
 * attestation is a certificate — the insurer's belief; with it, a statement
 * the insurer is liable for, and the evidence for estoppel is the artifact.
 */
export type InsurerUndertaking = "NO_DENIAL_FOR_UNDISCLOSED_LAPSE";

export interface InsurerAttestation {
  schema: "freight-venue/insurer-attestation/v1";
  insurerId: string;
  /** The insurer's name as it appears on the registry filing — what makes this the insurer OF RECORD. */
  insurerName?: string;
  usdot: string;
  policyNumber: string;
  type: FilingType;
  form: FilingForm;
  coverageToUsd: number;
  effectiveDate: string;
  /** A cancellation the insurer has filed (or is filing now), if any. */
  cancellation?: { filedDate: string; effectiveDate: string };
  noticeDays: number;
  undertaking?: InsurerUndertaking;
  asOf: string;
  kid: string;
  /** Detached JWS by the insurer's key over the attestation sans this field. */
  signature: string;
}

export interface InsurerKey {
  insurerId: string;
  publicKey: OkpJwk;
  /** The name under which this insurer files with the registry; when known, attestations must be of record under it. */
  insurerName?: string;
}

export function signInsurerAttestation(insurer: KeyPair, insurerId: string, fields: Omit<InsurerAttestation, "schema" | "insurerId" | "asOf" | "kid" | "signature" | "noticeDays"> & { noticeDays?: number }, now = new Date(), insurerName?: string): InsurerAttestation {
  const unsigned: Omit<InsurerAttestation, "signature"> = { schema: "freight-venue/insurer-attestation/v1", insurerId, insurerName, noticeDays: 30, ...fields, asOf: now.toISOString(), kid: insurer.kid };
  return { ...unsigned, signature: signJws(unsigned, insurer, { typ: "insurer-attestation+jws" }, true) };
}

export function verifyInsurerAttestation(a: InsurerAttestation, key: OkpJwk): boolean {
  if (a.schema !== "freight-venue/insurer-attestation/v1") return false;
  const { signature, ...unsigned } = a;
  try {
    return verifyJws(signature, importPublicKey(key), unsigned).ok;
  } catch {
    return false;
  }
}

/** Through when this word alone assures coverage: the disclosed cancellation, else asOf + the statutory notice. */
export function coverageAssuredThrough(a: InsurerAttestation): Date {
  const statutory = new Date(new Date(a.asOf).getTime() + a.noticeDays * 86_400_000);
  if (!a.cancellation) return statutory;
  const eff = new Date(a.cancellation.effectiveDate);
  return eff < statutory ? eff : statutory;
}

/**
 * The statutory window makes "when must the origin speak again" arithmetic.
 * A word signed at S assures through S + notice; to reach a delivery at D it
 * must be signed at or after D − notice, and it must be on file before the
 * truck moves. So a commitment whose word on file falls short of delivery is
 * CONDITIONAL: a renewal signed in [D − notice, pickup] must be presented by
 * pickup, or the commitment is voided in time to re-cover the load. If
 * D − notice is after pickup (transit longer than the notice period), no word
 * signed before dispatch can reach delivery and the load cannot be assured.
 */
export interface RenewalWindow {
  /** What the word on file assures through, if any. */
  assuredThrough?: string;
  /** Whether the word on file already reaches delivery. */
  reachesDelivery: boolean;
  /** Earliest signing time of a word that can reach delivery. */
  earliestSignedAt: string;
  /** The renewal must be on file by this moment (pickup). */
  dueBy: string;
  /** false when earliestSignedAt is after dueBy: no renewal can help. */
  possible: boolean;
}

export function renewalWindow(onFile: InsurerAttestation | undefined, pickup: Date, delivery: Date, noticeDays = onFile?.noticeDays ?? 30): RenewalWindow {
  const assured = onFile ? coverageAssuredThrough(onFile) : undefined;
  const earliest = new Date(delivery.getTime() - noticeDays * 86_400_000);
  return { assuredThrough: assured?.toISOString(), reachesDelivery: !!assured && assured >= delivery, earliestSignedAt: earliest.toISOString(), dueBy: pickup.toISOString(), possible: earliest <= pickup };
}

/** Does this word satisfy a renewal condition: signed no earlier than the window allows, and assuring through delivery? */
export function satisfiesRenewal(a: InsurerAttestation, w: RenewalWindow, delivery: Date): boolean {
  return new Date(a.asOf) >= new Date(w.earliestSignedAt) && coverageAssuredThrough(a) >= delivery;
}

/**
 * Is this attestation the word of the insurer OF RECORD? The registry's
 * filing names the insurer and the policy; an attestation about a policy the
 * registry does not show, or under a name that is not the filing's insurer,
 * is somebody's word, not the origin's.
 */
export function insurerOfRecord(a: InsurerAttestation, records: (RegistryRecord | null)[], insurerName = a.insurerName): { ok: boolean; why?: string; filing?: InsuranceFiling; shownBy: number } {
  const filings = records.flatMap((r) => (r?.usdot === a.usdot ? r.insurance : [])).filter((f) => f.policyNumber === a.policyNumber);
  if (records.filter(Boolean).length === 0) return { ok: false, why: "no registry record to check the filing against", shownBy: 0 };
  if (filings.length === 0) return { ok: false, why: `policy ${a.policyNumber} is not among the filings the registry shows for ${a.usdot}`, shownBy: 0 };
  const named = insurerName ? filings.filter((f) => f.insurer === insurerName) : filings;
  if (named.length === 0) return { ok: false, why: `policy ${a.policyNumber} is filed by ${[...new Set(filings.map((f) => f.insurer))].join("/")}, not by ${insurerName}`, shownBy: filings.length };
  if (named.some((f) => f.type !== a.type)) return { ok: false, why: `policy ${a.policyNumber} is filed as ${named[0]!.type}, attested as ${a.type}`, shownBy: named.length };
  return { ok: true, filing: named[0], shownBy: named.length };
}

/** A signed falsehood by the origin: the insurer signed after the registry received its own filing, and did not disclose it. */
export interface InsurerFalseAttestationProof {
  insurerId: string;
  usdot: string;
  signedAt: string;
  attestation: InsurerAttestation;
  missing: FilingEvidence;
}

export function insurerContradictedBy(a: InsurerAttestation, evidence: FilingEvidence[]): InsurerFalseAttestationProof | undefined {
  for (const e of evidence) {
    if (e.policyNumber !== a.policyNumber || e.source === `insurer:${a.insurerId}` && e.asOf === a.asOf) continue;
    // The insurer answers for what it had itself filed on an earlier day than it signed.
    if (e.cancellationFiledDate >= dayOf(a.asOf)) continue;
    if (a.cancellation && a.cancellation.effectiveDate <= e.cancellationDate) continue;
    return { insurerId: a.insurerId, usdot: a.usdot, signedAt: a.asOf, attestation: a, missing: e };
  }
  return undefined;
}

export function filingShownByInsurer(a: InsurerAttestation): FilingEvidence | undefined {
  return a.cancellation ? { source: `insurer:${a.insurerId}`, policyNumber: a.policyNumber, cancellationDate: a.cancellation.effectiveDate, cancellationFiledDate: a.cancellation.filedDate, cancellationReceivedDate: a.cancellation.filedDate, asOf: a.asOf } : undefined;
}

/**
 * Standing per the origin's word: in force at `at`, and — if `through` is
 * asked — assured through it. Beyond the assured window the insurer's word
 * is silent, not negative: that is the registries' question.
 */
export function insurerStanding(a: InsurerAttestation, at: Date, through?: Date): { ok: boolean; reasonCode?: ReasonCode; assuredThrough: string; evidence: Record<string, unknown> } {
  const assured = coverageAssuredThrough(a);
  const base = { assuredThrough: assured.toISOString(), insurer: a.insurerId, policyNumber: a.policyNumber, asOf: a.asOf, cancellation: a.cancellation };
  if (new Date(a.effectiveDate) > at) return { ok: false, reasonCode: "INSURANCE_LAPSED", assuredThrough: assured.toISOString(), evidence: { ...base, note: "policy not yet effective" } };
  if (a.cancellation && new Date(a.cancellation.effectiveDate) <= at) return { ok: false, reasonCode: "INSURANCE_LAPSED", assuredThrough: assured.toISOString(), evidence: base };
  if (through && a.cancellation && new Date(a.cancellation.effectiveDate) <= through) return { ok: false, reasonCode: "INSURANCE_CANCELLATION_PENDING", assuredThrough: assured.toISOString(), evidence: { ...base, through: through.toISOString() } };
  return { ok: true, assuredThrough: assured.toISOString(), evidence: base };
}

/**
 * How the venue sees the registry: a store (the mock authority, in tests) or
 * a mirror of verified attestations from every registry it is configured
 * with (the venue process). `refresh` obtains signed attestations no older
 * than `maxAgeMs` from at least a quorum of them or throws — a venue that
 * cannot reach the registry cannot verify, and must not commit.
 */
export interface RegistryView {
  get(usdot: string): (RegistryRecord & OutOfBand) | undefined;
  snapshotHash(usdot: string): string;
  /** The verified attestations relied on for this entity, one per registry (a store attests nothing). */
  attestations?(usdot: string): RegistryAttestation[];
  refresh?(usdot: string, maxAgeMs: number, now?: Date): Promise<RegistryAttestation[]>;
}
