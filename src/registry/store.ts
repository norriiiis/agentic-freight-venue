/**
 * The mock registry's own store: a JSON file with the public record plus the
 * two out-of-band stubs (proof-of-control token, vetting flags).
 *
 * STUB: in production the authority is FMCSA's L&I / QCMobile data as
 * mirrored and signed by a vetting provider. This process stands in for that
 * signer: it is a SEPARATE trust domain from the venue — own key, own clock,
 * own data — and the venue only ever sees what it signs.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { recordHash, type InsurerRegistration, type OutOfBand, type RegistryRecord, type RegistryView } from "../protocol/registry";

export type StoredRecord = RegistryRecord & Required<OutOfBand>;

export class MockRegistry implements RegistryView {
  private records = new Map<string, StoredRecord>();
  /** Registered filers: the insurers that file with this registry, the names they file under, and their keys. */
  private filers = new Map<string, InsurerRegistration>();
  private readonly filersPath: string;
  constructor(private readonly path: string, filersPath?: string) {
    this.filersPath = filersPath ?? path.replace(/\.json$/, "") + ".filers.json";
    this.reload();
  }
  reload() {
    const arr: StoredRecord[] = JSON.parse(readFileSync(this.path, "utf8"));
    this.records = new Map(arr.map((r) => [r.usdot, r]));
    if (existsSync(this.filersPath)) this.filers = new Map((JSON.parse(readFileSync(this.filersPath, "utf8")) as InsurerRegistration[]).map((f) => [f.insurerId, f]));
  }
  persist() {
    writeFileSync(this.path, JSON.stringify([...this.records.values()], null, 2));
    writeFileSync(this.filersPath, JSON.stringify([...this.filers.values()], null, 2));
  }
  filer(insurerId: string): InsurerRegistration | null {
    return this.filers.get(insurerId) ?? null;
  }
  allFilers(): InsurerRegistration[] {
    return [...this.filers.values()];
  }
  /** SIM-ONLY (the upstream onboarding a filer): register, or add a key to, an insurer's filer registration. */
  registerFiler(reg: { insurerId: string; legalName: string; publicKey: InsurerRegistration["keys"][number]["publicKey"]; kid: string; validFrom?: string }) {
    const now = new Date().toISOString();
    const cur = this.filers.get(reg.insurerId) ?? { insurerId: reg.insurerId, legalName: reg.legalName, keys: [], registeredAt: now };
    if (!cur.keys.some((k) => k.kid === reg.kid)) cur.keys.push({ kid: reg.kid, publicKey: reg.publicKey, validFrom: reg.validFrom ?? now });
    this.filers.set(reg.insurerId, cur);
    this.persist();
  }
  /** SIM-ONLY: the filer revokes a key with the registry (routine rotation, or compromise as of a time). */
  revokeFilerKey(insurerId: string, kid: string, revokedAt: string, reason: "ROTATION" | "COMPROMISE") {
    const cur = this.filers.get(insurerId);
    const k = cur?.keys.find((x) => x.kid === kid);
    if (!cur || !k) throw new Error(`registry: filer ${insurerId} key ${kid} not found`);
    k.revokedAt = revokedAt;
    k.declaredAt = new Date().toISOString();
    k.reason = reason;
    this.persist();
  }
  get(usdot: string): StoredRecord | undefined {
    return this.records.get(usdot);
  }
  byMc(mc: string): StoredRecord | undefined {
    return [...this.records.values()].find((r) => r.mc === mc);
  }
  all(): StoredRecord[] {
    return [...this.records.values()];
  }
  /** The public record — what an attestation carries. */
  publicRecord(usdot: string): RegistryRecord | null {
    const r = this.records.get(usdot);
    if (!r) return null;
    const { _proofOfControlToken: _t, _vettingFlags: _f, ...pub } = r;
    return pub;
  }
  outOfBand(usdot: string): OutOfBand | undefined {
    const r = this.records.get(usdot);
    return r ? { _proofOfControlToken: r._proofOfControlToken, _vettingFlags: r._vettingFlags } : undefined;
  }
  snapshotHash(usdot: string): string {
    return recordHash(this.publicRecord(usdot));
  }
  /** SIM-ONLY mutation hooks (an insurer filing a cancellation, FMCSA revoking authority). */
  update(usdot: string, patch: Partial<RegistryRecord>) {
    const r = this.records.get(usdot);
    if (!r) throw new Error(`registry: ${usdot} not found`);
    this.records.set(usdot, { ...r, ...patch });
    this.persist();
  }
}
