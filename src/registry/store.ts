/**
 * The mock registry's own store: a JSON file with the public record plus the
 * two out-of-band stubs (proof-of-control token, vetting flags).
 *
 * STUB: in production the authority is FMCSA's L&I / QCMobile data as
 * mirrored and signed by a vetting provider. This process stands in for that
 * signer: it is a SEPARATE trust domain from the venue — own key, own clock,
 * own data — and the venue only ever sees what it signs.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { recordHash, type OutOfBand, type RegistryRecord, type RegistryView } from "../protocol/registry";

export type StoredRecord = RegistryRecord & Required<OutOfBand>;

export class MockRegistry implements RegistryView {
  private records = new Map<string, StoredRecord>();
  constructor(private readonly path: string) {
    this.reload();
  }
  reload() {
    const arr: StoredRecord[] = JSON.parse(readFileSync(this.path, "utf8"));
    this.records = new Map(arr.map((r) => [r.usdot, r]));
  }
  persist() {
    writeFileSync(this.path, JSON.stringify([...this.records.values()], null, 2));
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
