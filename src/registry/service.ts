/**
 * The registry as a signing authority. Every answer about an entity is a
 * RegistryAttestation: the public record and the registry's own clock, under
 * the registry's key. A venue relays these; it cannot forge, backdate or
 * refresh them.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { exportPrivateJwk, generateKeyPair, importKeyPair, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { signAttestation, signFilerAttestation, signRegulatorLogAttestation, type FilerAttestation, type InsurerRegistration, type OutOfBand, type RegistryAttestation, type RegistryRecord, type RegulatorLogAttestation } from "../protocol/registry";
import type { RootEvent } from "../protocol/venue-keys";
import { MockRegistry } from "./store";

export class RegistryService {
  readonly kp: KeyPair;
  readonly store: MockRegistry;
  /** SIM fault: the registry is unreachable (answers 503). */
  unavailable = false;
  /**
   * SIM fault: a mirror that stopped syncing its upstream — it keeps signing the records it had. An HONEST frozen
   * mirror says so (`upstreamAsOf` stops advancing) and is merely stale; one that `claimsCurrent` signs a sync time
   * it did not have, and answers for the record it served.
   */
  private frozen?: { records: Map<string, RegistryRecord | null>; filers: Map<string, InsurerRegistration>; regulators: Map<string, RootEvent[]>; at: Date; claimsCurrent: boolean };
  private served = 0;

  constructor(readonly registryId: string, dataDir: string, storePath: string) {
    mkdirSync(dataDir, { recursive: true });
    const keyPath = join(dataDir, "registry-key.jwk.json");
    if (existsSync(keyPath)) this.kp = importKeyPair(JSON.parse(readFileSync(keyPath, "utf8")));
    else {
      this.kp = generateKeyPair();
      writeFileSync(keyPath, JSON.stringify(exportPrivateJwk(this.kp)));
    }
    writeFileSync(join(dataDir, "registry-public.jwk.json"), JSON.stringify({ ...this.kp.publicJwk, registryId }));
    this.store = new MockRegistry(storePath);
  }

  wellKnown(): { registryId: string; publicKey: OkpJwk } {
    return { registryId: this.registryId, publicKey: this.kp.publicJwk };
  }

  attest(usdot: string, now = new Date()): RegistryAttestation {
    this.served++;
    const record = this.frozen ? (this.frozen.records.get(usdot) ?? null) : this.store.publicRecord(usdot);
    const upstreamAsOf = this.frozen && !this.frozen.claimsCurrent ? this.frozen.at : now;
    return signAttestation(this.kp, this.registryId, usdot, record, now, upstreamAsOf);
  }

  /** The registry's signed word about a filer — who signs under which key, since when, and until when. */
  attestFiler(insurerId: string, now = new Date()): FilerAttestation {
    this.served++;
    const reg = this.frozen ? (this.frozen.filers.get(insurerId) ?? null) : this.store.filer(insurerId);
    const upstreamAsOf = this.frozen && !this.frozen.claimsCurrent ? this.frozen.at : now;
    return signFilerAttestation(this.kp, this.registryId, insurerId, reg ? structuredClone(reg) : null, now, upstreamAsOf);
  }

  /** The registry's signed word about a regulator's key log — how a party that pins only registries learns who the regulator is. */
  attestRegulator(regulatorId: string, now = new Date()): RegulatorLogAttestation {
    this.served++;
    const log = this.frozen ? (this.frozen.regulators.get(regulatorId) ?? null) : this.store.regulatorLog(regulatorId);
    const upstreamAsOf = this.frozen && !this.frozen.claimsCurrent ? this.frozen.at : now;
    return signRegulatorLogAttestation(this.kp, this.registryId, regulatorId, log ? structuredClone(log) : null, now, upstreamAsOf);
  }

  /** SIM: freeze what this mirror serves at the current records (or thaw); `claimsCurrent` makes it lie about its sync. */
  freeze(on: boolean, claimsCurrent = false) {
    this.frozen = on ? { records: new Map(this.store.all().map((r) => [r.usdot, this.store.publicRecord(r.usdot)])), filers: new Map(this.store.allFilers().map((f) => [f.insurerId, structuredClone(f)])), regulators: new Map(this.store.allRegulators().map((r) => [r.regulatorId, structuredClone(this.store.regulatorLog(r.regulatorId)!)])), at: new Date(), claimsCurrent } : undefined;
  }
  get isFrozen(): boolean {
    return !!this.frozen;
  }
  get claimsCurrent(): boolean {
    return !!this.frozen?.claimsCurrent;
  }

  records(): RegistryRecord[] {
    return this.store.all().map((r) => this.store.publicRecord(r.usdot)!);
  }

  /** STUB: what a proof-of-control challenge and a vetting provider would return out of band. Never attested. */
  outOfBand(usdot: string): OutOfBand | undefined {
    return this.store.outOfBand(usdot);
  }

  status() {
    return { registryId: this.registryId, kid: this.kp.kid, records: this.store.all().length, attestationsServed: this.served, unavailable: this.unavailable, frozen: this.isFrozen, claimsCurrent: this.claimsCurrent };
  }
}
