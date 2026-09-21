/**
 * The registry as a signing authority. Every answer about an entity is a
 * RegistryAttestation: the public record and the registry's own clock, under
 * the registry's key. A venue relays these; it cannot forge, backdate or
 * refresh them.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { KeyPair, OkpJwk } from "../protocol/crypto";
import { keyProviderFromEnv, loadOrCreate } from "../protocol/keys";
import { signAttestation, signFilerAttestation, signRegulatorLogAttestation, type FilerAttestation, type InsurerRegistration, type OutOfBand, type RegistryAttestation, type RegistryRecord, type RegulatorLogAttestation } from "../protocol/registry";
import type { RootEvent } from "../protocol/venue-keys";
import { MockRegistry } from "./store";
import { FileUpstream, type UpstreamSource } from "./upstream";

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
  /** Where this mirror syncs from, and when each entity was last synced successfully — the `upstreamAsOf` it signs. */
  readonly upstream: UpstreamSource;
  private syncedAt = new Map<string, Date>();
  private syncFailures = 0;

  constructor(readonly registryId: string, dataDir: string, storePath: string, opts: { upstream?: UpstreamSource; syncMaxAgeMs?: number } = {}) {
    mkdirSync(dataDir, { recursive: true });
    this.kp = loadOrCreate(keyProviderFromEnv((name) => join(dataDir, `${name}.jwk.json`)), "registry-key");
    writeFileSync(join(dataDir, "registry-public.jwk.json"), JSON.stringify({ ...this.kp.publicJwk, registryId }));
    this.store = new MockRegistry(storePath);
    this.upstream = opts.upstream ?? new FileUpstream(this.store);
    this.syncMaxAgeMs = opts.syncMaxAgeMs ?? 60_000;
  }
  private readonly syncMaxAgeMs: number;

  /**
   * Sync one entity from the upstream if the mirror's copy is older than the sync policy. A failed sync leaves the
   * copy AND its `upstreamAsOf` where they were: a mirror never claims a currency it did not get.
   */
  async sync(usdot: string, now = new Date()): Promise<{ synced: boolean; upstreamAsOf?: Date; error?: string }> {
    if (this.upstream instanceof FileUpstream) return { synced: true, upstreamAsOf: now }; // the store is the upstream
    const last = this.syncedAt.get(usdot);
    if (last && now.getTime() - last.getTime() < this.syncMaxAgeMs) return { synced: true, upstreamAsOf: last };
    try {
      const rec = await this.upstream.record(usdot);
      if (rec) this.store.upsertPublic(rec);
      this.syncedAt.set(usdot, now);
      return { synced: true, upstreamAsOf: now };
    } catch (e) {
      this.syncFailures++;
      return { synced: false, upstreamAsOf: last, error: e instanceof Error ? e.message : String(e) };
    }
  }

  wellKnown(): { registryId: string; publicKey: OkpJwk } {
    return { registryId: this.registryId, publicKey: this.kp.publicJwk };
  }

  async attest(usdot: string, now = new Date()): Promise<RegistryAttestation> {
    this.served++;
    const record = this.frozen ? (this.frozen.records.get(usdot) ?? null) : this.store.publicRecord(usdot);
    let upstreamAsOf = this.frozen && !this.frozen.claimsCurrent ? this.frozen.at : now;
    if (!this.frozen && !(this.upstream instanceof FileUpstream)) {
      const s = await this.sync(usdot, now);
      // Honest currency: the time the upstream was last actually read for this entity (or never).
      upstreamAsOf = s.upstreamAsOf ?? new Date(0);
      return signAttestation(this.kp, this.registryId, usdot, this.store.publicRecord(usdot), now, upstreamAsOf);
    }
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
    return { registryId: this.registryId, kid: this.kp.kid, records: this.store.all().length, attestationsServed: this.served, unavailable: this.unavailable, frozen: this.isFrozen, claimsCurrent: this.claimsCurrent, upstream: this.upstream.id, syncFailures: this.syncFailures };
  }
}
