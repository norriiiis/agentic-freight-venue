/**
 * The venue's view of the registry: a mirror of VERIFIED attestations, one
 * per entity, under a registry key pinned at first contact (trust on first
 * use here; an operator pins it by configuration in production).
 *
 * The mirror never invents a record. `get` returns what the registry last
 * signed; `refresh` demands a signature no older than the caller's policy or
 * throws RegistryUnavailable — and a venue that cannot obtain the registry's
 * word has no business attesting anyone's standing.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { OkpJwk } from "../protocol/crypto";
import { writeFileAtomic } from "../protocol/fsatomic";
import { attestationFreshAt, verifyAttestation, type OutOfBand, type RegistryAttestation, type RegistryKey, type RegistryRecord, type RegistryView } from "../protocol/registry";

export class RegistryUnavailable extends Error {
  constructor(public readonly usdot: string, public readonly why: string, public readonly lastAsOf?: string) {
    super(`registry unavailable for ${usdot}: ${why}`);
  }
}

interface MirrorFile {
  pinned?: RegistryKey;
  attestations: Record<string, RegistryAttestation>;
  outOfBand: Record<string, OutOfBand>;
}

export class RegistryMirror implements RegistryView {
  private file: MirrorFile = { attestations: {}, outOfBand: {} };
  private readonly path: string;
  /** SIM fault: never refresh — serve whatever was last mirrored (a venue that read the registry once). */
  stale = false;

  constructor(readonly registryUrl: string, dataDir: string, readonly skewMs = 60_000) {
    mkdirSync(dataDir, { recursive: true });
    this.path = join(dataDir, "registry-mirror.json");
    if (existsSync(this.path)) this.file = JSON.parse(readFileSync(this.path, "utf8"));
  }

  get pinned(): RegistryKey | undefined {
    return this.file.pinned;
  }

  /** Pin the registry key: from configuration, or (TOFU) from the registry's well-known document. */
  async init(configured?: RegistryKey): Promise<RegistryKey> {
    if (configured) this.file.pinned = configured;
    else if (!this.file.pinned) {
      const res = await fetch(`${this.registryUrl}/.well-known/registry.json`).catch(() => undefined);
      if (!res?.ok) throw new Error(`registry at ${this.registryUrl} unreachable and no registry key pinned`);
      const wk = (await res.json()) as { registryId: string; publicKey: OkpJwk };
      this.file.pinned = { registryId: wk.registryId, publicKey: wk.publicKey };
      writeFileSync(join(this.path, "..", "registry.pinned.json"), JSON.stringify(this.file.pinned, null, 2));
    }
    this.persist();
    return this.file.pinned!;
  }

  private persist() {
    writeFileAtomic(this.path, JSON.stringify(this.file, null, 2));
  }

  get(usdot: string): (RegistryRecord & OutOfBand) | undefined {
    const a = this.file.attestations[usdot];
    if (!a?.record) return undefined;
    return { ...a.record, ...(this.file.outOfBand[usdot] ?? {}) };
  }

  snapshotHash(usdot: string): string {
    return this.file.attestations[usdot]?.recordHash ?? "";
  }

  attestation(usdot: string): RegistryAttestation | undefined {
    return this.file.attestations[usdot];
  }

  /** Every attestation held, for introspection. */
  all(): RegistryAttestation[] {
    return Object.values(this.file.attestations);
  }

  async refresh(usdot: string, maxAgeMs: number, now = new Date()): Promise<RegistryAttestation> {
    const have = this.file.attestations[usdot];
    if (have && (this.stale || attestationFreshAt(have, now, maxAgeMs, this.skewMs).ok)) return have;
    if (this.stale) throw new RegistryUnavailable(usdot, "no attestation mirrored (stale mode)");
    const pinned = this.file.pinned;
    if (!pinned) throw new RegistryUnavailable(usdot, "no registry key pinned");
    const res = await fetch(`${this.registryUrl}/attest?usdot=${encodeURIComponent(usdot)}`).catch((e: Error) => e);
    if (res instanceof Error || !res.ok) throw new RegistryUnavailable(usdot, res instanceof Error ? res.message : `HTTP ${res.status}`, have?.asOf);
    const a = (await res.json()) as RegistryAttestation;
    if (a.registryId !== pinned.registryId || a.usdot !== usdot || !verifyAttestation(a, pinned.publicKey)) throw new RegistryUnavailable(usdot, "attestation does not verify under the pinned registry key", have?.asOf);
    const fresh = attestationFreshAt(a, now, maxAgeMs, this.skewMs);
    if (!fresh.ok) throw new RegistryUnavailable(usdot, `registry answered with asOf ${a.asOf}, ${fresh.ageMs}ms from now (max ${maxAgeMs}, skew ${this.skewMs})`, have?.asOf);
    if (have && new Date(a.asOf) < new Date(have.asOf)) throw new RegistryUnavailable(usdot, `registry answered with asOf ${a.asOf}, earlier than the ${have.asOf} already held`, have.asOf);
    this.file.attestations[usdot] = a;
    if (!this.file.outOfBand[usdot]) {
      const oob = await fetch(`${this.registryUrl}/stub/out-of-band?usdot=${encodeURIComponent(usdot)}`).catch(() => undefined);
      if (oob?.ok) {
        const v = (await oob.json()) as OutOfBand | null;
        if (v) this.file.outOfBand[usdot] = v;
      }
    }
    this.persist();
    return a;
  }
}
