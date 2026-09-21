/**
 * The venue's view of the registry: a mirror of VERIFIED attestations, one
 * per configured registry per entity, under keys pinned at first contact
 * (trust on first use here; an operator pins them by configuration in
 * production).
 *
 * The mirror never invents a record. `get` returns what the registries last
 * signed; `refresh` asks every registry, demands signatures no older than the
 * caller's policy from at least a quorum of them, and throws
 * RegistryUnavailable otherwise — a venue that cannot obtain the registries'
 * word has no business attesting anyone's standing. Whether the answers
 * AGREE is not the mirror's question: standing is judged over every
 * attestation held (identity/verifier.ts), and any one of them saying "not
 * in standing" is enough to refuse.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { OkpJwk } from "../protocol/crypto";
import { writeFileAtomic } from "../protocol/fsatomic";
import { attestationFreshAt, verifyAttestation, verifyFilerAttestation, type FilerAttestation, type OutOfBand, type RegistryAttestation, type RegistryKey, type RegistryRecord, type RegistryView } from "../protocol/registry";

export interface RegistrySource {
  registryId: string;
  url: string;
  /** Operator-pinned key; absent = trust on first use from the registry's well-known document. */
  publicKey?: OkpJwk;
}

export class RegistryUnavailable extends Error {
  constructor(public readonly usdot: string, public readonly why: string, public readonly perRegistry: Record<string, string>, public readonly lastAsOf?: string) {
    super(`registry unavailable for ${usdot}: ${why}`);
  }
}

interface MirrorFile {
  pinned: Record<string, RegistryKey>;
  /** usdot → registryId → latest verified attestation from that registry. */
  attestations: Record<string, Record<string, RegistryAttestation>>;
  /** usdot → the registries whose (fresh) word the last refresh relied on, in source order. */
  reliedOn: Record<string, string[]>;
  outOfBand: Record<string, OutOfBand>;
  /** insurerId → registryId → latest verified filer attestation: who signs under which key, per the registries. */
  filers: Record<string, Record<string, FilerAttestation>>;
  reliedOnFilers: Record<string, string[]>;
}

export class RegistryMirror implements RegistryView {
  private file: MirrorFile = { pinned: {}, attestations: {}, reliedOn: {}, outOfBand: {}, filers: {}, reliedOnFilers: {} };
  private readonly path: string;
  /** SIM fault: never refresh — serve whatever was last mirrored (a venue that read the registry once). */
  stale = false;
  /** SIM fault: registries the venue pretends not to have (a venue choosing its sources the way it might choose its witnesses). */
  hidden: string[] = [];

  constructor(readonly sources: RegistrySource[], dataDir: string, readonly quorum = 1, readonly skewMs = 60_000) {
    mkdirSync(dataDir, { recursive: true });
    this.path = join(dataDir, "registry-mirror.json");
    if (existsSync(this.path)) this.file = { filers: {}, reliedOnFilers: {}, ...JSON.parse(readFileSync(this.path, "utf8")) };
  }

  /** The pinned registry keys, in source order. */
  get pinned(): RegistryKey[] {
    return this.sources.map((s) => this.file.pinned[s.registryId]).filter((k): k is RegistryKey => !!k);
  }

  /** Pin every registry's key: from configuration, or (TOFU) from its well-known document. */
  async init(): Promise<RegistryKey[]> {
    for (const src of this.sources) {
      if (src.publicKey) this.file.pinned[src.registryId] = { registryId: src.registryId, publicKey: src.publicKey };
      else if (!this.file.pinned[src.registryId]) {
        const res = await fetch(`${src.url}/.well-known/registry.json`).catch(() => undefined);
        if (!res?.ok) throw new Error(`registry ${src.registryId} at ${src.url} unreachable and no key pinned`);
        const wk = (await res.json()) as { registryId: string; publicKey: OkpJwk };
        if (wk.registryId !== src.registryId) throw new Error(`registry at ${src.url} identifies as ${wk.registryId}, configured as ${src.registryId}`);
        this.file.pinned[src.registryId] = { registryId: src.registryId, publicKey: wk.publicKey };
      }
    }
    writeFileSync(join(this.path, "..", "registries.pinned.json"), JSON.stringify(this.pinned, null, 2));
    this.persist();
    return this.pinned;
  }

  private persist() {
    writeFileAtomic(this.path, JSON.stringify(this.file, null, 2));
  }

  private active(): RegistrySource[] {
    return this.sources.filter((s) => !this.hidden.includes(s.registryId));
  }

  get(usdot: string): (RegistryRecord & OutOfBand) | undefined {
    const first = this.attestations(usdot)[0];
    if (!first?.record) return undefined;
    return { ...first.record, ...(this.file.outOfBand[usdot] ?? {}) };
  }

  snapshotHash(usdot: string): string {
    return this.attestations(usdot)[0]?.recordHash ?? "";
  }

  /** The attestations the last refresh relied on, in source order. */
  attestations(usdot: string): RegistryAttestation[] {
    const ids = this.file.reliedOn[usdot] ?? [];
    return ids.map((id) => this.file.attestations[usdot]?.[id]).filter((a): a is RegistryAttestation => !!a && !this.hidden.includes(a.registryId));
  }

  /** Everything held, for introspection. */
  all(): RegistryAttestation[] {
    return Object.values(this.file.attestations).flatMap((m) => Object.values(m));
  }

  private async fetchOne(src: RegistrySource, usdot: string, maxAgeMs: number, now: Date): Promise<{ ok: true; attestation: RegistryAttestation } | { ok: false; why: string }> {
    return this.fetchSigned<RegistryAttestation>(src, `/attest?usdot=${encodeURIComponent(usdot)}`, this.file.attestations[usdot]?.[src.registryId], (a, key) => a.usdot === usdot && verifyAttestation(a, key), maxAgeMs, now);
  }

  private async fetchFiler(src: RegistrySource, insurerId: string, maxAgeMs: number, now: Date): Promise<{ ok: true; attestation: FilerAttestation } | { ok: false; why: string }> {
    return this.fetchSigned<FilerAttestation>(src, `/attest-filer?insurerId=${encodeURIComponent(insurerId)}`, this.file.filers[insurerId]?.[src.registryId], (a, key) => a.insurerId === insurerId && verifyFilerAttestation(a, key), maxAgeMs, now);
  }

  /** One registry's signed word, cached while fresh, else fetched and verified under its pinned key. */
  private async fetchSigned<A extends { registryId: string; asOf: string; upstreamAsOf?: string }>(src: RegistrySource, path: string, have: A | undefined, check: (a: A, key: OkpJwk) => boolean, maxAgeMs: number, now: Date): Promise<{ ok: true; attestation: A } | { ok: false; why: string }> {
    if (have && attestationFreshAt(have, now, maxAgeMs, this.skewMs).ok) return { ok: true, attestation: have };
    const pinned = this.file.pinned[src.registryId];
    if (!pinned) return { ok: false, why: "no key pinned" };
    const res = await fetch(`${src.url}${path}`).catch((e: Error) => e);
    if (res instanceof Error || !res.ok) return { ok: false, why: res instanceof Error ? res.message : `HTTP ${res.status}` };
    const a = (await res.json()) as A;
    if (a.registryId !== src.registryId || !check(a, pinned.publicKey)) return { ok: false, why: "attestation does not verify under the pinned key" };
    const fresh = attestationFreshAt(a, now, maxAgeMs, this.skewMs);
    if (!fresh.ok) return { ok: false, why: `answered asOf ${a.asOf}, ${fresh.ageMs}ms from now (max ${maxAgeMs}, skew ${this.skewMs})` };
    if (have && new Date(a.asOf) < new Date(have.asOf)) return { ok: false, why: `answered asOf ${a.asOf}, earlier than the ${have.asOf} already held` };
    return { ok: true, attestation: a };
  }

  /** The filer attestations the last refresh relied on, in source order. */
  filerAttestations(insurerId: string): FilerAttestation[] {
    const ids = this.file.reliedOnFilers[insurerId] ?? [];
    return ids.map((id) => this.file.filers[insurerId]?.[id]).filter((a): a is FilerAttestation => !!a && !this.hidden.includes(a.registryId));
  }

  /** Ask every registry who this filer is; same quorum and freshness as for an entity. */
  async refreshFiler(insurerId: string, maxAgeMs: number, now = new Date()): Promise<FilerAttestation[]> {
    if (this.stale) {
      const held = this.filerAttestations(insurerId);
      if (held.length === 0) throw new RegistryUnavailable(insurerId, "nothing mirrored (stale mode)", {});
      return held;
    }
    const sources = this.active();
    const outcomes = await Promise.all(sources.map(async (src) => [src.registryId, await this.fetchFiler(src, insurerId, maxAgeMs, now)] as const));
    const fresh: FilerAttestation[] = [];
    const perRegistry: Record<string, string> = {};
    for (const [id, o] of outcomes) {
      if (o.ok) {
        fresh.push(o.attestation);
        perRegistry[id] = `ok (asOf ${o.attestation.asOf})`;
        (this.file.filers[insurerId] ??= {})[id] = o.attestation;
      } else perRegistry[id] = o.why;
    }
    if (fresh.length < Math.max(1, this.quorum)) {
      this.persist();
      throw new RegistryUnavailable(insurerId, `${fresh.length} of ${sources.length} registries answered fresh about filer ${insurerId}; quorum ${this.quorum}`, perRegistry);
    }
    this.file.reliedOnFilers[insurerId] = fresh.map((a) => a.registryId);
    this.persist();
    return fresh;
  }

  /**
   * Ask every registry; keep what verifies and is fresh; require a quorum.
   * Returns the attestations relied on (source order). Under the SIM `stale`
   * fault nothing is fetched and the previous holdings are returned as-is.
   */
  async refresh(usdot: string, maxAgeMs: number, now = new Date()): Promise<RegistryAttestation[]> {
    if (this.stale) {
      const held = this.attestations(usdot);
      if (held.length === 0) throw new RegistryUnavailable(usdot, "nothing mirrored (stale mode)", {});
      return held;
    }
    const sources = this.active();
    const outcomes = await Promise.all(sources.map(async (src) => [src.registryId, await this.fetchOne(src, usdot, maxAgeMs, now)] as const));
    const fresh: RegistryAttestation[] = [];
    const perRegistry: Record<string, string> = {};
    for (const [id, o] of outcomes) {
      if (o.ok) {
        fresh.push(o.attestation);
        perRegistry[id] = `ok (asOf ${o.attestation.asOf})`;
        (this.file.attestations[usdot] ??= {})[id] = o.attestation;
      } else perRegistry[id] = o.why;
    }
    if (fresh.length < Math.max(1, this.quorum)) {
      this.persist();
      const last = this.attestations(usdot).map((a) => a.asOf).sort().at(-1);
      throw new RegistryUnavailable(usdot, `${fresh.length} of ${sources.length} registries answered fresh; quorum ${this.quorum}`, perRegistry, last);
    }
    this.file.reliedOn[usdot] = fresh.map((a) => a.registryId);
    if (!this.file.outOfBand[usdot]) {
      const src = sources.find((s) => s.registryId === fresh[0]!.registryId)!;
      const oob = await fetch(`${src.url}/stub/out-of-band?usdot=${encodeURIComponent(usdot)}`).catch(() => undefined);
      if (oob?.ok) {
        const v = (await oob.json()) as OutOfBand | null;
        if (v) this.file.outOfBand[usdot] = v;
      }
    }
    this.persist();
    return fresh;
  }
}
