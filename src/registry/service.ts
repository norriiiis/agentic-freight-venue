/**
 * The registry as a signing authority. Every answer about an entity is a
 * RegistryAttestation: the public record and the registry's own clock, under
 * the registry's key. A venue relays these; it cannot forge, backdate or
 * refresh them.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { exportPrivateJwk, generateKeyPair, importKeyPair, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { signAttestation, type OutOfBand, type RegistryAttestation, type RegistryRecord } from "../protocol/registry";
import { MockRegistry } from "./store";

export class RegistryService {
  readonly kp: KeyPair;
  readonly store: MockRegistry;
  /** SIM fault: the registry is unreachable (answers 503). */
  unavailable = false;
  /** SIM fault: a mirror that stopped syncing its upstream — it keeps signing the records it had, with a fresh clock. Stale or lying: the same from outside. */
  private frozen?: Map<string, RegistryRecord | null>;
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
    const record = this.frozen ? (this.frozen.has(usdot) ? this.frozen.get(usdot)! : null) : this.store.publicRecord(usdot);
    return signAttestation(this.kp, this.registryId, usdot, record, now);
  }

  /** SIM: freeze what this mirror serves at the current records (or thaw). */
  freeze(on: boolean) {
    this.frozen = on ? new Map(this.store.all().map((r) => [r.usdot, this.store.publicRecord(r.usdot)])) : undefined;
  }
  get isFrozen(): boolean {
    return !!this.frozen;
  }

  records(): RegistryRecord[] {
    return this.store.all().map((r) => this.store.publicRecord(r.usdot)!);
  }

  /** STUB: what a proof-of-control challenge and a vetting provider would return out of band. Never attested. */
  outOfBand(usdot: string): OutOfBand | undefined {
    return this.store.outOfBand(usdot);
  }

  status() {
    return { registryId: this.registryId, kid: this.kp.kid, records: this.store.all().length, attestationsServed: this.served, unavailable: this.unavailable, frozen: this.isFrozen };
  }
}
