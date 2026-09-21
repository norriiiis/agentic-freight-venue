/**
 * Where a process gets its private key. The protocols never mint authority —
 * every key that matters is replaced by someone who does not use it — but
 * the SIGNING key of each process still has to come from somewhere. This is
 * the seam a deployment fills:
 *
 *   file:   a JWK on disk in the data dir (the default; what the simulator uses)
 *   env:    a JWK injected by a secrets manager (KEY_<NAME>=…), never written to disk
 *   remote: a signer that holds the key elsewhere (KMS, HSM) — the seam is declared
 *           here and REFUSED at startup, because this codebase signs synchronously;
 *           adopting a remote signer means making sign() async end to end, which is
 *           the one change a KMS forces and this skeleton has not made.
 *
 * Roots (venue root, regulator root, pre-committed next roots) belong in
 * custody the process cannot reach; a provider that hands a process its root
 * is misconfigured, and the venue key ring refuses to start that way.
 */
import { existsSync, readFileSync } from "node:fs";
import { writeFileAtomic } from "./fsatomic";
import { exportPrivateJwk, generateKeyPair, importKeyPair, type KeyPair, type OkpJwk } from "./crypto";

export interface KeyProvider {
  kind: "file" | "env" | "remote";
  /** Load the named key, or undefined if it does not exist yet. */
  load(name: string): KeyPair | undefined;
  /** Persist a newly generated key (a provider that cannot — env, remote — throws: keys are provisioned, not minted). */
  save(name: string, kp: KeyPair): void;
}

export class FileKeyProvider implements KeyProvider {
  readonly kind = "file" as const;
  constructor(private readonly pathFor: (name: string) => string) {}
  load(name: string): KeyPair | undefined {
    const p = this.pathFor(name);
    return existsSync(p) ? importKeyPair(JSON.parse(readFileSync(p, "utf8")) as OkpJwk) : undefined;
  }
  save(name: string, kp: KeyPair) {
    writeFileAtomic(this.pathFor(name), JSON.stringify(exportPrivateJwk(kp)));
  }
}

/** KEY_<NAME> holds the private JWK; nothing is written to disk. Rotation re-provisions the variable. */
export class EnvKeyProvider implements KeyProvider {
  readonly kind = "env" as const;
  constructor(private readonly env: Record<string, string | undefined> = process.env) {}
  private varFor(name: string) {
    return `KEY_${name.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
  }
  load(name: string): KeyPair | undefined {
    const v = this.env[this.varFor(name)];
    return v ? importKeyPair(JSON.parse(v) as OkpJwk) : undefined;
  }
  save(name: string): void {
    throw new Error(`env key provider cannot mint keys: provision ${this.varFor(name)} from your secrets manager`);
  }
}

export class RemoteKeyProvider implements KeyProvider {
  readonly kind = "remote" as const;
  constructor(readonly url: string) {}
  load(name: string): KeyPair | undefined {
    throw new Error(`remote signer at ${this.url} for ${name}: not supported — signing is synchronous in this codebase; a KMS requires async sign() end to end`);
  }
  save(): void {
    throw new Error("remote signer: keys are provisioned, not minted");
  }
}

/** Load or, for a file provider, mint on first run. */
export function loadOrCreate(p: KeyProvider, name: string): KeyPair {
  const have = p.load(name);
  if (have) return have;
  if (p.kind !== "file") throw new Error(`no key ${name} provisioned (${p.kind} provider)`);
  const kp = generateKeyPair();
  p.save(name, kp);
  return kp;
}

/** Choose a provider from configuration: KEY_PROVIDER=file|env|remote (default file). */
export function keyProviderFromEnv(pathFor: (name: string) => string, env: Record<string, string | undefined> = process.env): KeyProvider {
  switch (env.KEY_PROVIDER ?? "file") {
    case "env": return new EnvKeyProvider(env);
    case "remote": return new RemoteKeyProvider(env.KEY_SIGNER_URL ?? "");
    default: return new FileKeyProvider(pathFor);
  }
}
