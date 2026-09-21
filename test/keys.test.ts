import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EnvKeyProvider, FileKeyProvider, RemoteKeyProvider, keyProviderFromEnv, loadOrCreate } from "../src/protocol/keys";
import { exportPrivateJwk, generateKeyPair } from "../src/protocol/crypto";

describe("key provider seam", () => {
  it("file: mints on first run, reloads the same key after", () => {
    const dir = mkdtempSync(join(tmpdir(), "fv-keys-"));
    const p = new FileKeyProvider((n) => join(dir, `${n}.jwk.json`));
    const a = loadOrCreate(p, "venue-key");
    const b = loadOrCreate(p, "venue-key");
    expect(b.kid).toBe(a.kid);
  });
  it("env: provisioned, never minted, never written", () => {
    const kp = generateKeyPair();
    const p = new EnvKeyProvider({ KEY_VENUE_KEY: JSON.stringify(exportPrivateJwk(kp)) });
    expect(loadOrCreate(p, "venue-key").kid).toBe(kp.kid);
    expect(() => loadOrCreate(p, "other-key")).toThrow(/no key other-key provisioned/);
  });
  it("remote: declared and refused, because signing is synchronous here", () => {
    const p = keyProviderFromEnv(() => "", { KEY_PROVIDER: "remote", KEY_SIGNER_URL: "https://kms.example" });
    expect(p).toBeInstanceOf(RemoteKeyProvider);
    expect(() => p.load("venue-key")).toThrow(/async sign/);
  });
});
