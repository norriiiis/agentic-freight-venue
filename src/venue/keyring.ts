/**
 * The venue process's key ring: the root PUBLIC key, the ACTIVE operational
 * key pair, every certificate and revocation the root has issued, and a
 * pending next key awaiting certification.
 *
 * The root PRIVATE key is written once at first start to `venue-root.jwk.json`
 * for the OPERATOR to take custody of; this class never reads it back. In
 * production that file is an HSM and the operator is a ceremony.
 */
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { exportPrivateJwk, generateKeyPair, importKeyPair, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { writeFileAtomic } from "../protocol/fsatomic";
import { makeResolver, signCert, type VenueKeyCert, type VenueKeyHistory, type VenueKeyResolver, type VenueKeyRevocation } from "../protocol/venue-keys";

interface RingFile {
  rootPublicKey: OkpJwk;
  activeKid: string;
  certs: VenueKeyCert[];
  revocations: VenueKeyRevocation[];
}

export class VenueKeyRing {
  readonly rootPublicKey: OkpJwk;
  private active: KeyPair;
  private certs: VenueKeyCert[];
  private revocations: VenueKeyRevocation[];
  private pending?: KeyPair;
  private readonly ringPath: string;
  private readonly keyPath: string;
  private readonly nextPath: string;

  constructor(private readonly dir: string, readonly venueId: string) {
    this.ringPath = join(dir, "venue-keyring.json");
    this.keyPath = join(dir, "venue-key.jwk.json");
    this.nextPath = join(dir, "venue-key.next.jwk.json");
    if (existsSync(this.ringPath)) {
      const f = JSON.parse(readFileSync(this.ringPath, "utf8")) as RingFile;
      this.rootPublicKey = f.rootPublicKey;
      this.certs = f.certs;
      this.revocations = f.revocations;
      this.active = importKeyPair(JSON.parse(readFileSync(this.keyPath, "utf8")));
      if (this.active.kid !== f.activeKid) throw new Error("venue key ring inconsistent: active key on disk does not match the ring");
      if (existsSync(this.nextPath)) this.pending = importKeyPair(JSON.parse(readFileSync(this.nextPath, "utf8")));
    } else {
      // First start: create the root (handed to the operator), certify the first operational key, forget the root private half.
      const root = generateKeyPair();
      writeFileAtomic(join(dir, "venue-root.jwk.json"), JSON.stringify(exportPrivateJwk(root)));
      this.rootPublicKey = root.publicJwk;
      this.active = generateKeyPair();
      writeFileAtomic(this.keyPath, JSON.stringify(exportPrivateJwk(this.active)));
      this.certs = [signCert(root, this.active.publicJwk, 0, "INITIAL")];
      this.revocations = [];
      this.persist();
    }
    writeFileAtomic(join(dir, "venue-root-public.jwk.json"), JSON.stringify(this.rootPublicKey, null, 2));
    writeFileAtomic(join(dir, "venue-public.jwk.json"), JSON.stringify(this.active.publicJwk, null, 2));
  }

  private persist() {
    const f: RingFile = { rootPublicKey: this.rootPublicKey, activeKid: this.active.kid, certs: this.certs, revocations: this.revocations };
    writeFileAtomic(this.ringPath, JSON.stringify(f, null, 2));
  }

  /** The key that signs right now. Callers must not cache it across a rotation. */
  signer(): KeyPair {
    return this.active;
  }
  currentCert(): VenueKeyCert {
    return this.certs.find((c) => c.kid === this.active.kid)!;
  }
  history(): VenueKeyHistory {
    return { venueId: this.venueId, rootPublicKey: this.rootPublicKey, certs: this.certs, revocations: this.revocations, asOf: new Date().toISOString() };
  }
  resolver(): VenueKeyResolver {
    return makeResolver(this.rootPublicKey, this.history());
  }
  certFor(kid: string): VenueKeyCert | undefined {
    return this.certs.find((c) => c.kid === kid);
  }
  revocationFor(kid: string): VenueKeyRevocation | undefined {
    return this.revocations.find((r) => r.kid === kid);
  }

  /** Step 1 of rotation: generate the next key; the operator certifies its public half. Persisted so a crash cannot lose it. */
  prepare(): { kid: string; publicKey: OkpJwk; seq: number } {
    this.pending = generateKeyPair();
    writeFileAtomic(this.nextPath, JSON.stringify(exportPrivateJwk(this.pending)));
    return { kid: this.pending.kid, publicKey: this.pending.publicJwk, seq: this.currentCert().seq + 1 };
  }
  pendingKid(): string | undefined {
    return this.pending?.kid;
  }
  pendingSigner(): KeyPair | undefined {
    return this.pending;
  }

  /**
   * Step 2: install a root-certified pending key as ACTIVE. Idempotent by kid
   * (a crash after install re-runs harmlessly). The old private key is deleted.
   */
  install(cert: VenueKeyCert, revocationOfOld?: VenueKeyRevocation): { previousKid: string } {
    const previousKid = this.active.kid;
    if (cert.kid === this.active.kid) return { previousKid };
    const r = makeResolver(this.rootPublicKey);
    if (!r.add(cert)) throw new Error("certificate not signed by the venue root");
    if (revocationOfOld && !r.revoke(revocationOfOld)) throw new Error("revocation not signed by the venue root");
    if (!this.pending || this.pending.kid !== cert.kid) throw new Error("certificate does not name the pending key");
    if (!this.certs.some((c) => c.kid === cert.kid)) this.certs.push(cert);
    if (revocationOfOld && !this.revocations.some((x) => x.kid === revocationOfOld.kid)) this.revocations.push(revocationOfOld);
    writeFileAtomic(this.keyPath, JSON.stringify(exportPrivateJwk(this.pending)));
    this.active = this.pending;
    this.pending = undefined;
    this.persist();
    if (existsSync(this.nextPath)) unlinkSync(this.nextPath);
    writeFileAtomic(join(this.dir, "venue-public.jwk.json"), JSON.stringify(this.active.publicJwk, null, 2));
    return { previousKid };
  }
}
