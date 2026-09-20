/**
 * The venue process's key ring: the root LOG (public), the ACTIVE operational
 * key pair, every certificate and revocation, the pre-commitment to the next
 * root, and a pending next operational key awaiting certification.
 *
 * Root private halves are written once at first start — the current root and
 * the PRE-COMMITTED next root — for the OPERATOR to take custody of; this class
 * never reads them back. In production those files are HSMs and the operator
 * is a ceremony. The process holds only the root's public key and the hash of
 * its successor, which is exactly what makes a stolen root useless for
 * rotating: the thief cannot produce the pre-committed key.
 */
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { exportPrivateJwk, generateKeyPair, importKeyPair, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { writeFileAtomic } from "../protocol/fsatomic";
import { makeResolver, rootCommitment, signCert, signRootEvent, verifyCert, verifyRootEventSelf, type RootEvent, type VenueKeyCert, type VenueKeyHistory, type VenueKeyResolver, type VenueKeyRevocation } from "../protocol/venue-keys";

interface RingFile {
  rootLog: RootEvent[];
  activeKid: string;
  certs: VenueKeyCert[];
  revocations: VenueKeyRevocation[];
}

export class VenueKeyRing {
  private rootLog: RootEvent[];
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
      this.rootLog = f.rootLog;
      this.certs = f.certs;
      this.revocations = f.revocations;
      this.active = importKeyPair(JSON.parse(readFileSync(this.keyPath, "utf8")));
      if (this.active.kid !== f.activeKid) throw new Error("venue key ring inconsistent: active key on disk does not match the ring");
      if (existsSync(this.nextPath)) this.pending = importKeyPair(JSON.parse(readFileSync(this.nextPath, "utf8")));
    } else {
      // First start (the founding ceremony): root R0 and its pre-committed successor R1 go to the operator;
      // the process keeps R0's public key and H(R1). The first operational key is certified by R0.
      const root = generateKeyPair();
      const nextRoot = generateKeyPair();
      writeFileAtomic(join(dir, "venue-root.jwk.json"), JSON.stringify(exportPrivateJwk(root)));
      writeFileAtomic(join(dir, "venue-root-next.jwk.json"), JSON.stringify(exportPrivateJwk(nextRoot)));
      this.rootLog = [signRootEvent(root, { seq: 0, nextRootCommitment: rootCommitment(nextRoot.publicJwk), at: new Date().toISOString(), reason: "ESTABLISHMENT" })];
      this.active = generateKeyPair();
      writeFileAtomic(this.keyPath, JSON.stringify(exportPrivateJwk(this.active)));
      this.certs = [signCert(root, this.active.publicJwk, 0, "INITIAL")];
      this.revocations = [];
      this.persist();
    }
    this.publishPublic();
  }

  private persist() {
    const f: RingFile = { rootLog: this.rootLog, activeKid: this.active.kid, certs: this.certs, revocations: this.revocations };
    writeFileAtomic(this.ringPath, JSON.stringify(f, null, 2));
  }
  private publishPublic() {
    writeFileAtomic(join(this.dir, "venue-root-public.jwk.json"), JSON.stringify(this.rootPublicKey, null, 2));
    writeFileAtomic(join(this.dir, "venue-public.jwk.json"), JSON.stringify(this.active.publicJwk, null, 2));
  }

  /** The CURRENT root's public key. */
  get rootPublicKey(): OkpJwk {
    return this.currentRootEvent().rootPublicKey;
  }
  /** The founding root: what an agent that onboarded on day one pinned. */
  get foundingRootPublicKey(): OkpJwk {
    return this.rootLog[0]!.rootPublicKey;
  }
  currentRootEvent(): RootEvent {
    return [...this.rootLog].sort((a, b) => b.seq - a.seq)[0]!;
  }
  /** The key that signs right now. Callers must not cache it across a rotation. */
  signer(): KeyPair {
    return this.active;
  }
  currentCert(): VenueKeyCert {
    // The most recently issued certificate for the active key (a re-certification supersedes the original).
    return this.certs.filter((c) => c.kid === this.active.kid).sort((a, b) => b.seq - a.seq)[0]!;
  }
  history(): VenueKeyHistory {
    return { venueId: this.venueId, rootPublicKey: this.rootPublicKey, rootLog: this.rootLog, certs: this.certs, revocations: this.revocations, asOf: new Date().toISOString() };
  }
  /** Resolver from the FOUNDING root, so it accepts everything any agent could have pinned. */
  resolver(): VenueKeyResolver {
    return makeResolver(this.foundingRootPublicKey, this.history());
  }
  certsFor(kid: string): VenueKeyCert[] {
    return this.certs.filter((c) => c.kid === kid);
  }
  certFor(kid: string): VenueKeyCert | undefined {
    return this.certsFor(kid).sort((a, b) => b.seq - a.seq)[0];
  }
  revocationFor(kid: string): VenueKeyRevocation | undefined {
    return this.revocations.find((r) => r.kid === kid);
  }
  nextCertSeq(): number {
    return Math.max(...this.certs.map((c) => c.seq)) + 1;
  }

  // ---- operational key rotation ----

  prepare(): { kid: string; publicKey: OkpJwk; seq: number } {
    this.pending = generateKeyPair();
    writeFileAtomic(this.nextPath, JSON.stringify(exportPrivateJwk(this.pending)));
    return { kid: this.pending.kid, publicKey: this.pending.publicJwk, seq: this.nextCertSeq() };
  }
  pendingKid(): string | undefined {
    return this.pending?.kid;
  }
  pendingSigner(): KeyPair | undefined {
    return this.pending;
  }
  install(cert: VenueKeyCert, revocationOfOld?: VenueKeyRevocation): { previousKid: string } {
    const previousKid = this.active.kid;
    if (cert.kid === this.active.kid) return { previousKid };
    const r = this.resolver();
    if (!r.add(cert)) throw new Error("certificate not signed by a trusted venue root");
    if (revocationOfOld && !r.revoke(revocationOfOld)) throw new Error("revocation not signed by a trusted venue root");
    if (!this.pending || this.pending.kid !== cert.kid) throw new Error("certificate does not name the pending key");
    if (!this.certs.some((c) => c.rootSignature === cert.rootSignature)) this.certs.push(cert);
    if (revocationOfOld && !this.revocations.some((x) => x.kid === revocationOfOld.kid)) this.revocations.push(revocationOfOld);
    writeFileAtomic(this.keyPath, JSON.stringify(exportPrivateJwk(this.pending)));
    this.active = this.pending;
    this.pending = undefined;
    this.persist();
    if (existsSync(this.nextPath)) unlinkSync(this.nextPath);
    this.publishPublic();
    return { previousKid };
  }

  // ---- root rotation (pre-rotation) ----

  /**
   * Install a root rotation event. Authority: the new root's public key must
   * hash to the CURRENT root's pre-commitment, and the event must be signed by
   * the new root. Nothing the current root signs can authorize a different
   * successor. On COMPROMISE the operator also supplies a re-certification of
   * the venue's genuine operational key under the new root (carrying its
   * original validFrom), so its whole tenure stays trusted while any key the
   * thief certified does not. Idempotent by root kid.
   */
  installRoot(event: RootEvent, recert?: VenueKeyCert): { previousRootKid: string; recertified?: string } {
    const cur = this.currentRootEvent();
    if (event.rootKid === cur.rootKid) return { previousRootKid: cur.previousRootKid ?? cur.rootKid };
    if (event.previousRootKid !== cur.rootKid) throw new Error(`root event does not link to the current root (${cur.rootKid.slice(0, 12)}…)`);
    if (event.seq !== cur.seq + 1) throw new Error("root event sequence is not the next one");
    if (rootCommitment(event.rootPublicKey) !== cur.nextRootCommitment) throw new Error("new root does not match the pre-committed successor");
    if (!verifyRootEventSelf(event)) throw new Error("root event is not signed by the new root");
    if (event.reason === "COMPROMISE" && !event.compromisedAt) throw new Error("COMPROMISE root event must carry compromisedAt");
    let recertified: string | undefined;
    if (recert) {
      if (recert.kid !== this.active.kid) throw new Error("re-certification does not name the active operational key");
      if (!verifyCert(recert, event.rootPublicKey)) throw new Error("re-certification is not signed by the new root");
      if (!this.certs.some((c) => c.rootSignature === recert.rootSignature)) this.certs.push(recert);
      recertified = recert.kid;
    }
    this.rootLog.push(event);
    this.persist();
    this.publishPublic();
    return { previousRootKid: cur.rootKid, recertified };
  }
}
