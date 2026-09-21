/**
 * The mock registry's own store: a JSON file with the public record plus the
 * two out-of-band stubs (proof-of-control token, vetting flags).
 *
 * STUB: in production the authority is FMCSA's L&I / QCMobile data as
 * mirrored and signed by a vetting provider. This process stands in for that
 * signer: it is a SEPARATE trust domain from the venue — own key, own clock,
 * own data — and the venue only ever sees what it signs.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { filerKeyLicensed, recordHash, regulatorKeyAt, verifyRegulatorAttestation, type InsurerRegistration, type OutOfBand, type RegistryRecord, type RegistryView, type RegulatorAttestation, type RegulatorKey } from "../protocol/registry";
import { verifyRootEventSelf, walkRootLog, type RootEvent } from "../protocol/venue-keys";
import { importPublicKey, verifyJws } from "../protocol/crypto";
import type { ReasonCode } from "../protocol/reasons";

export class FilerRefusal extends Error {
  constructor(public readonly reasonCode: ReasonCode, public readonly evidence: Record<string, unknown>) {
    super(`${reasonCode}: ${JSON.stringify(evidence)}`);
  }
}

export type StoredRecord = RegistryRecord & Required<OutOfBand>;

export class MockRegistry implements RegistryView {
  private records = new Map<string, StoredRecord>();
  /** Registered filers: the insurers that file with this registry, the names they file under, and their keys. */
  private filers = new Map<string, InsurerRegistration>();
  /**
   * The regulators whose word this registry accepts about who is a licensed insurer and which key it files under:
   * each bootstrapped ONCE from its establishment event (operator configuration at the upstream — the law's binding),
   * then followed mechanically through pre-committed rotations. Nobody can hand this registry a new regulator root.
   */
  private regulators = new Map<string, { regulatorId: string; log: RootEvent[] }>();
  private readonly filersPath: string;
  constructor(private readonly path: string, filersPath?: string) {
    this.filersPath = filersPath ?? path.replace(/\.json$/, "") + ".filers.json";
    this.reload();
  }
  reload() {
    const arr: StoredRecord[] = JSON.parse(readFileSync(this.path, "utf8"));
    this.records = new Map(arr.map((r) => [r.usdot, r]));
    if (existsSync(this.filersPath)) {
      const f = JSON.parse(readFileSync(this.filersPath, "utf8")) as { filers: InsurerRegistration[]; regulators: { regulatorId: string; log: RootEvent[] }[] } | InsurerRegistration[];
      const filers = Array.isArray(f) ? f : f.filers;
      this.filers = new Map(filers.map((x) => [x.insurerId, x]));
      this.regulators = new Map((Array.isArray(f) ? [] : f.regulators).map((r) => [r.regulatorId, r]));
    }
  }
  persist() {
    writeFileSync(this.path, JSON.stringify([...this.records.values()], null, 2));
    writeFileSync(this.filersPath, JSON.stringify({ filers: [...this.filers.values()], regulators: [...this.regulators.values()] }, null, 2));
  }
  /** Bootstrap a regulator ONCE from its establishment event. A registry cannot be given a new root for a regulator it knows. */
  pinRegulator(r: { regulatorId: string; establishment: RootEvent }) {
    if (!verifyRootEventSelf(r.establishment) || r.establishment.reason !== "ESTABLISHMENT" || r.establishment.seq !== 0) throw new FilerRefusal("REGULATOR_ROTATION_UNAUTHORIZED", { error: "not a self-signed establishment event (seq 0)", regulatorId: r.regulatorId });
    const cur = this.regulators.get(r.regulatorId);
    if (cur && cur.log[0]?.rootKid !== r.establishment.rootKid) throw new FilerRefusal("REGULATOR_ROTATION_UNAUTHORIZED", { error: "this registry already knows this regulator by another root; a new key arrives only as a pre-committed rotation", regulatorId: r.regulatorId, knownRoot: cur.log[0]?.rootKid, offered: r.establishment.rootKid });
    if (!cur) this.regulators.set(r.regulatorId, { regulatorId: r.regulatorId, log: [r.establishment] });
    this.persist();
  }
  /** The regulator publishes a key event; the registry accepts it iff it extends the walk from the root it bootstrapped. */
  acceptRegulatorEvent(regulatorId: string, event: RootEvent) {
    const cur = this.regulators.get(regulatorId);
    if (!cur) throw new FilerRefusal("REGULATOR_ROTATION_UNAUTHORIZED", { error: "unknown regulator", regulatorId });
    if (cur.log.some((e) => e.seq === event.seq)) return; // already have it
    const walk = walkRootLog(cur.log[0]!.rootPublicKey, [...cur.log, event]);
    const rejected = walk?.rejected.find((x) => x.seq === event.seq);
    if (!walk || rejected || !walk.roots.has(event.rootKid)) throw new FilerRefusal("REGULATOR_ROTATION_UNAUTHORIZED", { error: rejected?.why ?? "event does not extend the regulator's log", regulatorId, seq: event.seq, offeredKid: event.rootKid, currentKid: walk?.current.kid });
    cur.log.push(event);
    this.persist();
  }
  regulatorLog(regulatorId: string): RootEvent[] | null {
    return this.regulators.get(regulatorId)?.log ?? null;
  }
  allRegulators(): RegulatorKey[] {
    return [...this.regulators.values()].map((r) => ({ regulatorId: r.regulatorId, publicKey: walkRootLog(r.log[0]!.rootPublicKey, r.log)?.current.publicKey ?? r.log[0]!.rootPublicKey }));
  }
  private licenseOk(lic: RegulatorAttestation | undefined, legalName: string, publicKeyX: string): Record<string, unknown> | undefined {
    if (!lic) return { error: "no regulator attestation: the registry registers a filer's key on the regulator's word or not at all" };
    const reg = this.regulators.get(lic.regulatorId);
    if (!reg) return { error: `regulator ${lic.regulatorId} is not one this registry pins`, pinned: [...this.regulators.keys()] };
    const k = regulatorKeyAt({ regulatorId: reg.regulatorId, publicKey: reg.log[0]!.rootPublicKey }, reg.log, lic.kid, new Date(lic.asOf));
    if (!k.ok) return { error: `${lic.regulatorId}: ${k.why}`, reasonCode: "REGULATOR_KEY_UNTRUSTED" };
    if (!verifyRegulatorAttestation(lic, k.publicKey!)) return { error: `attestation does not verify under ${lic.regulatorId}'s key ${lic.kid.slice(0, 12)}…` };
    const check = filerKeyLicensed({ kid: lic.publicKey.kid ?? "", publicKey: { ...lic.publicKey, x: publicKeyX }, validFrom: "", licensedBy: lic }, legalName);
    if (!check.ok) return { error: check.why };
    if (lic.publicKey.x !== publicKeyX) return { error: "the regulator's attestation binds a different key than the one presented" };
    return undefined;
  }
  filer(insurerId: string): InsurerRegistration | null {
    return this.filers.get(insurerId) ?? null;
  }
  allFilers(): InsurerRegistration[] {
    return [...this.filers.values()];
  }
  /**
   * The upstream onboards a filer: an insurer's filing name and first key, on its REGULATOR's signed word that this
   * licensed company files under this key — or not at all. A same-named filer is a different account; filings name
   * the account that submitted them.
   */
  registerFiler(reg: { insurerId: string; legalName: string; publicKey: InsurerRegistration["keys"][number]["publicKey"]; kid: string; licensedBy?: RegulatorAttestation; validFrom?: string }) {
    const now = new Date().toISOString();
    if (this.filers.has(reg.insurerId)) throw new FilerRefusal("FILER_ROTATION_UNAUTHORIZED", { error: "filer already registered; a further key is a rotation, licensed by the regulator", insurerId: reg.insurerId });
    const bad = this.licenseOk(reg.licensedBy, reg.legalName, reg.publicKey.x);
    if (bad) throw new FilerRefusal("FILER_UNLICENSED", { ...bad, insurerId: reg.insurerId, legalName: reg.legalName, kid: reg.kid });
    const cur: InsurerRegistration = { insurerId: reg.insurerId, legalName: reg.legalName, naicCode: reg.licensedBy!.naicCode, keys: [{ kid: reg.kid, publicKey: reg.publicKey, validFrom: reg.validFrom ?? now, licensedBy: reg.licensedBy }], registeredAt: now };
    this.filers.set(reg.insurerId, cur);
    this.persist();
  }
  /** A successor key: licensed by the regulator, never appointed by the current key (a thief holding it gains nothing). */
  rotateFilerKey(req: { insurerId: string; publicKey: InsurerRegistration["keys"][number]["publicKey"]; kid: string; licensedBy?: RegulatorAttestation }) {
    const cur = this.filers.get(req.insurerId);
    if (!cur) throw new FilerRefusal("FILER_UNLICENSED", { error: "unknown filer", insurerId: req.insurerId });
    if (!req.licensedBy) throw new FilerRefusal("FILER_ROTATION_UNAUTHORIZED", { error: "no regulator attestation for the successor key: the current key cannot appoint its replacement", insurerId: req.insurerId, kid: req.kid });
    const bad = this.licenseOk(req.licensedBy, cur.legalName, req.publicKey.x);
    if (bad) throw new FilerRefusal("FILER_UNLICENSED", { ...bad, insurerId: req.insurerId, kid: req.kid });
    if (!cur.keys.some((k) => k.kid === req.kid)) cur.keys.push({ kid: req.kid, publicKey: req.publicKey, validFrom: new Date().toISOString(), licensedBy: req.licensedBy });
    this.persist();
  }
  /**
   * Revoke a key: authorized by the key itself (self-revocation harms only a thief) or by the regulator. For a
   * COMPROMISE the effective time may be in the past; the declaration time is now.
   */
  revokeFilerKey(req: { insurerId: string; kid: string; revokedAt: string; reason: "ROTATION" | "COMPROMISE"; authorization: { kind: "CURRENT_KEY"; jws: string } | { kind: "REGULATOR"; attestation: RegulatorAttestation } }) {
    const cur = this.filers.get(req.insurerId);
    const k = cur?.keys.find((x) => x.kid === req.kid);
    if (!cur || !k) throw new FilerRefusal("FILER_UNLICENSED", { error: `filer ${req.insurerId} key ${req.kid} not found` });
    const a = req.authorization;
    if (a.kind === "CURRENT_KEY") {
      const live = cur.keys.filter((x) => !x.revokedAt);
      const signer = live.find((x) => verifyJws(a.jws, importPublicKey(x.publicKey), { action: "filer-key/revoke", insurerId: req.insurerId, kid: req.kid, revokedAt: req.revokedAt, reason: req.reason }).ok);
      if (!signer) throw new FilerRefusal("FILER_ROTATION_UNAUTHORIZED", { error: "revocation not signed by a live key of this filer", insurerId: req.insurerId, kid: req.kid });
    } else {
      const bad = this.licenseOk(a.attestation, cur.legalName, a.attestation.publicKey.x);
      if (bad || !cur.keys.some((x) => x.publicKey.x === a.attestation.publicKey.x)) throw new FilerRefusal("FILER_ROTATION_UNAUTHORIZED", { error: "regulator attestation does not name a key of this filer", ...bad, insurerId: req.insurerId });
    }
    k.revokedAt = req.revokedAt;
    k.declaredAt = new Date().toISOString();
    k.reason = req.reason;
    this.persist();
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
