/**
 * The commitment artifact: a self-contained, signed record of what two
 * parties agreed. Either party can hand this file to an auditor, an insurer
 * or a court months later and it verifies WITHOUT the venue's cooperation:
 *
 *   - both parties' ACCEPT messages are included verbatim, each carrying the
 *     signer's detached JWS over the message (which contains the full terms)
 *   - both parties' credentials are included, binding each key to a registry
 *     entity, signed by the venue's issuer key
 *   - the REGISTRY's signed word about each party, as the venue held it at
 *     commitment: a verifier reruns the standing check over it and holds the
 *     venue to the freshness policy it declares — "the venue checked" is not
 *     a claim anyone has to take on trust
 *   - the venue's attestation signature covers the whole bundle
 *   - a ledger inclusion pointer lets anyone with the ledger file confirm
 *     the record's position in the chain
 *
 * Trust anchors an independent verifier needs: the venue's public key (which
 * a production venue would publish in a transparency log / DNS / well-known
 * URL). The artifact embeds it for convenience; a verifier SHOULD pin it.
 */
import { randomUUID } from "node:crypto";
import { DEFAULT_CLOCK } from "../protocol/clock";
import { canonicalize, hashObject } from "../protocol/canonical";
import { importPublicKey, signJws, verifyJws, type KeyPair, type OkpJwk } from "../protocol/crypto";
import { dataPart, type Message } from "../protocol/a2a";
import { verifyMessageSignature } from "../protocol/envelope";
import { termsHash, type AcceptPayload, type Terms } from "../protocol/freight";
import type { Credential, CredentialStatusEntry } from "../protocol/types";
import { makeResolver, type RootEvent, type VenueKeyCert, type VenueKeyHistory } from "../protocol/venue-keys";
import { verifyEquivocationProof, verifyReceipt, witnessedAsOf, type EquivocationProof, type WitnessKey, type Witnessed } from "../protocol/witness";
import { findInclusion, verifyNotice, verifyPromise, type BrokenPromiseProof, type InclusionPromise, type PendingNotice } from "../protocol/inclusion";
import { attestationFreshAt, contradictedBy, coverageAssuredThrough, filerContradictedBy, filerKeyOfRecord, filingShownByInsurer, filingsShownBy, insurerContradictedBy, insurerOfRecord, insurerStanding, keyEventsShownBy, regulatorLogOfRecord, renewalWindow, satisfiesRenewal, standing, standingProjection, verifyAttestation, verifyFilerAttestation, verifyInsurerAttestation, verifyRegulatorLogAttestation, type FilerAttestation, type FilingEvidence, type InsurerAttestation, type InsurerKey, type RegistryAttestation, type RegistryKey, type RegulatorKey, type RegulatorLogAttestation } from "../protocol/registry";
import { verifyChain, type LedgerEntry } from "./chain";
import type { ReasonCode } from "../protocol/reasons";

export interface GuaranteeSummary {
  guaranteeId: string;
  coveredAmountUsd: number;
  premiumUsd: number;
  scope: string[];
  exclusions: string[];
  conditions: string[];
}

export interface VenueAttestation {
  kid: string;
  at: string;
  /** Detached JWS over { contentHash } — the hash of everything in the artifact except attestations and the ledger pointer. */
  jws: string;
}

export interface CommitmentArtifact {
  schema: "freight-venue/commitment-artifact/v2";
  commitmentId: string;
  createdAt: string;
  /**
   * The venue's key material a verifier needs: the root (to pin) and the
   * root-signed certificates for every venue kid this artifact references
   * (attestation keys and credential issuer keys).
   */
  venue: { venueId: string; rootPublicKey: OkpJwk; rootLog?: RootEvent[]; certs: VenueKeyCert[] };
  terms: Terms;
  termsHash: string;
  acceptances: { broker: Message; carrier: Message };
  credentials: { broker: Credential; carrier: Credential };
  /**
   * The registries' signed word on each party that the venue relied on at
   * commitment — one attestation per registry — with the registries it
   * consulted and its own freshness and quorum policy. Absent only in
   * artifacts from before registry attestations existed; a verifier that pins
   * a registry key treats absence as REGISTRY_ATTESTATION_MISSING.
   */
  registry?: { registries: RegistryKey[]; attestations: { broker: RegistryAttestation[]; carrier: RegistryAttestation[] }; policy: { maxAgeMs: number; quorum: number } };
  /**
   * Each party's own insurer's signed word (the COI on file at commitment), if presented: the origin of the fact the
   * registries mirror. `renewal` marks a CONDITIONAL commitment: the carrier's word falls short of delivery, and a
   * renewal signed at or after `earliestSignedAt` must be on file by `dueBy` (pickup) or the venue voids.
   */
  insurance?: { broker?: InsurerAttestation; carrier?: InsurerAttestation; renewal?: { earliestSignedAt: string; dueBy: string; requiredBy: string }; filers?: { broker?: FilerAttestation[]; carrier?: FilerAttestation[] }; regulators?: RegulatorLogAttestation[] };
  underwriting: { decision: "GUARANTEED" | "UNGUARANTEED"; riskScore?: number; guarantee?: GuaranteeSummary; reasonCode?: ReasonCode };
  /** Position this record will occupy in the venue ledger (known before append, so it is inside the attestation). */
  ledger: { seq: number; prevHash: string };
  /**
   * Attestations are ADDITIVE: the original, plus any re-attestation under a
   * new venue key after a compromise. A verifier needs at least one that is
   * both valid and trusted at its signing time.
   */
  venueAttestations: VenueAttestation[];
  /** Filled after append; NOT covered by attestations. Inclusion is checked against the ledger file. */
  ledgerEntryHash?: string;
}

/** What an attestation signs and what the ledger entry commits to: the artifact content, minus attestations and the post-append pointer. */
export function artifactHash(a: Omit<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash"> & Partial<Pick<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash">>): string {
  const { ledgerEntryHash: _x, venueAttestations: _y, ...rest } = a;
  return hashObject(rest);
}

export function attest(content: Omit<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash">, venueKp: KeyPair, at = new Date()): VenueAttestation {
  return { kid: venueKp.kid, at: at.toISOString(), jws: signJws({ contentHash: artifactHash(content) }, venueKp, { typ: "commitment-attestation+jws" }, true) };
}

export function buildArtifact(
  input: Omit<CommitmentArtifact, "schema" | "commitmentId" | "createdAt" | "venueAttestations" | "ledgerEntryHash">,
  venueKp: KeyPair,
  commitmentId = `cmt_${randomUUID()}`,
): CommitmentArtifact {
  const content: Omit<CommitmentArtifact, "venueAttestations" | "ledgerEntryHash"> = {
    schema: "freight-venue/commitment-artifact/v2",
    commitmentId,
    createdAt: new Date().toISOString(),
    ...input,
  };
  return { ...content, venueAttestations: [attest(content, venueKp)] };
}

/**
 * The two parties as witnesses: their credential-bound keys, straight from the
 * artifact. A verifier who is one of the parties pins the other's key because
 * it TRANSACTED with it — no trust in the venue is needed to do so.
 */
export function partyWitnessKeys(a: CommitmentArtifact): WitnessKey[] {
  return [
    { witnessId: a.credentials.broker.subject.agentId, publicKey: a.credentials.broker.subject.publicKey },
    { witnessId: a.credentials.carrier.subject.agentId, publicKey: a.credentials.carrier.subject.publicKey },
  ];
}

/** Re-attest an existing artifact under a (new) venue key, optionally swapping in re-issued credentials and adding the certs a verifier will need. */
export function reattestArtifact(a: CommitmentArtifact, venueKp: KeyPair, opts: { credentials?: CommitmentArtifact["credentials"]; addCerts?: VenueKeyCert[] } = {}): CommitmentArtifact {
  const certs = [...a.venue.certs];
  for (const c of opts.addCerts ?? []) if (!certs.some((x) => x.kid === c.kid)) certs.push(c);
  const { venueAttestations, ledgerEntryHash, ...content } = a;
  const next = { ...content, credentials: opts.credentials ?? a.credentials, venue: { ...a.venue, certs } };
  // Replacing credentials or certs changes the content hash, so earlier attestations no longer bind: keep only those that still verify.
  const kept = venueAttestations.filter((x) => hashObject(next) === artifactHash(a) ? true : false);
  return { ...next, venueAttestations: [...kept, attest(next, venueKp)], ledgerEntryHash };
}

export interface ArtifactCheck {
  name: string;
  ok: boolean;
  detail?: string;
}
export interface ArtifactVerification {
  ok: boolean;
  reasonCode?: ReasonCode;
  checks: ArtifactCheck[];
  /** When pinned witnesses vouch for the status list / key history: the time up to which they are known complete. */
  witnessed?: { statusAsOf?: string; keysAsOf?: string; by: string[] };
  summary: { loadRef: string; rateUsd: number; broker: string; carrier: string; guaranteed: boolean };
}

/**
 * Independent verification. Pin the venue ROOT key (`pinnedRootKey`) to refuse
 * the embedded one (recommended). Pass the venue's published key history to
 * learn of venue-key compromises, and its credential status list to learn of
 * agent-key compromises; without them, a compromise declared after signing is
 * invisible offline. Every check is reported, not just the first failure.
 */
export type StatusListInput = CredentialStatusEntry[] | (Partial<Witnessed> & { entries: CredentialStatusEntry[] });
export type KeyHistoryInput = Partial<Pick<VenueKeyHistory, "certs" | "revocations" | "rootLog">> & Partial<Witnessed>;

/**
 * Freshness. A status list or key history says nothing about events after the
 * moment it was taken. With pinned WITNESS keys the verifier learns the latest
 * time W an independent party cosigned the head the list projects, and
 * requires W ≥ asOf − maxStalenessMs — otherwise a later revocation or
 * compromise would be invisible and the verdict is STATUS_STALE, not "trusted".
 * `asOf` is the moment being judged (a pickup, a claim, the commitment; default
 * now); a witness receipt is always in the past, so judging "now" needs a
 * tolerance (default 15 minutes) and judging a past moment can be strict (0).
 * With the ledger too, it checks the list is complete up to that witnessed head.
 * `minWitnesses` (default 1) is the quorum: that many distinct pinned witnesses
 * must have cosigned the SAME head — a venue showing different ledgers to
 * different witnesses cannot assemble one. `requiredWitnesses` names witnesses
 * that must be among them: the counterparty (whose key is in this artifact —
 * see partyWitnessKeys), the verifier itself, its insurer. A venue that
 * controls k witnesses defeats "any k"; it cannot conjure a named one.
 * `equivocationProofs` are witness-signed proofs of a split view; any valid
 * one for this venue voids everything. `brokenPromises` likewise: the venue
 * promised to record a notice and a witnessed chain past the deadline lacks
 * it. `inclusionPromises` the verifier holds itself are checked against the
 * ledger. `pendingNotices` are source-signed notices a pinned witness holds
 * that the venue never acknowledged: not proof of anything, but status is
 * uncertain until they appear (NOTICE_PENDING).
 *
 * Registry. `registryKeys` pins the registry (vetting-provider) signers —
 * the verifier's choice, not the venue's. Per party, the attestations the
 * venue embedded from pinned registries must verify, be about the committed
 * party, and be no older at `createdAt` than `maxRegistryAgeMs` (default: the
 * policy the venue itself declares); at least `minRegistries` of them
 * (default: the venue's declared quorum) must qualify, including every
 * `requiredRegistries` id (REGISTRY_QUORUM_NOT_MET names the missing one — a
 * venue cannot conjure a registry's signature, nor quietly drop one the
 * verifier insists on). The standing check is then RERUN over EVERY
 * qualifying attestation, and they must be unanimous: a lapse any registry
 * had already published is REGISTRY_CONTRADICTS_COMMITMENT, the venue's own
 * evidence against it; registries that differ on the facts standing rests
 * on without differing on the verdict are REGISTRY_DISAGREEMENT, which
 * withholds "fine". `currentAttestations` — the registries' word fetched
 * today — answer the same question without the venue's help: cancellation
 * dates are history.
 *
 * Accountability. Every attestation states when its mirror last synced; a
 * mirror that claims a sync after a cancellation's FILING date and served a
 * record without it has signed a falsehood, and any word showing the filing
 * — another mirror's in the artifact, any mirror's today, or the insurer's
 * — is the proof: REGISTRY_FALSE_ATTESTATION. Collusion has to be total and
 * permanent to be safe, and one honest word later convicts it.
 *
 * The origin. `insurerKeys` pins insurers; a party's own insurer's signed
 * word in the artifact (or `currentInsurerAttestations`, fetched today) is
 * checked like a mirror's — no set of mirrors can forge it, and a disclosed
 * cancellation at or before delivery is INSURER_CONTRADICTS_COMMITMENT.
 * `requireInsurerAttestation` demands it (INSURER_ATTESTATION_MISSING), and
 * assured through the delivery window — its statutory notice period from
 * when it spoke. A word that falls short makes the commitment CONDITIONAL:
 * a renewal signed at or after delivery − notice must be on file by pickup.
 * `renewals` (or INSURANCE_RENEWAL entries in `ledger`) supply it; judged at
 * `asOf`, the verdict is INSURANCE_RENEWAL_PENDING before the deadline,
 * INSURANCE_RENEWAL_NOT_PRESENTED after it, and
 * INSURANCE_NOT_ASSURED_THROUGH_DELIVERY when no renewal could ever help.
 *
 * The origin's honesty. An insurer's word counts only if it is the insurer
 * OF RECORD's — the registry's filing names the insurer (`insurerName` on
 * the pinned key, or in the attestation) and the policy
 * (INSURER_NOT_OF_RECORD) — and not a signed falsehood: an insurer that
 * signed "no cancellation" after the date the registry received its own
 * filing is convicted by the mirrors' word, symmetric with how the mirrors
 * are convicted by its (INSURER_FALSE_ATTESTATION). `requireInsurerUndertaking`
 * accepts only an attestation carrying the insurer's signed promise not to
 * deny a covered loss for an undisclosed lapse (INSURER_UNDERTAKING_MISSING):
 * a certificate is a belief; an undertaking is a liability.
 *
 * Whose key. The insurer's key is derived from the registries' FILER
 * directory embedded in the artifact (`insurance.filers`): filer
 * attestations that verify under the pinned registry keys, a quorum of them
 * fresh at commitment, unanimous that the signing key was the filer's at
 * signing time. `insurerKeys` pinned out of band are a cross-check, not a
 * substitute — a verifier need pin nothing beyond the registries, and no
 * venue operator's configuration is consulted (INSURER_KEY_NOT_OF_RECORD).
 * `currentFilerAttestations` — the registries' word today — catch a key
 * revoked as of a time before the signature, and a mirror in the artifact
 * that hid a revocation (REGISTRY_FALSE_ATTESTATION).
 *
 * How the key got there. A filer's key is registered on its REGULATOR's
 * signed word that this licensed insurer files under this key, and the
 * registration carries that word; a key without it, or with one naming
 * another name or key, is FILER_UNLICENSED. `regulatorKeys` pins the
 * regulators — ANY key each regulator ever had: the regulator's key-event
 * log, as the registries attest it in the artifact (`insurance.regulators`)
 * or today (`currentRegulatorAttestations`), is walked from the pinned key
 * through pre-committed rotations, and the licensing signature must be by a
 * key so reached and not since declared compromised as of before it
 * (REGULATOR_KEY_UNTRUSTED). Without pinned regulators the registries'
 * word anchors the log — k independent mirrors say who the regulator is —
 * and the check says so.
 */
export function verifyArtifact(
  a: CommitmentArtifact,
  opts: { pinnedRootKey?: OkpJwk; keyHistory?: KeyHistoryInput; statusList?: StatusListInput; witnessKeys?: WitnessKey[]; minWitnesses?: number; requiredWitnesses?: string[]; equivocationProofs?: EquivocationProof[]; inclusionPromises?: InclusionPromise[]; brokenPromises?: BrokenPromiseProof[]; pendingNotices?: PendingNotice[]; noticeSources?: WitnessKey[]; registryKeys?: RegistryKey[]; minRegistries?: number; requiredRegistries?: string[]; maxRegistryAgeMs?: number; currentAttestations?: RegistryAttestation[]; insurerKeys?: InsurerKey[]; requireInsurerAttestation?: boolean; requireInsurerUndertaking?: boolean; currentInsurerAttestations?: InsurerAttestation[]; currentFilerAttestations?: FilerAttestation[]; regulatorKeys?: RegulatorKey[]; currentRegulatorAttestations?: RegulatorLogAttestation[]; renewals?: InsurerAttestation[]; asOf?: Date; maxStalenessMs?: number; ledger?: LedgerEntry[]; now?: Date } = {},
): ArtifactVerification {
  const checks: ArtifactCheck[] = [];
  const push = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail });
  const statusEntries: CredentialStatusEntry[] | undefined = Array.isArray(opts.statusList) ? opts.statusList : opts.statusList?.entries;
  const statusPub = opts.statusList && !Array.isArray(opts.statusList) ? opts.statusList : undefined;
  const keysPub = opts.keyHistory;
  const witnessed: ArtifactVerification["witnessed"] = opts.witnessKeys ? { by: [] } : undefined;
  const root = opts.pinnedRootKey ?? a.venue.rootPublicKey;
  // The pinned root may be older than the one the artifact names; the root log (embedded and/or supplied) must walk from it.
  const resolver = makeResolver(root, { certs: [...a.venue.certs, ...(opts.keyHistory?.certs ?? [])], revocations: opts.keyHistory?.revocations ?? [], rootLog: [...(a.venue.rootLog ?? []), ...(opts.keyHistory?.rootLog ?? [])] });
  if (opts.pinnedRootKey) {
    const embeddedKid = a.venue.rootPublicKey.kid ?? "";
    push("venue.root.pinned-reaches-embedded", opts.pinnedRootKey.x === a.venue.rootPublicKey.x || resolver.rootTrusted(embeddedKid), `embedded root ${embeddedKid.slice(0, 12)}… is not the pinned root and no pre-rotation chain from the pinned root reaches it`);
  }
  if (opts.witnessKeys) {
    const asOf = opts.asOf ?? opts.now ?? new Date();
    const tolerance = opts.maxStalenessMs ?? DEFAULT_CLOCK.witnessStalenessMs;
    const needed = new Date(asOf.getTime() - tolerance);
    const k = Math.max(1, opts.minWitnesses ?? 1);
    const proofs = (opts.equivocationProofs ?? []).filter((p) => p.venueId === a.venue.venueId && verifyEquivocationProof(p, opts.witnessKeys!));
    if (opts.equivocationProofs) push("venue.no-equivocation", proofs.length === 0, proofs.length ? `${proofs.length} witness-signed proof(s) that this venue showed different ledgers (seq ${proofs.map((p) => p.seq).join(", ")}): nothing it publishes is trustworthy` : "");
    const judge = (label: "status" | "keys", pub: Partial<Witnessed> | undefined) => {
      if (!pub) return;
      if (!pub.venueId || pub.witnessed === undefined) { push(`${label}.witnessed`, false, "publication carries no witnessed head (pre-witness format or stripped)"); return; }
      const w = witnessedAsOf({ venueId: pub.venueId, witnessed: pub.witnessed }, opts.witnessKeys!, { minWitnesses: k, required: opts.requiredWitnesses });
      push(`${label}.witnessed`, w.by.length > 0, w.by.length ? `head seq ${w.head!.seq} cosigned by ${w.by.join(", ")}` : "no receipt by a pinned witness");
      if (k > 1 || w.by.length || opts.requiredWitnesses?.length) push(`${label}.witness-quorum`, w.quorum, w.quorum ? `${w.by.length} pinned witness(es) on the same head (min ${k}${opts.requiredWitnesses?.length ? `, required: ${opts.requiredWitnesses.join(", ")}` : ""})` : w.missingRequired.length ? `required witness(es) have NOT cosigned this head: ${w.missingRequired.join(", ")} — the venue cannot conjure a named witness's signature` : `only ${w.by.length} pinned witness(es) cosigned this head; ${k} required — a venue showing different ledgers to different witnesses cannot assemble a quorum on one head`);
      if (!w.at) return;
      if (w.at) {
        push(`${label}.fresh-as-of`, w.at >= needed, w.at >= needed ? `witnessed ${w.at.toISOString()}, judging ${asOf.toISOString()}${tolerance ? ` (tolerance ${tolerance}ms)` : " (strict)"}` : `witnessed only until ${w.at.toISOString()}; nothing after that is known — asked about ${asOf.toISOString()}${tolerance ? ` with ${tolerance}ms tolerance` : " (strict)"}`);
        if (label === "status") witnessed!.statusAsOf = w.at.toISOString();
        else witnessed!.keysAsOf = w.at.toISOString();
        for (const b of w.by) if (!witnessed!.by.includes(b)) witnessed!.by.push(b);
      }
      if (opts.ledger && w.head) {
        const chain = verifyChain(opts.ledger, { rootPublicKey: opts.pinnedRootKey ?? a.venue.rootPublicKey, revocations: keysPub?.revocations });
        const at = opts.ledger.find((e) => e.seq === w.head!.seq);
        const headOk = !!at && at.hash === w.head.hash;
        if (label === "status" && statusEntries) {
          const onLedger = opts.ledger.filter((e) => e.type === "CREDENTIAL_STATUS" && e.seq <= w.head!.seq && (e.payload as { status: CredentialStatusEntry | null }).status).map((e) => (e.payload as { status: CredentialStatusEntry }).status);
          const missing = onLedger.filter((x) => !statusEntries.some((y) => y.credentialId === x.credentialId && y.status === x.status && y.at === x.at));
          push("status.complete-to-witnessed-head", chain.ok && headOk && missing.length === 0, !chain.ok ? `ledger: ${chain.error}` : !headOk ? "witnessed head is not in the supplied ledger" : missing.length ? `${missing.length} status entr${missing.length === 1 ? "y" : "ies"} on the ledger before the witnessed head are missing from the list` : `${onLedger.length} status entries, all present`);
        } else if (label === "keys") {
          push("keys.complete-to-witnessed-head", chain.ok && headOk, !chain.ok ? `ledger: ${chain.error}` : !headOk ? "witnessed head is not in the supplied ledger" : "");
        }
      }
    };
    judge("status", statusPub);
    judge("keys", keysPub);

    // ---- inclusion: promises the venue made, and notices it never answered
    const venueKeyFor = (kid: string) => resolver.key(kid);
    const broken = (opts.brokenPromises ?? []).filter((b) => b.promise.venueId === a.venue.venueId && verifyPromise(b.promise, venueKeyFor) && opts.witnessKeys!.some((w) => w.witnessId === b.headReceipt.witnessId && verifyReceipt(b.headReceipt, w.publicKey)) && new Date(b.headReceipt.at) > new Date(b.promise.includeBy) && (!opts.ledger || !findInclusion(b.promise, opts.ledger.filter((e) => e.seq <= b.headReceipt.seq))));
    if (opts.brokenPromises) push("venue.honours-inclusion-promises", broken.length === 0, broken.length ? `${broken.length} promise(s) broken: ${broken.map((b) => `${b.promise.noticeId} promised by ${b.promise.includeBy}, absent at seq ${b.headReceipt.seq} (${b.headReceipt.witnessId}, ${b.headReceipt.at})`).join("; ")}` : "");
    if (opts.inclusionPromises && opts.ledger) {
      const w = statusPub ? witnessedAsOf({ venueId: statusPub.venueId!, witnessed: statusPub.witnessed ?? null }, opts.witnessKeys!, { minWitnesses: k, required: opts.requiredWitnesses }) : undefined;
      const upTo = w?.head?.seq ?? Number.MAX_SAFE_INTEGER;
      for (const p of opts.inclusionPromises) {
        if (p.venueId !== a.venue.venueId || !verifyPromise(p, venueKeyFor)) { push(`inclusion[${p.noticeId}].promise-valid`, false, "promise not signed by a certified venue key"); continue; }
        const entry = findInclusion(p, opts.ledger.filter((e) => e.seq <= upTo));
        const deadlinePassed = !!w?.at && w.at > new Date(p.includeBy);
        push(`inclusion[${p.noticeId}]`, !!entry || !deadlinePassed, entry ? `recorded at seq ${entry.seq}` : deadlinePassed ? `promised by ${p.includeBy}; witnessed chain to seq ${upTo} at ${w!.at!.toISOString()} does not contain it` : `not yet recorded; deadline ${p.includeBy} not passed as of the witnessed time`);
      }
    }
    const pending = (opts.pendingNotices ?? []).filter((pn) => opts.noticeSources?.some((src) => src.witnessId === pn.notice.sourceId && verifyNotice(pn.notice, src.publicKey)) && (!opts.ledger || !opts.ledger.some((e) => (e.payload as { noticeHash?: string }).noticeHash === hashObject(pn.notice))));
    if (opts.pendingNotices) push("status.no-pending-notices", pending.length === 0, pending.length ? `${pending.length} source-signed notice(s) lodged with ${[...new Set(pending.map((p) => p.lodgedWith))].join(", ")} that the venue never acknowledged: ${pending.map((p) => `${p.notice.assertion} ${p.notice.subject.credentialId ?? p.notice.subject.usdot ?? p.notice.subject.agentId} (${p.submissionOutcome})`).join("; ")}` : "");
  }
  push("venue.certs.signed-by-root", a.venue.certs.length > 0 && a.venue.certs.every((c) => resolver.cert(c.kid) !== undefined), `${resolver.kids().length}/${a.venue.certs.length} embedded certificates verify against the root`);

  // 1. Attestations: valid signature by a certified key, trusted at signing time. At least one must pass both.
  const content = artifactHash(a);
  let anyTrusted = false;
  a.venueAttestations.forEach((att, i) => {
    const key = resolver.key(att.kid);
    const sig = key ? verifyJws(att.jws, importPublicKey(key), { contentHash: content }) : { ok: false, error: "attesting key not certified by the root" };
    push(`venue.attestation[${i}].signature`, sig.ok, sig.error);
    const why = resolver.untrustedAt(att.kid, new Date(att.at));
    push(`venue.attestation[${i}].trusted-at-signing`, sig.ok && !why, why);
    if (sig.ok && !why) anyTrusted = true;
  });
  push("venue.attestation.any-trusted", anyTrusted, "no attestation is both valid and by a key trusted at its signing time");

  // 2. termsHash is the hash of the terms
  push("terms.hash", termsHash(a.terms) === a.termsHash, `computed ${termsHash(a.terms).slice(0, 12)}… vs recorded ${a.termsHash.slice(0, 12)}…`);

  // 3. Each acceptance: is an ACCEPT over these exact terms, signed by the credential-bound key
  for (const side of ["broker", "carrier"] as const) {
    const msg = a.acceptances[side];
    const cred = a.credentials[side];
    const data = dataPart(msg) as AcceptPayload | undefined;
    push(`${side}.accept.type`, data?.type === "ACCEPT", `got ${data?.type}`);
    push(`${side}.accept.terms-match`, !!data && canonicalize(data.terms) === canonicalize(a.terms), "terms inside ACCEPT differ from artifact terms");
    push(`${side}.accept.termsHash-match`, data?.termsHash === a.termsHash);
    const sig = verifyMessageSignature(msg, cred.subject.publicKey);
    push(`${side}.accept.signature`, sig.ok, sig.error);
    push(`${side}.accept.signer-is-credential-subject`, (msg.metadata as { senderAgentId?: string })?.senderAgentId === cred.subject.agentId && (msg.metadata as { credentialId?: string })?.credentialId === cred.credentialId);
    // 4. Credential genuine: issuer signature by the venue key named in the credential, trusted when it issued
    const { issuerSignature, ...credUnsigned } = cred;
    const issuerKey = resolver.key(cred.issuer.kid);
    const cs = issuerKey ? verifyJws(issuerSignature, importPublicKey(issuerKey), credUnsigned) : { ok: false, error: `issuer key ${cred.issuer.kid.slice(0, 12)}… not certified by the root` };
    push(`${side}.credential.issuer-signature`, cs.ok, cs.error);
    const issuedWhy = resolver.untrustedAt(cred.issuer.kid, new Date(cred.signedAt ?? cred.issuedAt));
    push(`${side}.credential.issuer-trusted-at-issuance`, cs.ok && !issuedWhy, issuedWhy);
    const termsEntity = side === "broker" ? a.terms.brokerEntity : a.terms.carrierEntity;
    push(`${side}.credential.entity-matches-terms`, cred.subject.entity.usdot === termsEntity.usdot && (termsEntity.mc ?? cred.subject.entity.mc) === cred.subject.entity.mc);
    const termsAgent = side === "broker" ? a.terms.brokerAgentId : a.terms.carrierAgentId;
    push(`${side}.credential.agent-matches-terms`, cred.subject.agentId === termsAgent);
    // Note: credential validity AT SIGNING TIME is what matters for a historical record. Later expiry or
    // a later routine key rotation does not invalidate an old signature; a compromise declared effective
    // BEFORE the signature does — which needs the venue's published status list.
    const signedAt = new Date((msg.metadata as { ts?: string })?.ts ?? 0);
    push(`${side}.credential.valid-at-signing`, signedAt >= new Date(cred.issuedAt) && signedAt < new Date(cred.expiresAt), `signed ${signedAt.toISOString()}, valid ${cred.issuedAt}..${cred.expiresAt}`);
    if (statusEntries) {
      const st = statusEntries.find((x) => x.credentialId === cred.credentialId);
      const compromisedBefore = !!st?.compromisedAt && signedAt >= new Date(st.compromisedAt);
      const revokedBefore = st?.status === "REVOKED" && signedAt >= new Date(st.at);
      push(`${side}.credential.trusted-at-signing`, !compromisedBefore && !revokedBefore, compromisedBefore ? `key declared compromised as of ${st!.compromisedAt}, signature at ${signedAt.toISOString()}` : revokedBefore ? `revoked ${st!.at}, signature at ${signedAt.toISOString()}` : st ? `status ${st.status} (${st.reason}) after signing — does not affect this signature` : "");
    }
  }

  // 5. The registries' word: what the venue relied on, from whom, fresh enough, and unanimous about standing.
  const reg = a.registry;
  const regKeys = opts.registryKeys ?? reg?.registries ?? [];
  const keyFor = (id: string) => regKeys.find((k) => k.registryId === id)?.publicKey;
  if (opts.registryKeys || reg) {
    const reliedAt = new Date(a.createdAt);
    const through = new Date(a.terms.delivery.windowEnd);
    push("registry.attestations-present", !!reg, opts.registryKeys ? "the artifact carries no registry attestation: the venue's claim to have checked standing cannot be verified" : "");
    if (reg) {
      const maxAge = opts.maxRegistryAgeMs ?? reg.policy.maxAgeMs;
      const k = Math.max(1, opts.minRegistries ?? reg.policy.quorum ?? 1);
      const required = opts.requiredRegistries ?? [];
      if (!opts.registryKeys) push("registry.keys-pinned", true, "using the registry keys EMBEDDED by the venue — its choice of registries; pin your own");
      for (const side of ["broker", "carrier"] as const) {
        const cred = a.credentials[side];
        const atts = reg.attestations[side] ?? [];
        const qualifying: RegistryAttestation[] = [];
        const staleOnly: string[] = [];
        for (const att of atts) {
          const key = keyFor(att.registryId);
          if (!key) { push(`${side}.registry[${att.registryId}]`, true, "not a pinned registry — ignored"); continue; }
          const signed = verifyAttestation(att, key);
          const subject = att.usdot === cred.subject.entity.usdot && (!att.record || att.record.usdot === att.usdot);
          const fresh = attestationFreshAt(att, reliedAt, maxAge);
          const ok = signed && subject && fresh.ok;
          push(`${side}.registry[${att.registryId}]`, ok, ok ? `signed, about ${att.usdot}, ${fresh.ageMs}ms old at commitment (policy ${maxAge}ms)` : !signed ? "attestation does not verify under the pinned key for this registry" : !subject ? `attestation is about ${att.usdot}, credential binds ${cred.subject.entity.usdot}` : `registry word was ${fresh.ageMs}ms old at commitment; policy allows ${maxAge}ms — a cancellation filed in between was invisible to the venue, and it did not ask`);
          if (ok) qualifying.push(att);
          else if (signed && subject) staleOnly.push(att.registryId);
        }
        const ids = qualifying.map((q) => q.registryId);
        const missingRequired = required.filter((r) => !ids.includes(r));
        const quorum = qualifying.length >= k && missingRequired.length === 0;
        push(`${side}.registry.quorum`, quorum, quorum ? `${qualifying.length} pinned registr${qualifying.length === 1 ? "y" : "ies"} (${ids.join(", ")}) qualify; ${k} required${required.length ? `, incl. ${required.join(", ")}` : ""}` : missingRequired.length ? `required registr${missingRequired.length === 1 ? "y" : "ies"} ${missingRequired.join(", ")} absent from the artifact — the venue cannot conjure a registry's signature, and a verifier who names one is not bound by the venue's choice of registries` : `only ${qualifying.length} pinned registr${qualifying.length === 1 ? "y" : "ies"} qualify (${ids.join(", ") || "none"}); ${k} required${staleOnly.length ? ` — ${staleOnly.join(", ")} signed but stale` : ""}`);
        if (qualifying.length === 0) continue;
        const verdicts = qualifying.map((q) => ({ id: q.registryId, asOf: q.asOf, st: standing(q.record, reliedAt, { hazmat: a.terms.load.hazmat, through }) }));
        const lapsed = verdicts.filter((v) => !v.st.ok);
        push(`${side}.registry.standing-at-commitment`, lapsed.length === 0, lapsed.length ? `${lapsed.map((v) => `${v.id}: ${v.st.reasonCode} (as of ${v.asOf})`).join("; ")}${lapsed.length < verdicts.length ? `; ${verdicts.filter((v) => v.st.ok).map((v) => v.id).join(", ")} showed standing — a stale or lying mirror, and the rule is unanimity: any registry's word of a lapse blocks` : ""} — the registries' own record, which the venue held, shows this at ${reliedAt.toISOString()}` : `in standing per ${verdicts.map((v) => v.id).join(", ")}`);
        const projections = new Set(qualifying.map((q) => standingProjection(q.record)));
        push(`${side}.registry.consistent`, projections.size <= 1, projections.size > 1 ? `${projections.size} different views of the facts standing rests on (authorities, filings, operating status) among ${ids.join(", ")}: at least one mirror is stale or wrong` : "");
      }
    }
    // The registries' word today. Cancellation dates are history: a later record answers whether the party was in standing THEN.
    for (const side of ["broker", "carrier"] as const) {
      const usdot = a.credentials[side].subject.entity.usdot;
      const current = (opts.currentAttestations ?? []).filter((c) => c.usdot === usdot);
      if (current.length === 0) continue;
      const verdicts: { id: string; asOf: string; st: ReturnType<typeof standing> }[] = [];
      for (const cur of current) {
        const key = keyFor(cur.registryId);
        const signed = !!key && verifyAttestation(cur, key);
        push(`${side}.registry.current[${cur.registryId}].signed`, signed, key ? "current registry attestation does not verify under the pinned key" : `no pinned key for registry ${cur.registryId}`);
        if (signed) verdicts.push({ id: cur.registryId, asOf: cur.asOf, st: standing(cur.record, reliedAt, { hazmat: a.terms.load.hazmat, through }) });
      }
      if (verdicts.length === 0) continue;
      const lapsed = verdicts.filter((v) => !v.st.ok);
      push(`${side}.registry.standing-per-current-record`, lapsed.length === 0, lapsed.length ? `${lapsed.map((v) => `${v.id} (as of ${v.asOf}): ${v.st.reasonCode}`).join("; ")} — the registry's record today shows this party was NOT in good standing at ${reliedAt.toISOString()}${lapsed.length < verdicts.length ? `; ${verdicts.filter((v) => v.st.ok).map((v) => v.id).join(", ")} say otherwise — split word, and any lapse blocks` : ""}` : `in good standing at commitment per ${verdicts.map((v) => `${v.id} (as of ${v.asOf})`).join(", ")}`);
    }
  }

  // 6. The origin's word (the party's own insurer), and accountability for every mirror the venue relied on.
  const insurerRelevant = !!(opts.insurerKeys || opts.requireInsurerAttestation || a.insurance || opts.currentInsurerAttestations);
  if (reg || insurerRelevant) {
    const reliedAt = new Date(a.createdAt);
    const through = new Date(a.terms.delivery.windowEnd);
    const pinnedInsurer = (id: string) => opts.insurerKeys?.find((k) => k.insurerId === id);
    // The registries' word on a filer: verified under pinned registry keys, quorum, fresh at commitment; unanimous on the key at `at`.
    const k = Math.max(1, opts.minRegistries ?? reg?.policy.quorum ?? 1);
    const maxAge = opts.maxRegistryAgeMs ?? reg?.policy.maxAgeMs ?? DEFAULT_CLOCK.registryMaxAgeMs;
    // The regulators' key logs per the registries: verified under pinned registry keys, fresh at commitment (or today), unanimous on the head.
    const regulatorWord = (regulatorId: string): { keys?: RegulatorKey; log?: RootEvent[]; anchoredBy: string; why?: string } => {
      const all = [...(a.insurance?.regulators ?? []), ...(opts.currentRegulatorAttestations ?? [])].filter((r) => r.regulatorId === regulatorId);
      const qualifying = all.filter((r) => { const key = regKeys.find((x) => x.registryId === r.registryId)?.publicKey; return !!key && verifyRegulatorLogAttestation(r, key) && (opts.currentRegulatorAttestations?.includes(r) || attestationFreshAt(r, reliedAt, maxAge).ok); });
      const rec = regulatorLogOfRecord(qualifying);
      const pinned = opts.regulatorKeys?.find((r) => r.regulatorId === regulatorId);
      if (pinned) return { keys: pinned, log: rec.ok ? rec.log : undefined, anchoredBy: `your pinned ${regulatorId} key${rec.ok ? `, log per ${qualifying.map((q) => q.registryId).join(", ")}` : " alone (no registry word on its log)"}` };
      if (rec.ok && qualifying.filter((q) => !opts.currentRegulatorAttestations?.includes(q)).length >= k) return { keys: rec.anchor, log: rec.log, anchoredBy: `the registries' word (${qualifying.map((q) => q.registryId).join(", ")}) — pin the regulator to anchor it yourself` };
      return { anchoredBy: "nothing", why: rec.why ?? `${qualifying.length} registries vouch for who ${regulatorId} is; ${k} required` };
    };
    const filerWord = (side: "broker" | "carrier", insurerId: string, kid: string, at: Date): { ok: boolean; key?: OkpJwk; legalName?: string; why?: string; unlicensed?: string; regulatorKeyUntrusted?: boolean; qualifying: FilerAttestation[] } => {
      const all = [...(a.insurance?.filers?.[side] ?? []), ...(opts.currentFilerAttestations ?? [])].filter((f) => f.insurerId === insurerId);
      const qualifying = all.filter((f) => { const key = regKeys.find((r) => r.registryId === f.registryId)?.publicKey; return !!key && verifyFilerAttestation(f, key) && (opts.currentFilerAttestations?.includes(f) || attestationFreshAt(f, reliedAt, maxAge).ok); });
      const embeddedQualifying = qualifying.filter((f) => !opts.currentFilerAttestations?.includes(f));
      if (embeddedQualifying.length < k && !opts.currentFilerAttestations?.length) return { ok: false, why: `${embeddedQualifying.length} pinned registr${embeddedQualifying.length === 1 ? "y" : "ies"} vouch for who ${insurerId} is (${embeddedQualifying.map((f) => f.registryId).join(", ") || "none"}); ${k} required — the artifact does not establish whose key signed`, qualifying };
      // Resolve every regulator the filer's keys cite, from a pinned key or the registries' anchor, through its log.
      const regulatorIds = [...new Set(qualifying.flatMap((f) => f.registration?.keys.map((x) => x.licensedBy?.regulatorId).filter((x): x is string => !!x) ?? []))];
      const rkeys: RegulatorKey[] = [];
      const rlogs: Record<string, RootEvent[]> = {};
      for (const id of regulatorIds) {
        const w = regulatorWord(id);
        if (w.keys) rkeys.push(w.keys);
        if (w.log) rlogs[id] = w.log;
        // Unanchored (no pinned key, no registry word) is reported, not failed: the licensing binding is then checked for presence and consistency only, as it was before regulators had logs.
        push(`${side}.regulator[${id}].anchored`, !!w.keys || !opts.regulatorKeys, w.keys ? `anchored by ${w.anchoredBy}` : opts.regulatorKeys ? `no anchor for regulator ${id}: ${w.why}` : `NOT anchored — regulator signature unchecked (pin the regulator, or supply the registries' word on it): ${w.why}`);
      }
      const r = filerKeyOfRecord(qualifying, kid, at, rkeys.length || opts.regulatorKeys ? rkeys : undefined, rlogs);
      return { ok: r.ok, key: r.key?.publicKey, legalName: r.legalName, why: r.why, unlicensed: r.unlicensed, regulatorKeyUntrusted: r.regulatorKeyUntrusted, qualifying };
    };
    const insurerKey = (id: string, kid: string, at: Date, side: "broker" | "carrier"): { key?: OkpJwk; legalName?: string; source: string; why?: string } => {
      const fw = filerWord(side, id, kid, at);
      if (fw.qualifying.length) push(`${side}.filer[${id}].licensed`, !fw.unlicensed, fw.unlicensed ?? "");
      if (fw.regulatorKeyUntrusted) push(`${side}.filer[${id}].regulator-key-trusted`, false, fw.why ?? "");
      const pinned = pinnedInsurer(id);
      if (fw.ok && pinned && pinned.publicKey.x !== fw.key!.x) return { source: "conflict", why: `the key you pinned for ${id} (${pinned.publicKey.kid?.slice(0, 12)}…) is not the one the registries list for that filer at ${at.toISOString()} (${fw.key!.kid?.slice(0, 12)}…)` };
      if (fw.ok) return { key: fw.key, legalName: pinned?.insurerName ?? fw.legalName, source: `registries (${fw.qualifying.map((f) => f.registryId).join(", ")})` };
      if (pinned && fw.qualifying.length === 0) return { key: pinned.publicKey, legalName: pinned.insurerName, source: "pinned out of band (no registry word on this filer in the artifact)" };
      return { source: "registries", why: fw.why, legalName: pinned?.insurerName ?? fw.legalName };
    };
    for (const side of ["broker", "carrier"] as const) {
      const cred = a.credentials[side];
      const usdot = cred.subject.entity.usdot;
      const embedded = a.insurance?.[side];
      // Accountability for the mirrors' word on filers: a mirror claiming a sync after a revocation it does not show.
      const filerEvidence = [...(a.insurance?.filers?.[side] ?? []), ...(opts.currentFilerAttestations ?? [])].flatMap(keyEventsShownBy);
      for (const f of a.insurance?.filers?.[side] ?? []) {
        if (!regKeys.some((r) => r.registryId === f.registryId)) continue;
        const proof = filerContradictedBy(f, filerEvidence);
        push(`${side}.registry[${f.registryId}].true-when-signed-about-filer`, !proof, proof ? `${f.registryId} claimed sync at ${proof.claimedSyncAt} and showed ${proof.insurerId}'s key ${proof.missing.kid.slice(0, 12)}… unrevoked; ${proof.missing.source} shows it revoked ${proof.missing.revokedAt}: a signed falsehood` : "");
      }
      const evidence: FilingEvidence[] = [];
      const verdicts: { label: string; a: InsurerAttestation }[] = [];
      // Only a carrier's BIPD is required by policy; a broker's bond insurer may attest the same way.
      const required = !!opts.requireInsurerAttestation && side === "carrier";
      if (required || embedded) push(`${side}.insurer.attestation-present`, !!embedded, "no signed word from the party's own insurer is in the artifact — the venue relied on registry mirrors alone");
      if (embedded) {
        const ik = insurerKey(embedded.insurerId, embedded.kid, new Date(embedded.asOf), side);
        const key = ik.key;
        const signed = !!key && verifyInsurerAttestation(embedded, key);
        push(`${side}.insurer[${embedded.insurerId}].key-of-record`, !!key, ik.why ?? `no word on whose key ${embedded.insurerId} signs under: pin the registries (the artifact carries their filer directory) or the insurer`);
        push(`${side}.insurer[${embedded.insurerId}].signed`, !key || signed, key ? `insurer attestation does not verify under the key ${ik.source} give${ik.source.startsWith("registries") ? "" : "s"} for this filer` : "");
        push(`${side}.insurer[${embedded.insurerId}].subject`, embedded.usdot === usdot, `insurer attestation is about ${embedded.usdot}, credential binds ${usdot}`);
        // Of record: the registry's filing names the insurer and the policy; anyone else's signature is not the origin's word.
        const recs = [...(reg?.attestations[side] ?? []), ...(opts.currentAttestations ?? []).filter((c) => c.usdot === usdot)].map((x) => x.record);
        const ofRecord = recs.length ? insurerOfRecord(embedded, recs, ik.legalName ?? embedded.insurerName) : undefined;
        if (ofRecord) push(`${side}.insurer[${embedded.insurerId}].of-record`, ofRecord.ok, ofRecord.ok ? `policy ${embedded.policyNumber} filed by ${ofRecord.filing!.insurer} per ${ofRecord.shownBy} registry record(s)` : ofRecord.why);
        // Symmetric accountability: the origin signed after the registry received its own filing and did not disclose it.
        const mirrorFilings = [...(reg?.attestations[side] ?? []), ...(opts.currentAttestations ?? []).filter((c) => c.usdot === usdot)].flatMap(filingsShownBy);
        const lie = insurerContradictedBy(embedded, mirrorFilings);
        push(`${side}.insurer[${embedded.insurerId}].true-when-signed`, !lie, lie ? `${embedded.insurerId} signed "${embedded.cancellation ? `cancellation effective ${embedded.cancellation.effectiveDate}` : "no cancellation"}" at ${embedded.asOf}; the registry (${lie.missing.source}) received its cancellation filing on ${lie.missing.cancellationFiledDate} (effective ${lie.missing.cancellationDate}): a signed falsehood by the origin` : "");
        if (opts.requireInsurerUndertaking && side === "carrier") push(`${side}.insurer.undertaking`, embedded.undertaking === "NO_DENIAL_FOR_UNDISCLOSED_LAPSE", embedded.undertaking ? "" : `the insurer's word is a certificate (its belief), not an undertaking: no signed promise not to deny a covered loss for an undisclosed lapse`);
        if (!!key && signed && !lie && (!ofRecord || ofRecord.ok)) {
          verdicts.push({ label: `${embedded.insurerId} (in artifact, as of ${embedded.asOf})`, a: embedded });
          const st = insurerStanding(embedded, reliedAt, through);
          push(`${side}.insurer.standing-at-commitment`, st.ok, st.ok ? `in force per the insurer's own word; assured through ${st.assuredThrough}` : `${st.reasonCode}: the party's own insurer's word, which the venue held, shows this — ${JSON.stringify(st.evidence).slice(0, 200)}`);
          if (required || a.insurance?.renewal) {
            const pickup = new Date(a.terms.pickup.windowStart);
            const w = renewalWindow(embedded, pickup, through);
            const judged = opts.asOf ?? opts.now ?? new Date();
            if (w.reachesDelivery) push(`${side}.insurer.assured-through-delivery`, true, `assured through ${w.assuredThrough} ≥ delivery ${through.toISOString()}`);
            else {
              // The statutory window: only a renewal signed at or after delivery − notice can reach delivery, and it must be on file by pickup.
              const fromLedger = (opts.ledger ?? []).filter((e) => e.type === "INSURANCE_RENEWAL" && (e.payload as { commitmentId?: string }).commitmentId === a.commitmentId).map((e) => (e.payload as { attestation: InsurerAttestation }).attestation);
              const candidates = [...(opts.renewals ?? []), ...fromLedger].filter((r) => { if (r.usdot !== usdot) return false; const key = insurerKey(r.insurerId, r.kid, new Date(r.asOf), side).key; return !!key && verifyInsurerAttestation(r, key); });
              const bad = candidates.map((r) => ({ r, st: insurerStanding(r, new Date(r.asOf), through) })).find((x) => !x.st.ok);
              const good = candidates.find((r) => satisfiesRenewal(r, w, through) && insurerStanding(r, new Date(r.asOf), through).ok);
              if (bad) push(`${side}.insurer.standing-per-renewal`, false, `${bad.st.reasonCode}: the renewal the insurer signed at ${bad.r.asOf} discloses a cancellation effective ${bad.r.cancellation?.effectiveDate} — before delivery ${through.toISOString()}`);
              else if (good) { push(`${side}.insurer.assured-through-delivery`, true, `renewed: insurer's word signed ${good.asOf} (window from ${w.earliestSignedAt}) assures through ${coverageAssuredThrough(good).toISOString()} ≥ delivery`); for (const r of [good]) verdicts.push({ label: `${r.insurerId} (renewal, as of ${r.asOf})`, a: r }); }
              else if (!w.possible) push(`${side}.insurer.assured-through-delivery`, false, `no word signed before pickup ${w.dueBy} can reach delivery ${through.toISOString()}: transit outruns the ${embedded.noticeDays}-day notice period`);
              else if (judged <= new Date(w.dueBy)) push(`${side}.insurer.renewal-due`, false, `conditional: the insurer's word on file (as of ${embedded.asOf}) assures only through ${w.assuredThrough}; a renewal signed at or after ${w.earliestSignedAt} must be on file by pickup ${w.dueBy}${a.insurance?.renewal ? " (the venue bound itself to void otherwise)" : " (the venue recorded no such condition — it did not require the origin's word)"}; judged at ${judged.toISOString()}`);
              else push(`${side}.insurer.renewal-not-presented`, false, `pickup ${w.dueBy} passed with no renewal signed at or after ${w.earliestSignedAt} on record; the word on file assured only through ${w.assuredThrough}, delivery ${through.toISOString()} — the venue should have voided${a.insurance?.renewal ? "" : ", and had recorded no condition to void on"}`);
            }
          }
        }
      }
      for (const cur of (opts.currentInsurerAttestations ?? []).filter((c) => c.usdot === usdot)) {
        const key = insurerKey(cur.insurerId, cur.kid, new Date(cur.asOf), side).key;
        const signed = !!key && verifyInsurerAttestation(cur, key);
        push(`${side}.insurer.current[${cur.insurerId}].signed`, signed, key ? "current insurer attestation does not verify under the insurer's key of record" : `no word on whose key ${cur.insurerId} signs under at ${cur.asOf}`);
        if (!signed) continue;
        verdicts.push({ label: `${cur.insurerId} (today, as of ${cur.asOf})`, a: cur });
        const st = insurerStanding(cur, reliedAt, through);
        push(`${side}.insurer.standing-per-current-word`, st.ok, st.ok ? `in force at commitment per the insurer's word today` : `${st.reasonCode}: the insurer's own word today shows coverage was ${st.reasonCode === "INSURANCE_LAPSED" ? "not in force at commitment" : "ending before delivery"} — ${JSON.stringify(st.evidence).slice(0, 200)}`);
      }
      // Accountability: every filing anyone's signed word shows, against every mirror's sync claim in the artifact.
      for (const v of verdicts) { const f = filingShownByInsurer(v.a); if (f) evidence.push(f); }
      for (const x of reg?.attestations[side] ?? []) evidence.push(...filingsShownBy(x));
      for (const x of (opts.currentAttestations ?? []).filter((c) => c.usdot === usdot)) evidence.push(...filingsShownBy(x));
      for (const x of reg?.attestations[side] ?? []) {
        if (!regKeys.some((k) => k.registryId === x.registryId)) continue;
        const proof = contradictedBy(x, evidence);
        const corroborated = proof ? [...new Set(evidence.filter((e) => e.policyNumber === proof.missing.policyNumber && e.cancellationFiledDate === proof.missing.cancellationFiledDate).map((e) => e.source))] : [];
        push(`${side}.registry[${x.registryId}].true-when-signed`, !proof, proof ? `${x.registryId} claimed sync at ${proof.claimedSyncAt} and served policy ${proof.missing.policyNumber} without the cancellation filed ${proof.missing.cancellationFiledDate} (effective ${proof.missing.cancellationDate}) that ${corroborated.join(", ")} show${corroborated.length === 1 ? "s" : ""}: a signed falsehood, or ${corroborated.join("/")} fabricated a filing — the two signatures decide between them` : "");
      }
    }
  }

  const failed = checks.filter((c) => !c.ok);
  const reasonCode = verdictFor(failed);
  return {
    ok: failed.length === 0,
    reasonCode,
    checks,
    witnessed,
    summary: {
      loadRef: a.terms.loadRef,
      rateUsd: a.terms.rateUsd,
      broker: `${a.credentials.broker.subject.entity.legalName} (${a.credentials.broker.subject.entity.mc ?? a.credentials.broker.subject.entity.usdot})`,
      carrier: `${a.credentials.carrier.subject.entity.legalName} (${a.credentials.carrier.subject.entity.mc ?? a.credentials.carrier.subject.entity.usdot})`,
      guaranteed: a.underwriting.decision === "GUARANTEED",
    },
  };
}

// ---------------------------------------------------------------- the verdict
//
// One artifact can fail many checks; the verdict names the one that matters
// most. The order is a declared table, most damning first: proof that the
// venue lied outranks proof that a source lied outranks a policy the verifier
// set outranks staleness. Two verdicts are "graded" — NOTICE_PENDING and
// INSURANCE_RENEWAL_PENDING mean "not yet fine", and apply only when nothing
// worse also failed. test/verdict.test.ts pins this order.

type Failed = { name: string; detail?: string };
const witnessKind = (c: Failed) => /\.(witnessed|witness-quorum|fresh-as-of|complete-to-witnessed-head)$/.test(c.name);
const perRegistry = (c: Failed) => /\.registry\[[^\]]+\]$/.test(c.name) || /\.registry\.current\[[^\]]+\]\.signed$/.test(c.name);

/** Predicates over the failed checks, in precedence order. The first that matches names the verdict. */
export const VERDICT_ORDER: { code: ReasonCode; when: (failed: Failed[]) => boolean }[] = [
  { code: "VENUE_EQUIVOCATION", when: (f) => f.some((c) => c.name === "venue.no-equivocation") },
  { code: "INCLUSION_PROMISE_BROKEN", when: (f) => f.some((c) => c.name === "venue.honours-inclusion-promises" || (c.name.startsWith("inclusion[") && !c.name.endsWith(".promise-valid"))) },
  { code: "NOTICE_PENDING", when: (f) => f.some((c) => c.name === "status.no-pending-notices") && f.every((c) => c.name === "status.no-pending-notices" || witnessKind(c)) },
  { code: "REGISTRY_FALSE_ATTESTATION", when: (f) => f.some((c) => /\.registry\[[^\]]+\]\.true-when-signed(-about-filer)?$/.test(c.name)) },
  { code: "INSURER_FALSE_ATTESTATION", when: (f) => f.some((c) => /\.insurer\[[^\]]+\]\.true-when-signed$/.test(c.name)) },
  { code: "INSURER_CONTRADICTS_COMMITMENT", when: (f) => f.some((c) => /\.insurer\.standing-(at-commitment|per-current-word|per-renewal)$/.test(c.name)) },
  { code: "REGISTRY_CONTRADICTS_COMMITMENT", when: (f) => f.some((c) => /\.registry\.standing-(at-commitment|per-current-record)$/.test(c.name)) },
  { code: "REGISTRY_ATTESTATION_MISSING", when: (f) => f.some((c) => c.name === "registry.attestations-present") },
  // Why a registry quorum failed: every failing per-registry check merely stale → STALE; any forged / mis-subject → INVALID; else too few or a named one absent.
  { code: "REGISTRY_STALE", when: (f) => f.some((c) => c.name.endsWith(".registry.quorum")) && f.filter(perRegistry).length > 0 && f.filter(perRegistry).every((c) => c.detail?.includes("old at commitment")) },
  { code: "REGISTRY_ATTESTATION_INVALID", when: (f) => f.some((c) => c.name.endsWith(".registry.quorum")) && f.filter(perRegistry).some((c) => !c.detail?.includes("old at commitment")) },
  { code: "REGISTRY_QUORUM_NOT_MET", when: (f) => f.some((c) => c.name.endsWith(".registry.quorum")) },
  { code: "REGISTRY_ATTESTATION_INVALID", when: (f) => f.filter(perRegistry).some((c) => !c.detail?.includes("old at commitment")) },
  { code: "REGISTRY_DISAGREEMENT", when: (f) => f.some((c) => c.name.endsWith(".registry.consistent")) },
  { code: "INSURER_ATTESTATION_INVALID", when: (f) => f.some((c) => /\.insurer(\.current)?\[[^\]]+\]\.(signed|subject)$/.test(c.name)) },
  { code: "REGULATOR_KEY_UNTRUSTED", when: (f) => f.some((c) => /\.filer\[[^\]]+\]\.regulator-key-trusted$|\.regulator\[[^\]]+\]\.anchored$/.test(c.name)) },
  { code: "FILER_UNLICENSED", when: (f) => f.some((c) => /\.filer\[[^\]]+\]\.licensed$/.test(c.name)) },
  { code: "INSURER_KEY_NOT_OF_RECORD", when: (f) => f.some((c) => /\.insurer\[[^\]]+\]\.key-of-record$/.test(c.name)) },
  { code: "INSURER_NOT_OF_RECORD", when: (f) => f.some((c) => /\.insurer\[[^\]]+\]\.of-record$/.test(c.name)) },
  { code: "INSURER_ATTESTATION_MISSING", when: (f) => f.some((c) => c.name.endsWith(".insurer.attestation-present")) },
  { code: "INSURER_UNDERTAKING_MISSING", when: (f) => f.some((c) => c.name.endsWith(".insurer.undertaking")) },
  { code: "INSURANCE_NOT_ASSURED_THROUGH_DELIVERY", when: (f) => f.some((c) => c.name.endsWith(".insurer.assured-through-delivery")) },
  { code: "INSURANCE_RENEWAL_NOT_PRESENTED", when: (f) => f.some((c) => c.name.endsWith(".insurer.renewal-not-presented")) },
  { code: "INSURANCE_RENEWAL_PENDING", when: (f) => f.some((c) => c.name.endsWith(".insurer.renewal-due")) && f.every((c) => c.name.endsWith(".insurer.renewal-due") || witnessKind(c)) },
  { code: "WITNESS_QUORUM_NOT_MET", when: (f) => f.every(witnessKind) && f.some((c) => c.name.endsWith(".witness-quorum")) },
  { code: "STATUS_NOT_WITNESSED", when: (f) => f.every(witnessKind) && f.some((c) => c.name.endsWith(".witnessed")) },
  { code: "STATUS_STALE", when: (f) => f.every(witnessKind) },
  { code: "RECORD_TAMPERED", when: (f) => f.some((c) => /\.signature$|terms\.hash|-match$/.test(c.name) && !c.name.startsWith("venue.attestation[")) },
  { code: "COMMITMENT_UNDER_COMPROMISED_KEY", when: (f) => f.some((c) => c.name.endsWith("credential.trusted-at-signing")) && !f.some(venueKeyProblem) },
  { code: "VENUE_KEY_UNTRUSTED", when: (f) => f.some(venueKeyProblem) },
];
function venueKeyProblem(c: Failed): boolean {
  return c.name === "venue.attestation.any-trusted" || c.name.endsWith("issuer-trusted-at-issuance") || c.name === "venue.certs.signed-by-root" || c.name === "venue.root.pinned-reaches-embedded";
}
export function verdictFor(failed: Failed[]): ReasonCode | undefined {
  if (failed.length === 0) return undefined;
  return VERDICT_ORDER.find((v) => v.when(failed))?.code ?? "CREDENTIAL_ISSUER_INVALID";
}
