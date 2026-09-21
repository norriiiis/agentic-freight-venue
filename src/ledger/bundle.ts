/**
 * The verification bundle: everything a verifier needs, in one document.
 *
 * verifyArtifact() takes twenty inputs because each is a different party's
 * word. A bundle gathers them: what the VENUE publishes (artifact, ledger,
 * status list, key history, renewals) and what the WORLD says today (each
 * registry's word on the parties, on the filers, on the regulators; the
 * witnesses' proofs and pending notices). The verifier supplies only its
 * PINS — the keys and policy it chose — and gets one verdict.
 *
 * Two ways to assemble one: `fetchBundle` pulls from live sources (the
 * venue's /bundle route for its part, each registry and witness for theirs —
 * never taking the venue's word for what the world says), and the venue's
 * /bundle route returns its own part for a party to keep. A bundle is data,
 * not trust: every item in it is signed by whoever said it, and the pins
 * decide whose signatures count.
 */
import type { OkpJwk } from "../protocol/crypto";
import type { CredentialStatusEntry } from "../protocol/types";
import type { EquivocationProof, WitnessKey } from "../protocol/witness";
import type { BrokenPromiseProof, PendingNotice } from "../protocol/inclusion";
import type { FilerAttestation, InsurerAttestation, InsurerKey, RegistryAttestation, RegistryKey, RegulatorKey, RegulatorLogAttestation } from "../protocol/registry";
import { httpGet } from "../protocol/rpc";
import type { LedgerEntry } from "./chain";
import { verifyArtifact, type ArtifactVerification, type CommitmentArtifact, type KeyHistoryInput, type StatusListInput } from "./artifact";

export interface VerificationBundle {
  schema: "freight-venue/verification-bundle/v1";
  commitmentId: string;
  assembledAt: string;
  assembledBy: string;
  /** The venue's part. */
  artifact: CommitmentArtifact;
  ledger?: LedgerEntry[];
  statusList?: StatusListInput;
  keyHistory?: KeyHistoryInput;
  renewals?: InsurerAttestation[];
  /** The world's word today, from parties other than the venue. */
  currentAttestations?: RegistryAttestation[];
  currentFilerAttestations?: FilerAttestation[];
  currentRegulatorAttestations?: RegulatorLogAttestation[];
  currentInsurerAttestations?: InsurerAttestation[];
  equivocationProofs?: EquivocationProof[];
  brokenPromises?: BrokenPromiseProof[];
  pendingNotices?: PendingNotice[];
  /** Where each part came from — so a reader knows which URLs were consulted. */
  sources: { venue?: string; registries?: string[]; witnesses?: string[] };
}

/** What the verifier brings: the keys it chose to trust and the policy it holds the venue to. */
export interface Pins {
  venueRoot?: OkpJwk;
  registryKeys?: RegistryKey[];
  minRegistries?: number;
  requiredRegistries?: string[];
  maxRegistryAgeMs?: number;
  regulatorKeys?: RegulatorKey[];
  insurerKeys?: InsurerKey[];
  requireInsurerAttestation?: boolean;
  requireInsurerUndertaking?: boolean;
  witnessKeys?: WitnessKey[];
  minWitnesses?: number;
  requiredWitnesses?: string[];
  maxStalenessMs?: number;
  noticeSources?: WitnessKey[];
}

export function verifyBundle(b: VerificationBundle, pins: Pins, asOf?: Date): ArtifactVerification {
  return verifyArtifact(b.artifact, {
    pinnedRootKey: pins.venueRoot,
    keyHistory: b.keyHistory,
    statusList: b.statusList,
    ledger: b.ledger,
    witnessKeys: pins.witnessKeys,
    minWitnesses: pins.minWitnesses,
    requiredWitnesses: pins.requiredWitnesses,
    maxStalenessMs: pins.maxStalenessMs,
    equivocationProofs: b.equivocationProofs,
    brokenPromises: b.brokenPromises,
    pendingNotices: b.pendingNotices,
    noticeSources: pins.noticeSources,
    registryKeys: pins.registryKeys,
    minRegistries: pins.minRegistries,
    requiredRegistries: pins.requiredRegistries,
    maxRegistryAgeMs: pins.maxRegistryAgeMs,
    currentAttestations: b.currentAttestations,
    insurerKeys: pins.insurerKeys,
    requireInsurerAttestation: pins.requireInsurerAttestation,
    requireInsurerUndertaking: pins.requireInsurerUndertaking,
    currentInsurerAttestations: b.currentInsurerAttestations,
    currentFilerAttestations: b.currentFilerAttestations,
    regulatorKeys: pins.regulatorKeys,
    currentRegulatorAttestations: b.currentRegulatorAttestations,
    renewals: b.renewals,
    asOf,
  });
}

/** The venue's part, as its /bundle route returns it. */
export type VenueBundlePart = Pick<VerificationBundle, "artifact" | "ledger" | "statusList" | "keyHistory" | "renewals">;

const tryGet = async <T>(url: string): Promise<T | undefined> => {
  try {
    return await httpGet<T>(url);
  } catch {
    return undefined;
  }
};

/**
 * Assemble a bundle from live sources. The venue supplies its part; the
 * world's word is fetched from the registries and witnesses the CALLER
 * names — the venue is never asked what the registries say. Unreachable
 * sources are simply absent, and `sources` records what was consulted.
 */
export async function fetchBundle(opts: { venueUrl: string; commitmentId: string; registryUrls?: string[]; witnessUrls?: string[] }): Promise<VerificationBundle> {
  const part = await httpGet<VenueBundlePart | { error: string }>(`${opts.venueUrl}/bundle/${encodeURIComponent(opts.commitmentId)}`);
  if ("error" in part) throw new Error(`venue: ${part.error}`);
  const a = part.artifact;
  const usdots = [a.credentials.broker.subject.entity.usdot, a.credentials.carrier.subject.entity.usdot];
  const insurers = [a.insurance?.broker?.insurerId, a.insurance?.carrier?.insurerId].filter((x): x is string => !!x);
  const regulators = [...new Set([...(a.insurance?.filers?.broker ?? []), ...(a.insurance?.filers?.carrier ?? [])].flatMap((f) => f.registration?.keys.map((k) => k.licensedBy?.regulatorId).filter((x): x is string => !!x) ?? []))];
  const b: VerificationBundle = {
    schema: "freight-venue/verification-bundle/v1",
    commitmentId: opts.commitmentId,
    assembledAt: new Date().toISOString(),
    assembledBy: "verifier",
    ...part,
    currentAttestations: [],
    currentFilerAttestations: [],
    currentRegulatorAttestations: [],
    equivocationProofs: [],
    brokenPromises: [],
    pendingNotices: [],
    sources: { venue: opts.venueUrl, registries: opts.registryUrls ?? [], witnesses: opts.witnessUrls ?? [] },
  };
  for (const r of opts.registryUrls ?? []) {
    for (const u of usdots) { const x = await tryGet<RegistryAttestation>(`${r}/attest?usdot=${u}`); if (x) b.currentAttestations!.push(x); }
    for (const i of insurers) { const x = await tryGet<FilerAttestation>(`${r}/attest-filer?insurerId=${i}`); if (x) b.currentFilerAttestations!.push(x); }
    for (const g of regulators) { const x = await tryGet<RegulatorLogAttestation>(`${r}/attest-regulator?regulatorId=${g}`); if (x) b.currentRegulatorAttestations!.push(x); }
  }
  for (const w of opts.witnessUrls ?? []) {
    b.equivocationProofs!.push(...((await tryGet<EquivocationProof[]>(`${w}/equivocations`)) ?? []));
    b.brokenPromises!.push(...((await tryGet<BrokenPromiseProof[]>(`${w}/broken`)) ?? []));
    b.pendingNotices!.push(...((await tryGet<PendingNotice[]>(`${w}/pending`)) ?? []));
  }
  return b;
}

/** A status-list entry type re-export for callers that only know the bundle. */
export type { CredentialStatusEntry };
