/**
 * This application's view of the venue and of the registry, over HTTP.
 *
 * It imports nothing from `venue/` or `registry/`: those are separate trust
 * domains and separate processes, and everything they say arrives as JSON
 * signed by them. What this client adds is the operator bearer token and
 * typed shapes for the few surfaces the console reads.
 */
import { httpGet, httpPost } from "../protocol/rpc";
import type { OkpJwk } from "../protocol/crypto";

export interface VenueAgentView { agentId: string; credentialId: string; url: string; registeredAt?: string; envelope?: Record<string, unknown> }
export interface VenueCommitmentView { commitmentId: string; loadRef: string; brokerAgentId: string; carrierAgentId: string; status: string; taskId: string; pickupWindowStart: string; renewal?: unknown; voided?: { reasonCode: string } }
export interface VenueTaskView { taskId: string; task: { id: string; status: { state: string } }; loadRef?: string }
export interface VenueAuditEntry { seq: number; ts: string; component: string; event: string; outcome: string; reasonCode?: string; subject?: string; taskId?: string; evidence?: Record<string, unknown> }
export interface VenueHealth { ok: boolean; venueId: string; outbox: number; deadLetter: number; tasks: number; commitments: number; nonces: number; jobs: { name: string; everyMs: number; lastRunAt?: string; lastOutcome?: unknown }[] }

export class VenueClient {
  constructor(readonly url: string, private readonly opsToken?: string) {}
  private get auth(): Record<string, string> { return this.opsToken ? { authorization: `Bearer ${this.opsToken}` } : {}; }

  health() { return httpGet<{ ok: boolean }>(`${this.url}/health`); }
  opsHealth() { return httpGet<VenueHealth>(`${this.url}/ops/health`, this.auth); }
  agents() { return httpGet<VenueAgentView[]>(`${this.url}/ops/agents`, this.auth); }
  commitments() { return httpGet<VenueCommitmentView[]>(`${this.url}/ops/commitments`, this.auth); }
  tasks() { return httpGet<VenueTaskView[]>(`${this.url}/ops/tasks`, this.auth); }
  audit(sinceSeq = 0) { return httpGet<VenueAuditEntry[]>(`${this.url}/ops/audit?from=${sinceSeq}`, this.auth); }
  messages(taskId: string) { return httpGet<Record<string, unknown>[]>(`${this.url}/ops/messages?taskId=${encodeURIComponent(taskId)}`, this.auth); }
  exposure(usdot: string, pairUsdot: string) { return httpGet<Record<string, unknown>>(`${this.url}/ops/exposure?usdot=${usdot}&pair=${pairUsdot}`, this.auth); }
  bundle(commitmentId: string) { return httpGet<Record<string, unknown>>(`${this.url}/bundle/${encodeURIComponent(commitmentId)}`); }
  publicKey() { return httpGet<{ venueId: string; rootPublicKey: OkpJwk; kid: string }>(`${this.url}/admin/public-key`).catch(() => undefined); }
  agentCard() { return httpGet<Record<string, unknown>>(`${this.url}/.well-known/agent-card.json`); }
}

export interface RegistryRecordView {
  usdot: string; mc?: string; legalName: string; dbaName?: string; entityType: string; operatingStatus: string;
  authorities: { type: string; status: string }[];
  insurance: { type: string; form: string; insurer: string; policyNumber: string; coverageToUsd: number; effectiveDate: string; cancellationDate?: string }[];
  safetyRating: string; powerUnits: number; drivers: number;
  physicalAddress: { street: string; city: string; state: string; zip: string }; phone: string; email: string;
}

export class RegistryClient {
  constructor(readonly url: string, readonly registryId: string) {}
  health() { return httpGet<{ ok: boolean }>(`${this.url}/health`); }
  /** The signed word about one entity. The signature is what matters; this client does not re-sign anything. */
  attest(usdot: string) { return httpGet<{ registryId: string; usdot: string; record: RegistryRecordView | null; asOf: string; upstreamAsOf?: string; signature: string }>(`${this.url}/attest?usdot=${encodeURIComponent(usdot)}`); }
  records() { return httpGet<RegistryRecordView[]>(`${this.url}/records`); }
  /** The out-of-band channel the registry stub stands in for: a token only someone who controls the entity's contact point can read. */
  outOfBand(usdot: string) { return httpGet<{ _proofOfControlToken?: string; _vettingFlags?: string[] } | null>(`${this.url}/stub/out-of-band?usdot=${encodeURIComponent(usdot)}`).catch(() => undefined); }
  upsert(record: unknown) { return httpPost<{ ok: boolean }>(`${this.url}/admin/update`, { record }); }
}
