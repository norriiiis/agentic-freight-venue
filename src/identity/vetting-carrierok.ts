/**
 * CarrierOk as the vetting provider.
 *
 * Built against their published OpenAPI document (api.carrierok.com, v2,
 * `Authorization: Bearer sk_live_…` or `x-api-key`; sandbox keys are
 * `sk_test_` and serve fixtures for ten carriers). `GET /v2/profile` returns
 * `{ items: CarrierProfile[], total_count }`; errors are `{ error, code?,
 * hint? }` and a 429 carries `Retry-After` in seconds.
 *
 * WHAT THIS PROVIDER IS, AND IS NOT. CarrierOk sells carrier DATA: FMCSA's
 * record plus scoring FMCSA does not publish, and — the part that matters
 * most here — a network graph of entities sharing an EIN, a phone or an
 * email. It does not sell identity verification: nobody there confirms that
 * the person asking to register a key runs the company. So this adapter does
 * NOT produce a proof of control, and nothing here signs a control
 * attestation. What it does is make the proof the venue already runs mean
 * more, and sometimes refuse to let it run at all:
 *
 *   A challenge is only as good as the mailbox it goes to. If the email on
 *   the public record is shared with eleven other registrants — a filing
 *   agent's inbox, which is the common case the previous turn could only
 *   warn about — then a code sent there proves control of something several
 *   companies read. `network_graph_count_email_address` says so, and the
 *   venue refuses to send rather than manufacture a proof worth nothing.
 *
 *   A contact point that changed last week is the account-takeover pattern.
 *   `email_last_changed` and `email_change_count` are recorded against the
 *   challenge so a human can see it later, and can block by policy.
 *
 * The signals it returns also feed the underwriting model and the credential's
 * vetting flags, which already existed and were fed by a fixture.
 *
 * NOT YET RUN AGAINST THE LIVE API. Every field name, endpoint, auth header
 * and error shape here comes from their OpenAPI document; the tests drive a
 * fake server that serves spec-shaped payloads. Before trusting it with a
 * client, run `npm run vetting:check -- <USDOT>` with a sandbox key.
 */
import { createHash } from "node:crypto";
import type { VettingAssessment, VettingProvider } from "./vetting";

/** Only the fields this adapter reads. The profile carries 300+; the rest are not our business. */
export interface CarrierOkProfile {
  dot_number?: string;
  docket?: string;
  docket_prefix?: string;
  docket_number?: string;
  legal_name?: string;
  entity_type_desc?: string;
  usdot_status?: string;
  out_of_service_flag?: boolean;
  email_address?: string;
  email_domain?: string;
  email_change_count?: string;
  email_last_changed?: string;
  telephone_number?: string;
  undeliverable_physical_address_authority?: boolean;
  authority_common?: string;
  authority_contract?: string;
  authority_broker?: string;
  authority_common_revocation?: boolean;
  authority_contract_revocation?: boolean;
  authority_broker_revocation?: boolean;
  authority_common_review?: boolean;
  authority_contract_review?: boolean;
  authority_broker_review?: boolean;
  authority_age_common_active?: string;
  total_revocations?: string;
  days_since_last_revocation?: string;
  last_revocation_date?: string;
  indicator_authority?: boolean;
  indicator_insurance?: boolean;
  insurance_bipd_on_file?: string;
  insurance_bipd_required?: string;
  insurance_cargo_on_file?: string;
  insurance_bond_on_file?: string;
  insurance_cancel_count?: string;
  insurance_last_canceled?: string;
  insurance_history?: unknown[];
  risk_score?: string;
  risk_score_probability?: number;
  iss_value?: string;
  iss_recommendation?: string;
  indicator_carrier_safety?: boolean;
  indicator_network_graph_contact?: boolean;
  indicator_network_graph_equipment?: boolean;
  indicator_address_history?: boolean;
  network_graph_count_ein?: string;
  network_graph_count_email_address?: string;
  network_graph_count_telephone_numbers?: string;
  inspections_vehicle_out_of_service_pct?: string;
  snapshot_date?: string;
  [k: string]: unknown;
}

export interface VettingPolicy {
  /** Refuse onboarding outright when the provider reports these. */
  blockOutOfService: boolean;
  blockNoActiveAuthority: boolean;
  blockRevokedAuthority: boolean;
  /** Composite classifications that refuse: "Low" | "Medium" | "High" | "Very High". */
  blockRiskScores: string[];
  /**
   * Other registrants that may share a contact point before a challenge to it stops proving anything.
   * 0 means the contact must be exclusive to this entity, which is the only setting that makes the proof sound.
   */
  maxContactSharedWith: number;
  /** A contact point changed this recently is recorded; set `blockRecentContactChange` to refuse on it too. */
  recentContactChangeDays: number;
  blockRecentContactChange: boolean;
  /** An unreachable provider blocks by default: no vetting is a decision, not an accident. */
  allowOnUnreachable: boolean;
  /** How long an assessment is reused before asking again. Vetting is per-onboarding, not per-message. */
  cacheTtlMs: number;
}

export const DEFAULT_VETTING_POLICY: VettingPolicy = {
  blockOutOfService: true,
  blockNoActiveAuthority: true,
  blockRevokedAuthority: true,
  blockRiskScores: ["Very High"],
  maxContactSharedWith: 0,
  recentContactChangeDays: 30,
  blockRecentContactChange: false,
  allowOnUnreachable: false,
  cacheTtlMs: 10 * 60_000,
};

const num = (v: unknown): number => {
  const n = Number(String(v ?? "").replace(/[^0-9.-]/g, ""));
  return Number.isFinite(n) ? n : 0;
};
const active = (s: string | undefined) => (s ?? "").toLowerCase() === "active";

export interface CarrierOkOptions {
  apiKey: string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  policy?: Partial<VettingPolicy>;
  /** Clock, for tests. */
  now?: () => Date;
}

export class CarrierOkVetting implements VettingProvider {
  readonly policy: VettingPolicy;
  private readonly cache = new Map<string, { at: number; value: VettingAssessment }>();
  /** Set when the key is a sandbox key, so callers can say so rather than mistake fixtures for the real record. */
  readonly sandbox: boolean;

  constructor(private readonly o: CarrierOkOptions) {
    this.policy = { ...DEFAULT_VETTING_POLICY, ...o.policy };
    this.sandbox = o.apiKey.startsWith("sk_test_");
  }
  private get name() { return `carrierok${this.sandbox ? ":sandbox" : ""}`; }
  private get base() { return (this.o.baseUrl ?? "https://api.carrierok.com").replace(/\/$/, ""); }
  private now() { return this.o.now?.() ?? new Date(); }

  /** One profile, or a stated reason there is none. Never throws: a vetting failure is an answer, not an exception. */
  async profile(usdot: string): Promise<{ ok: true; profile: CarrierOkProfile; body: unknown } | { ok: false; why: string; retryAfterMs?: number }> {
    const f = this.o.fetchImpl ?? fetch;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.o.timeoutMs ?? 8000);
    try {
      const res = await f(`${this.base}/v2/profile?dot_number=${encodeURIComponent(usdot)}`, {
        headers: { authorization: `Bearer ${this.o.apiKey}`, accept: "application/json" },
        signal: ctl.signal,
      });
      if (res.status === 429) {
        const retry = Number(res.headers.get("retry-after") ?? 0);
        return { ok: false, why: "rate-limited", retryAfterMs: (Number.isFinite(retry) ? retry : 60) * 1000 };
      }
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string; code?: string };
        return { ok: false, why: `http-${res.status}${body.code ? `:${body.code}` : ""}` };
      }
      const body = (await res.json()) as { items?: CarrierOkProfile[]; total_count?: number };
      const profile = body.items?.[0];
      if (!profile) return { ok: false, why: "not-found" };
      return { ok: true, profile, body };
    } catch (e) {
      return { ok: false, why: (e as Error).name === "AbortError" ? "timeout" : `unreachable:${String((e as Error).message).slice(0, 40)}` };
    } finally {
      clearTimeout(timer);
    }
  }

  async assess(usdot: string): Promise<VettingAssessment> {
    const hit = this.cache.get(usdot);
    if (hit && Date.now() - hit.at < this.policy.cacheTtlMs) return hit.value;
    const r = await this.profile(usdot);
    const checkedAt = this.now().toISOString();
    if (!r.ok) {
      const value: VettingAssessment = { provider: this.name, checkedAt, flags: [`provider-unreachable:${r.why}`], block: !this.policy.allowOnUnreachable };
      // A rate-limited or timed-out answer is not cached: it is not an answer about the carrier.
      if (r.why === "not-found") this.cache.set(usdot, { at: Date.now(), value: { ...value, flags: ["not-found"], block: true } });
      return r.why === "not-found" ? { ...value, flags: ["not-found"], block: true } : value;
    }
    const value = this.map(r.profile, r.body, checkedAt);
    this.cache.set(usdot, { at: Date.now(), value });
    return value;
  }

  /** The provider's record → flags, a block decision, and the contact facts the control gate needs. */
  map(p: CarrierOkProfile, body: unknown, checkedAt = this.now().toISOString()): VettingAssessment {
    const flags: string[] = [];
    const pol = this.policy;

    if (p.out_of_service_flag) flags.push("out-of-service");
    if ((p.usdot_status ?? "").toLowerCase() !== "active") flags.push(`usdot-status:${p.usdot_status ?? "unknown"}`);
    const anyAuthority = p.indicator_authority ?? (active(p.authority_common) || active(p.authority_contract) || active(p.authority_broker));
    if (!anyAuthority) flags.push("no-active-authority");
    for (const [kind, revoked, review] of [
      ["common", p.authority_common_revocation, p.authority_common_review],
      ["contract", p.authority_contract_revocation, p.authority_contract_review],
      ["broker", p.authority_broker_revocation, p.authority_broker_review],
    ] as const) {
      if (revoked) flags.push(`authority-revoked:${kind}`);
      if (review) flags.push(`authority-under-review:${kind}`);
    }
    const revocations = num(p.total_revocations);
    if (revocations > 0) flags.push(`revocations:${revocations}`);
    const sinceRevocation = num(p.days_since_last_revocation);
    if (p.last_revocation_date && sinceRevocation > 0 && sinceRevocation < 365) flags.push("revocation-within-12mo");
    const authorityAgeDays = num(p.authority_age_common_active);
    if (authorityAgeDays > 0 && authorityAgeDays < 180) flags.push(`new-authority:${authorityAgeDays}d`);

    if (p.indicator_insurance === false) flags.push("insurance-not-on-file");
    const cancels = num(p.insurance_cancel_count);
    if (cancels > 0) flags.push(`insurance-cancellations:${cancels}`);

    // The fraud signals: one operator wearing several registrations is the chameleon-carrier pattern, and the
    // peril this venue's guarantee is written against.
    const sharedEin = num(p.network_graph_count_ein);
    const sharedEmail = num(p.network_graph_count_email_address);
    const sharedPhone = num(p.network_graph_count_telephone_numbers);
    if (sharedEin > 0) flags.push(`shared-ein:${sharedEin}`);
    if (sharedEmail > 0) flags.push(`shared-email:${sharedEmail}`);
    if (sharedPhone > 0) flags.push(`shared-phone:${sharedPhone}`);
    if (p.indicator_network_graph_equipment) flags.push("shared-equipment");
    if (p.indicator_address_history) flags.push("address-history-pattern");
    if (p.undeliverable_physical_address_authority) flags.push("address-undeliverable");

    const changedDaysAgo = p.email_last_changed ? (this.now().getTime() - new Date(p.email_last_changed).getTime()) / 86_400_000 : Infinity;
    if (changedDaysAgo <= pol.recentContactChangeDays) flags.push(`contact-changed-${Math.max(0, Math.floor(changedDaysAgo))}d-ago`);
    const emailChanges = num(p.email_change_count);
    if (emailChanges > 2) flags.push(`email-changes:${emailChanges}`);

    if (p.risk_score) flags.push(`risk:${p.risk_score}`);
    if (p.iss_recommendation) flags.push(`iss:${p.iss_recommendation}`);
    if (p.indicator_carrier_safety === false) flags.push("safety-criteria-not-met");

    const block =
      (pol.blockOutOfService && !!p.out_of_service_flag) ||
      (pol.blockNoActiveAuthority && !anyAuthority) ||
      (pol.blockRevokedAuthority && !!(p.authority_common_revocation || p.authority_contract_revocation || p.authority_broker_revocation)) ||
      pol.blockRiskScores.includes(p.risk_score ?? "") ||
      (pol.blockRecentContactChange && changedDaysAgo <= pol.recentContactChangeDays);

    return {
      provider: this.name,
      checkedAt,
      flags,
      block,
      contact: {
        email: p.email_address,
        emailSharedWith: sharedEmail,
        emailLastChanged: p.email_last_changed,
        emailChangeCount: emailChanges,
        phone: p.telephone_number,
        phoneSharedWith: sharedPhone,
        addressUndeliverable: !!p.undeliverable_physical_address_authority,
      },
      risk: {
        score: p.risk_score,
        probability: p.risk_score_probability,
        authorityAgeDays: authorityAgeDays || undefined,
        revocations,
        insuranceCancellations: cancels,
        vehicleOosRate: num(p.inspections_vehicle_out_of_service_pct) || undefined,
        issValue: num(p.iss_value) || undefined,
      },
      digest: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
      snapshotDate: p.snapshot_date,
    };
  }

  /** `{dot}-{docket}`, which is what the monitoring endpoints key on. */
  static profileId(p: CarrierOkProfile): string | undefined {
    return p.dot_number && p.docket ? `${p.dot_number}-${p.docket}` : undefined;
  }
}

/**
 * The watchlist. FMCSA revocations and insurance cancellations are the events this venue most needs to hear about
 * between a commitment and a pickup, and polling every carrier's full profile would be both slow and expensive.
 * `POST /v2/monitoring/add` registers a profile; `GET /v2/monitoring/list?view_changes_*` returns only what moved.
 */
export class CarrierOkMonitor {
  constructor(private readonly o: CarrierOkOptions) {}
  private get base() { return (this.o.baseUrl ?? "https://api.carrierok.com").replace(/\/$/, ""); }
  private headers() { return { authorization: `Bearer ${this.o.apiKey}`, accept: "application/json", "content-type": "application/json" }; }

  async watch(profileIds: string[]): Promise<{ ok: boolean; added?: number; error?: string }> {
    if (!profileIds.length) return { ok: true, added: 0 };
    const f = this.o.fetchImpl ?? fetch;
    try {
      const res = await f(`${this.base}/v2/monitoring/add`, { method: "POST", headers: this.headers(), body: JSON.stringify({ profile_ids: profileIds }) });
      const body = (await res.json().catch(() => ({}))) as { added?: number; error?: string };
      return res.ok ? { ok: true, added: body.added } : { ok: false, error: body.error ?? `http-${res.status}` };
    } catch (e) {
      return { ok: false, error: (e as Error).message };
    }
  }

  async unwatch(profileIds: string[]): Promise<{ ok: boolean; removed?: number }> {
    if (!profileIds.length) return { ok: true, removed: 0 };
    const f = this.o.fetchImpl ?? fetch;
    try {
      const res = await f(`${this.base}/v2/monitoring/remove`, { method: "POST", headers: this.headers(), body: JSON.stringify({ profile_ids: profileIds }) });
      const body = (await res.json().catch(() => ({}))) as { removed?: number };
      return { ok: res.ok, removed: body.removed };
    } catch {
      return { ok: false };
    }
  }

  /**
   * What changed. Each value is a list of `{field}_current` / `{field}_prior` / `{field}_changed` triples, so the
   * answer is not "this carrier is different" but "this field was X and is now Y" — which is what an operator and
   * an audit entry both need.
   */
  async changes(opts: { since?: Date; insurance?: boolean; authority?: boolean; safety?: boolean; contact?: boolean } = {}): Promise<{ ok: boolean; changed: { profileId: string; fields: Record<string, unknown>[] }[]; error?: string }> {
    const f = this.o.fetchImpl ?? fetch;
    const q = new URLSearchParams({ pageSize: "500" });
    if (opts.insurance) q.set("view_changes_insurance", "1");
    if (opts.authority) q.set("view_changes_authority", "1");
    if (opts.safety) q.set("view_changes_safety", "1");
    if (opts.contact) q.set("view_changes_contact", "1");
    if (!opts.insurance && !opts.authority && !opts.safety && !opts.contact) q.set("view_changes", "1");
    if (opts.since) { q.set("date_type", "last_changed_date"); q.set("date_min", opts.since.toISOString().slice(0, 10).replace(/-/g, "")); }
    try {
      const res = await f(`${this.base}/v2/monitoring/list?${q}`, { headers: this.headers() });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string };
        return { ok: false, changed: [], error: body.error ?? `http-${res.status}` };
      }
      const body = (await res.json()) as { items?: Record<string, Record<string, unknown>[]> };
      return { ok: true, changed: Object.entries(body.items ?? {}).map(([profileId, fields]) => ({ profileId, fields })) };
    } catch (e) {
      return { ok: false, changed: [], error: (e as Error).message };
    }
  }
}
