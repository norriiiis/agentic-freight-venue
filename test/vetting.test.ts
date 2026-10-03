/**
 * The CarrierOk adapter, against a fake server that answers in the shapes
 * their OpenAPI document specifies: `{ items: [profile], total_count }` on
 * /v2/profile, `{ error, code }` on failures, `Retry-After` on 429, and the
 * `{profile_id: [{field_current, field_prior, field_changed}]}` map on
 * /v2/monitoring/list.
 *
 * What these assert is the mapping and the policy — which signals become
 * flags, which become a refusal, and what the control gate is told about a
 * contact point. They cannot assert that the live API matches its own
 * document; `npm run vetting:check` does that, with a sandbox key.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { CarrierOkMonitor, CarrierOkVetting, type CarrierOkProfile } from "../src/identity/vetting-carrierok";

/** A profile shaped like the example in their documentation, with the fields this adapter reads. */
const CLEAN: CarrierOkProfile = {
  dot_number: "2751903", docket: "MC0938251", docket_prefix: "MC", docket_number: "0938251",
  legal_name: "PRAIRIE WIND TRANSPORT INC", entity_type_desc: "Carrier", usdot_status: "Active",
  out_of_service_flag: false,
  email_address: "dispatch@prairiewindtransport.example", email_change_count: "0", email_last_changed: "2023-04-02",
  telephone_number: "8065550188", undeliverable_physical_address_authority: false,
  authority_common: "Active", authority_contract: "Active", authority_broker: "None",
  authority_common_revocation: false, authority_contract_revocation: false, authority_broker_revocation: false,
  authority_age_common_active: "1535", total_revocations: "0", indicator_authority: true,
  indicator_insurance: true, insurance_bipd_on_file: "1000000", insurance_bipd_required: "750000", insurance_cancel_count: "0",
  risk_score: "Low", risk_score_probability: 0.04, iss_value: "22", iss_recommendation: "PASS",
  indicator_carrier_safety: true,
  network_graph_count_ein: "0", network_graph_count_email_address: "0", network_graph_count_telephone_numbers: "0",
  inspections_vehicle_out_of_service_pct: "0.04", snapshot_date: "2026-09-30",
};

let server: Server;
let base = "";
let reply: { status: number; body: unknown; headers?: Record<string, string> } = { status: 200, body: { items: [CLEAN], total_count: 1 } };
const seen: { url: string; auth?: string; method: string; body?: unknown }[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      seen.push({ url: req.url ?? "", auth: req.headers.authorization, method: req.method ?? "GET", body: raw ? JSON.parse(raw) : undefined });
      res.writeHead(reply.status, { "content-type": "application/json", ...(reply.headers ?? {}) });
      res.end(JSON.stringify(reply.body));
    });
  });
  base = await new Promise<string>((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as { port: number }).port}`)));
});
afterAll(() => server.close());

const vetting = (policy = {}) => new CarrierOkVetting({ apiKey: "sk_test_abc", baseUrl: base, policy, now: () => new Date("2026-10-03T12:00:00Z") });
const ok = (p: Partial<CarrierOkProfile>) => { reply = { status: 200, body: { items: [{ ...CLEAN, ...p }], total_count: 1 } }; };

describe("the request is the one their document specifies", () => {
  it("calls /v2/profile?dot_number= with a bearer token, and knows a sandbox key when it sees one", async () => {
    seen.length = 0;
    ok({});
    const v = vetting();
    expect(v.sandbox).toBe(true);
    const a = await v.assess("2751903");
    expect(seen[0]!.url).toBe("/v2/profile?dot_number=2751903");
    expect(seen[0]!.auth).toBe("Bearer sk_test_abc");
    expect(a.provider).toBe("carrierok:sandbox");
    expect(a.snapshotDate).toBe("2026-09-30");
    expect(a.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("asks once and reuses the answer inside the cache window", async () => {
    ok({});
    const v = vetting({ cacheTtlMs: 60_000 });
    seen.length = 0;
    await v.assess("2751903");
    await v.assess("2751903");
    expect(seen).toHaveLength(1);
  });
});

describe("a clean carrier passes, and every refusal names what caused it", () => {
  it("passes a carrier with active authority, insurance on file and no shared contact", async () => {
    ok({});
    const a = await vetting().assess("2751903");
    expect(a.block).toBe(false);
    expect(a.flags).toEqual(["risk:Low", "iss:PASS"]);
    expect(a.contact).toMatchObject({ email: "dispatch@prairiewindtransport.example", emailSharedWith: 0, addressUndeliverable: false });
    expect(a.risk).toMatchObject({ score: "Low", authorityAgeDays: 1535, revocations: 0, issValue: 22 });
  });

  it("refuses out of service, no authority, a revoked authority and the worst risk band", async () => {
    ok({ out_of_service_flag: true });
    expect(await vetting().assess("2751903")).toMatchObject({ block: true, flags: expect.arrayContaining(["out-of-service"]) });
    ok({ indicator_authority: false, authority_common: "None", authority_contract: "None" });
    expect(await vetting().assess("2751903")).toMatchObject({ block: true, flags: expect.arrayContaining(["no-active-authority"]) });
    ok({ authority_common_revocation: true });
    expect(await vetting().assess("2751903")).toMatchObject({ block: true, flags: expect.arrayContaining(["authority-revoked:common"]) });
    ok({ risk_score: "Very High", risk_score_probability: 0.91 });
    expect(await vetting().assess("2751903")).toMatchObject({ block: true, flags: expect.arrayContaining(["risk:Very High"]) });
    // and the band below it does not refuse, unless the operator says so
    ok({ risk_score: "High" });
    expect(await vetting().assess("2751903")).toMatchObject({ block: false });
    expect(await vetting({ blockRiskScores: ["High", "Very High"] }).assess("2751903")).toMatchObject({ block: true });
  });

  it("surfaces the chameleon-carrier signals as named flags", async () => {
    ok({ network_graph_count_ein: "3", network_graph_count_email_address: "11", network_graph_count_telephone_numbers: "4", indicator_network_graph_equipment: true, indicator_address_history: true, total_revocations: "2", days_since_last_revocation: "90", last_revocation_date: "2026-07-05", insurance_cancel_count: "3", email_change_count: "5", email_last_changed: "2026-09-28" });
    const a = await vetting().assess("2751903");
    expect(a.flags).toEqual(expect.arrayContaining([
      "shared-ein:3", "shared-email:11", "shared-phone:4", "shared-equipment", "address-history-pattern",
      "revocations:2", "revocation-within-12mo", "insurance-cancellations:3", "email-changes:5", "contact-changed-5d-ago",
    ]));
    // none of those is a block on its own: they are priced, and they stop the challenge (below), but a carrier
    // with a shared phone is not a fraudster by arithmetic.
    expect(a.block).toBe(false);
  });

  it("a contact point changed last week can block, if the operator chose that", async () => {
    ok({ email_last_changed: "2026-09-30" });
    expect(await vetting().assess("2751903")).toMatchObject({ block: false });
    expect(await vetting({ blockRecentContactChange: true }).assess("2751903")).toMatchObject({ block: true });
  });
});

describe("a provider that cannot answer does not quietly pass a carrier", () => {
  it("blocks on an outage, a timeout and a rate limit — unless told otherwise", async () => {
    reply = { status: 500, body: { error: "boom", code: "SERVER_ERROR" } };
    expect(await vetting().assess("2751903")).toMatchObject({ block: true, flags: ["provider-unreachable:http-500:SERVER_ERROR"] });
    expect(await vetting({ allowOnUnreachable: true }).assess("2751903")).toMatchObject({ block: false });
    reply = { status: 429, body: { error: "slow down" }, headers: { "retry-after": "30" } };
    const v = vetting();
    expect(await v.assess("2751903")).toMatchObject({ block: true, flags: ["provider-unreachable:rate-limited"] });
    const r = await v.profile("2751903");
    expect(r).toMatchObject({ ok: false, why: "rate-limited", retryAfterMs: 30_000 });
    reply = { status: 401, body: { error: "bad key", code: "UNAUTHORIZED" } };
    expect(await vetting().assess("2751903")).toMatchObject({ block: true });
  });

  it("treats a USDOT the provider has never heard of as a refusal, not an outage", async () => {
    reply = { status: 200, body: { items: [], total_count: 0 } };
    expect(await vetting().assess("9999999")).toMatchObject({ block: true, flags: ["not-found"] });
  });

  it("does not cache an outage: the next call asks again", async () => {
    reply = { status: 500, body: { error: "boom" } };
    const v = vetting({ cacheTtlMs: 60_000 });
    seen.length = 0;
    await v.assess("2751903");
    await v.assess("2751903");
    expect(seen).toHaveLength(2);
  });
});

describe("the watchlist", () => {
  it("registers {dot}-{docket} ids and asks only for what moved", async () => {
    const m = new CarrierOkMonitor({ apiKey: "sk_test_abc", baseUrl: base });
    reply = { status: 200, body: { status: "ok", added: 2 } };
    seen.length = 0;
    expect(await m.watch(["2751903-MC0938251", "3312874-MC1088412"])).toMatchObject({ ok: true, added: 2 });
    expect(seen[0]).toMatchObject({ method: "POST", url: "/v2/monitoring/add", body: { profile_ids: ["2751903-MC0938251", "3312874-MC1088412"] } });

    reply = { status: 200, body: { total_count: 1, items: { "2751903-MC0938251": [{ authority_common_current: "Inactive", authority_common_prior: "Active", authority_common_changed: "2026-10-02" }] } } };
    seen.length = 0;
    const c = await m.changes({ since: new Date("2026-10-01T00:00:00Z"), insurance: true, authority: true });
    expect(c.ok).toBe(true);
    expect(c.changed).toEqual([{ profileId: "2751903-MC0938251", fields: [{ authority_common_current: "Inactive", authority_common_prior: "Active", authority_common_changed: "2026-10-02" }] }]);
    expect(seen[0]!.url).toContain("view_changes_authority=1");
    expect(seen[0]!.url).toContain("date_min=20261001");
    expect(seen[0]!.url).toContain("date_type=last_changed_date");
  });

  it("an empty watchlist is not a request, and a failure is reported rather than thrown", async () => {
    const m = new CarrierOkMonitor({ apiKey: "sk_test_abc", baseUrl: base });
    seen.length = 0;
    expect(await m.watch([])).toEqual({ ok: true, added: 0 });
    expect(seen).toHaveLength(0);
    reply = { status: 403, body: { error: "suspended" } };
    expect(await m.changes({})).toMatchObject({ ok: false, error: "suspended", changed: [] });
  });
});
