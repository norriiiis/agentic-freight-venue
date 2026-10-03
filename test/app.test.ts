/**
 * The client journey, end to end, through the real HTTP application:
 * invite → account → claim the entity → prove control → key → mandate →
 * agent live → post a load → committed, with both sides onboarded the same
 * way. Three processes (registry, venue, app) plus the two agent processes
 * the app starts for its clients.
 *
 * If this passes, a client can be onboarded and a load can be transacted.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { createServer } from "node:net";
import { waitForHealth } from "../src/protocol/rpc";

const ROOT = resolve(import.meta.dirname, "..");
const procs: ChildProcess[] = [];
let workspace = "";
let APP = "", VENUE = "", REGISTRY = "";
const OPS = randomBytes(16).toString("hex");
const BOOT = { email: "ops@interchange.test", password: "operator-password-1" };

const freePort = () => new Promise<number>((res, rej) => { const s = createServer(); s.on("error", rej); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => res(p)); }); });

function start(entry: string, env: Record<string, string>, label: string) {
  const p = spawn(process.execPath, ["--import", "tsx", join(ROOT, entry)], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], cwd: ROOT });
  p.stdout?.on("data", (d) => { if (process.env.FV_VERBOSE) process.stdout.write(`  ${label}| ${d}`); });
  p.stderr?.on("data", (d) => process.stderr.write(`  ${label}! ${d}`));
  procs.push(p);
  return p;
}

/** A browser's worth of HTTP: one cookie jar, forms, redirects followed by hand so we can assert on them. */
class Client {
  private cookies = new Map<string, string>();
  constructor(private readonly base: string) {}
  private header() { return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "); }
  private take(res: Response) {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(";");
      const i = pair!.indexOf("=");
      const k = pair!.slice(0, i), v = pair!.slice(i + 1);
      if (v === "") this.cookies.delete(k); else this.cookies.set(k, v);
    }
  }
  async get(path: string) {
    const res = await fetch(`${this.base}${path}`, { headers: { cookie: this.header() }, redirect: "manual" });
    this.take(res);
    return { status: res.status, location: res.headers.get("location"), body: await res.text() };
  }
  async post(path: string, form: Record<string, string>) {
    const res = await fetch(`${this.base}${path}`, { method: "POST", headers: { cookie: this.header(), "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString(), redirect: "manual" });
    this.take(res);
    return { status: res.status, location: res.headers.get("location"), body: await res.text() };
  }
  /** The CSRF token the server put in the page we are about to submit. */
  static csrf(html: string): string {
    return /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
  }
}

const appDb = () => new DatabaseSync(join(workspace, "app", "app.db"));

beforeAll(async () => {
  workspace = mkdtempSync(join(tmpdir(), "fv-app-"));
  const [rp, vp, ap] = await Promise.all([freePort(), freePort(), freePort()]);
  REGISTRY = `http://127.0.0.1:${rp}`; VENUE = `http://127.0.0.1:${vp}`; APP = `http://127.0.0.1:${ap}`;

  start("src/registry/server.ts", { REGISTRY_PORT: String(rp), REGISTRY_DATA_DIR: join(workspace, "registry"), SIM_MODE: "1" }, "registry");
  await waitForHealth(`${REGISTRY}/health`, 20_000);

  start("src/venue/server.ts", {
    VENUE_PORT: String(vp), VENUE_DATA_DIR: join(workspace, "venue"), VENUE_REGISTRY_URL: REGISTRY,
    VENUE_OPS_TOKEN: OPS, VENUE_REGISTRY_MAX_AGE_MS: "600000",
    VENUE_UW_PARAMS: JSON.stringify({ offerGuarantees: false }),
  }, "venue");
  await waitForHealth(`${VENUE}/health`, 25_000);

  start("src/app/server.ts", {
    APP_PORT: String(ap), APP_URL: APP, APP_DATA_DIR: join(workspace, "app"),
    APP_MASTER_KEY: randomBytes(32).toString("base64"),
    APP_VENUE_URL: VENUE, APP_VENUE_OPS_TOKEN: OPS, APP_REGISTRY_URL: REGISTRY,
    APP_BOOTSTRAP_EMAIL: BOOT.email, APP_BOOTSTRAP_PASSWORD: BOOT.password,
  }, "app");
  await waitForHealth(`${APP}/healthz`, 25_000);
}, 90_000);

afterAll(() => {
  for (const p of procs) { try { p.kill("SIGKILL"); } catch { /* already gone */ } }
  if (workspace) try { rmSync(workspace, { recursive: true, force: true }); } catch { /* best effort */ }
});

/** Walk one client all the way from an invitation to a live agent. */
async function onboard(opts: { email: string; company: string; role: "broker" | "carrier"; usdot: string; proof: "email" | "operator" }) {
  const staff = new Client(APP);
  const login = await staff.post("/login", { email: BOOT.email, password: BOOT.password });
  expect(login.location).toBe("/");
  const staffPage = await staff.get("/staff");
  const inv = await staff.post("/staff/invite", { csrf: Client.csrf(staffPage.body), email: opts.email, orgName: opts.company, orgRole: opts.role });
  expect(inv.location).toBe("/staff");

  const db = appDb();
  const code = (db.prepare("SELECT code FROM invites WHERE email = ? AND accepted_at IS NULL").get(opts.email) as { code: string }).code;
  db.close();

  const client = new Client(APP);
  const invitePage = await client.get(`/invite/${code}`);
  expect(invitePage.status).toBe(200);
  const created = await client.post(`/invite/${code}`, { csrf: Client.csrf(invitePage.body), name: "A Person", password: "a-long-enough-password-9" });
  expect(created.location).toBe("/onboarding");

  // 1. claim — the lookup redirects to a preview, as it does in a browser
  let ob = await client.get("/onboarding");
  const preview = await client.post("/onboarding/claim", { csrf: Client.csrf(ob.body), usdot: opts.usdot });
  ob = await client.get(preview.location!);
  expect(ob.body, "the registry preview did not render").toContain("Yes, this is us");
  await client.post("/onboarding/claim-confirm", { csrf: Client.csrf(ob.body), usdot: opts.usdot });

  // 2. prove control
  ob = await client.get("/onboarding");
  const orgId = (() => { const db2 = appDb(); const r = db2.prepare("SELECT org_id FROM entities WHERE usdot = ?").get(opts.usdot) as { org_id: string }; db2.close(); return r.org_id; })();
  if (opts.proof === "email") {
    await client.post("/onboarding/challenge", { csrf: Client.csrf(ob.body) });
    const db3 = appDb();
    const challenge = (db3.prepare("SELECT challenge FROM proofs WHERE org_id = ? AND status = 'PENDING' ORDER BY created_at DESC").get(orgId) as { challenge: string }).challenge;
    db3.close();
    ob = await client.get("/onboarding");
    const v = await client.post("/onboarding/verify", { csrf: Client.csrf(ob.body), code: challenge });
    expect(v.location).toBe("/onboarding");
  } else {
    // the operator path: a staff member records what they did by hand, in that client's context
    const sp = await staff.get(`/onboarding?org=${orgId}`);
    await staff.post(`/onboarding/attest?org=${orgId}`, { csrf: Client.csrf(sp.body), evidence: `Called (806) 555-0188 from the FMCSA record and spoke to the owner, who confirmed the request on ${new Date().toDateString()}.` });
  }

  // 3. key
  ob = await client.get("/onboarding");
  expect(ob.body).toContain("Create the signing key");
  await client.post("/onboarding/key", { csrf: Client.csrf(ob.body) });

  // 4. mandate
  ob = await client.get("/onboarding");
  const limits: Record<string, string> = opts.role === "broker"
    ? { minRatePerLoadUsd: "500", maxRatePerLoadUsd: "4000", maxRatePerMileUsd: "5", allowedLaneRegions: "TX OK KS MO AR LA", allowedEquipment: "VAN REEFER", hazmatPermitted: "false", requiredCounterpartyInsuranceUsd: "750000", maxPerCounterpartyExposureUsd: "20000", maxDailyExposureUsd: "40000", maxNegotiationRounds: "10", paymentMin: "15", paymentMax: "45", requireInsurerAttestation: "false" }
    : { minRatePerLoadUsd: "400", minRatePerMileUsd: "1.2", allowedLaneRegions: "TX OK KS MO AR LA", allowedEquipment: "VAN", hazmatPermitted: "false", requiredCounterpartyInsuranceUsd: "50000", maxPerCounterpartyExposureUsd: "20000", maxDailyExposureUsd: "40000", maxNegotiationRounds: "10", paymentMin: "0", paymentMax: "45", requireInsurerAttestation: "false" };
  await client.post("/onboarding/mandate", { csrf: Client.csrf(ob.body), ...limits });

  // 5. agent
  ob = await client.get("/onboarding");
  expect(ob.body).toContain("Start my agent");
  const started = await client.post("/onboarding/agent", { csrf: Client.csrf(ob.body) });
  expect(started.location, `agent did not come up for ${opts.company}`).toBe("/desk");
  return { client, orgId };
}

describe("a client is onboarded and transacts", () => {
  it("takes a broker and a carrier from invitation to a committed load", async () => {
    const carrier = await onboard({ email: "dispatch@prairie.test", company: "Prairie Wind Transport Inc", role: "carrier", usdot: "2751903", proof: "operator" });
    const broker = await onboard({ email: "ops@northline.test", company: "Northline Logistics LLC", role: "broker", usdot: "3312874", proof: "email" });

    // Both agents hold a credential the venue issued against the registry's word.
    const db = appDb();
    const agents = db.prepare("SELECT agent_id, status, credential_id FROM agents").all() as { agent_id: string; status: string; credential_id: string | null }[];
    db.close();
    expect(agents).toHaveLength(2);
    for (const a of agents) {
      expect(a.status, `${a.agent_id} is ${a.status}`).toBe("LIVE");
      expect(a.credential_id).toMatch(/^cred_/);
    }

    // The broker posts a load to the carrier, and the two agents negotiate it without anyone watching.
    const tenderPage = await broker.client.get("/tender");
    expect(tenderPage.status).toBe(200);
    const carrierAgentId = agents.find((a) => a.agent_id.includes("2751903"))!.agent_id;
    const day = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString().slice(0, 10);
    const posted = await broker.client.post("/tender", {
      csrf: Client.csrf(tenderPage.body), loadRef: "L-PILOT-0001", to: carrierAgentId,
      oCity: "Pasadena", oState: "TX", oZip: "77507", dCity: "Kansas City", dState: "MO", dZip: "64120",
      pickupDate: day(2), deliveryDate: day(3), miles: "780", equipment: "VAN", weightLbs: "38500",
      customerRateUsd: "2650", commodity: "Consumer packaged goods, palletized",
    });
    expect(posted.location, `tender refused: ${posted.body.slice(0, 400)}`).toMatch(/^\/loads\//);

    // Give the two agents a moment to converge, then read the outcome off the venue.
    const taskId = posted.location!.split("/loads/")[1]!;
    let state = "";
    for (let i = 0; i < 60 && state !== "COMMITTED"; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const tasks = await fetch(`${VENUE}/ops/tasks`, { headers: { authorization: `Bearer ${OPS}` } }).then((r) => r.json()) as { task: { id: string }; status: string }[];
      state = tasks.find((t) => t.task.id === taskId)?.status ?? "";
    }
    expect(state, "the negotiation did not reach a commitment").toBe("COMMITTED");

    const commitments = await fetch(`${VENUE}/ops/commitments`, { headers: { authorization: `Bearer ${OPS}` } }).then((r) => r.json()) as { loadRef: string; rateUsd: number; commitmentId: string; brokerUsdot: string; carrierUsdot: string }[];
    const c = commitments.find((x) => x.loadRef === "L-PILOT-0001")!;
    expect(c).toBeDefined();
    expect(c.brokerUsdot).toBe("3312874");
    expect(c.carrierUsdot).toBe("2751903");
    expect(c.rateUsd).toBeGreaterThan(0);
    expect(c.rateUsd).toBeLessThanOrEqual(2650 * 0.93); // inside the broker's private floor margin

    // The load shows up on the broker's own desk, and the record downloads.
    const desk = await broker.client.get("/desk");
    expect(desk.body).toContain("L-PILOT-0001");
    const bundle = await broker.client.get(`/commitments/${c.commitmentId}/bundle`);
    expect(bundle.status).toBe(200);
    const parsed = JSON.parse(bundle.body) as { artifact: { commitmentId: string; underwriting: { decision: string; reasonCode?: string } } };
    expect(parsed.artifact.commitmentId).toBe(c.commitmentId);
    // No guarantee is offered, and the record says so rather than implying cover.
    expect(parsed.artifact.underwriting.decision).toBe("UNGUARANTEED");
    expect(parsed.artifact.underwriting.reasonCode).toBe("GUARANTEE_NOT_OFFERED");
  }, 180_000);

  it("refuses a USDOT that is already claimed, and one with no brokerage authority", async () => {
    const staff = new Client(APP);
    await staff.post("/login", { email: BOOT.email, password: BOOT.password });
    const sp = await staff.get("/staff");
    await staff.post("/staff/invite", { csrf: Client.csrf(sp.body), email: "someone@else.test", orgName: "Someone Else LLC", orgRole: "broker" });
    const db = appDb();
    const code = (db.prepare("SELECT code FROM invites WHERE email = ? AND accepted_at IS NULL").get("someone@else.test") as { code: string }).code;
    db.close();
    const c = new Client(APP);
    const ip = await c.get(`/invite/${code}`);
    await c.post(`/invite/${code}`, { csrf: Client.csrf(ip.body), name: "Imposter", password: "another-long-password-7" });

    // taken by the broker onboarded above
    let ob = await c.get("/onboarding");
    const p1 = await c.post("/onboarding/claim", { csrf: Client.csrf(ob.body), usdot: "3312874" });
    ob = await c.get(p1.location!);
    const taken = await c.post("/onboarding/claim-confirm", { csrf: Client.csrf(ob.body), usdot: "3312874" });
    expect(taken.location).toBe("/onboarding");
    ob = await c.get("/onboarding");
    expect(ob.body).toContain("already claimed");

    // a carrier-only entity cannot be claimed as a broker
    const p2 = await c.post("/onboarding/claim", { csrf: Client.csrf(ob.body), usdot: "4102217" });
    ob = await c.get(p2.location!);
    await c.post("/onboarding/claim-confirm", { csrf: Client.csrf(ob.body), usdot: "4102217" });
    ob = await c.get("/onboarding");
    expect(ob.body).toContain("no active brokerage authority");
  }, 60_000);
});
