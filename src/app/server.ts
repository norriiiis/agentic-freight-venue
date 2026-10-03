/**
 * The hosted console: the application a client signs into.
 *
 *   APP_PORT              listen port (default 4200)
 *   APP_URL               public base URL, used in invitations and emails
 *   APP_DATA_DIR          this application's own state (default .data/app)
 *   APP_MASTER_KEY        32 bytes base64 — wraps principal keys when APP_KEY_STORE=local
 *   APP_KEY_STORE         local | vault | external   (default local)
 *   VAULT_ADDR, VAULT_TOKEN, VAULT_TRANSIT_MOUNT     when APP_KEY_STORE=vault
 *   APP_MAIL              console | http            (default console)
 *   APP_MAIL_PROVIDER     resend | postmark;  APP_MAIL_TOKEN, APP_MAIL_FROM
 *   APP_VENUE_URL         the venue (default http://127.0.0.1:4100)
 *   APP_VENUE_OPS_TOKEN   must equal the venue's VENUE_OPS_TOKEN
 *   APP_REGISTRY_URL      the registry this venue reads (default http://127.0.0.1:4400)
 *   APP_REGISTRY_ID       its id, for display (default fmcsa-li-mock)
 *   APP_SECURE_COOKIES=1  set when served over TLS
 *   APP_BOOTSTRAP_EMAIL / APP_BOOTSTRAP_PASSWORD   first operator account, created once at startup
 *   AGENT_LLM_URL etc.    passed through to every agent this service runs
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { AppDb, type AgentRow, type MemberRole, type OrgRole, type OrgRow } from "./db";
import { Auth, cookie, hashPassword, may, newId, newInviteCode, passwordProblems, verifyPassword } from "./auth";
import { keyStoreFromEnv } from "./keys";
import { notifierFromEnv } from "../protocol/notify";
import { FileKeyProvider, loadOrCreate } from "../protocol/keys";
import { RegistryClient, VenueClient } from "./venue";
import { Supervisor } from "./supervisor";
import { Onboarding, STARTING_LIMITS, stepOf } from "./onboarding";
import { CSS, esc, plain, shell, when, type ShellNav, type Tone } from "./views";
import { deskPage, invitePage, loadPage, loginPage, mandateForm, onboardingPage, refusalPage, staffPage, tenderPage } from "./pages";
import { validateLimits } from "../mandate/validate";
import type { MandateLimits } from "../mandate/types";
import { REASONS } from "../protocol/reasons";

const PORT = Number(process.env.APP_PORT ?? 4200);
const APP_URL = process.env.APP_URL ?? `http://127.0.0.1:${PORT}`;
const DATA = process.env.APP_DATA_DIR ?? ".data/app";

/**
 * The disclosure every page carries. The venue and the registry mirror it
 * reads are operated by the same company, and a reader who does not know that
 * cannot judge what a "registry attestation" is worth here. Saying so is not
 * optional: the whole design exists to stop one party vouching for itself
 * silently, and this deployment has one party doing exactly that, out loud.
 */
const DISCLOSURE = "This venue and the registry mirror it reads are operated by the same company. A registry attestation here is our signature over data we mirrored from FMCSA — not an independent party's word. Standing is still re-read and signed before every step, and every record you can download verifies on its own; but until a second, independent mirror signs alongside us, treat the registry's word as ours. No guarantee is offered on transactions at this time.";

const db = new AppDb(join(DATA, "app.db"));
const keys = keyStoreFromEnv(db);
const mail = notifierFromEnv("APP_", process.env, join(DATA, "sent-mail.jsonl"));
/**
 * This service's own identity as a control verifier. It signs only one thing: a statement that an operator
 * verified a client by hand, bound to the key being registered. The venue takes that word only if the operator
 * pinned this key in VENUE_CONTROL_VERIFIERS — so until that is done, the hand-verification path simply does not
 * work, which is the correct failure.
 */
const verifierId = process.env.APP_VERIFIER_ID ?? "interchange-console";
const verifierKp = loadOrCreate(new FileKeyProvider((n) => join(DATA, `${n}.jwk.json`)), "control-verifier");
const venue = new VenueClient(process.env.APP_VENUE_URL ?? "http://127.0.0.1:4100", process.env.APP_VENUE_OPS_TOKEN);
const registry = new RegistryClient(process.env.APP_REGISTRY_URL ?? "http://127.0.0.1:4400", process.env.APP_REGISTRY_ID ?? "fmcsa-li-mock");
const supervisor = new Supervisor(db, {
  dataRoot: DATA,
  venueUrl: venue.url,
  llm: process.env.AGENT_LLM_URL ? { url: process.env.AGENT_LLM_URL, model: process.env.AGENT_LLM_MODEL, key: process.env.AGENT_LLM_KEY, flavor: process.env.AGENT_LLM_FLAVOR } : undefined,
});
const onboarding = new Onboarding({ db, keys, mail, registry, venue, supervisor, appUrl: APP_URL, verifier: { verifierId, kp: verifierKp } });
const auth = new Auth(db, process.env.APP_SECURE_COOKIES === "1");

// ----------------------------------------------------------------- plumbing

type Params = Record<string, string>;
interface Req { req: IncomingMessage; res: ServerResponse; url: URL; params: Params; form: Params; session?: ReturnType<Auth["current"]>; org?: OrgRow & { memberRole: MemberRole } }

const html = (res: ServerResponse, body: string, status = 200) => { res.writeHead(status, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff", "referrer-policy": "same-origin" }); res.end(body); };
const redirect = (res: ServerResponse, to: string) => { res.writeHead(303, { location: to }); res.end(); };
const json = (res: ServerResponse, body: unknown, status = 200) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };

async function readForm(req: IncomingMessage): Promise<Params> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) { size += (c as Buffer).length; if (size > 256 * 1024) throw new Error("body too large"); chunks.push(c as Buffer); }
  const out: Params = {};
  for (const [k, v] of new URLSearchParams(Buffer.concat(chunks).toString("utf8"))) out[k] = v;
  return out;
}

const flashes = new Map<string, { tone: Tone; text: string }>();
const setFlash = (sessionId: string, tone: Tone, text: string) => { flashes.set(sessionId, { tone, text }); };
const takeFlash = (sessionId?: string) => { if (!sessionId) return undefined; const f = flashes.get(sessionId); flashes.delete(sessionId); return f; };

function navFor(org: OrgRow | undefined, active: string, staff: boolean): ShellNav[] {
  const n: ShellNav[] = [];
  if (org && org.status !== "LIVE") n.push({ href: "/onboarding", label: "Finish setting up", active: active === "onboarding" });
  if (org) {
    n.push({ href: "/desk", label: "Desk", active: active === "desk" });
    if (org.role === "broker" && org.status === "LIVE") n.push({ href: "/tender", label: "Post a load", active: active === "tender" });
    n.push({ href: "/mandate", label: "Mandate", active: active === "mandate" });
    n.push({ href: "/verify", label: "Verify a record", active: active === "verify" });
  }
  if (staff) n.push({ href: "/staff", label: "Operations", active: active === "staff" });
  return n;
}

async function currentAgentRow(orgId: string): Promise<AgentRow | undefined> { return db.agentsOf(orgId)[0]; }

/** Back to the onboarding page, keeping the client context a staff member is working inside. */
const back = (c: Req) => `/onboarding${c.url.searchParams.get("org") ? `?org=${encodeURIComponent(c.url.searchParams.get("org")!)}` : ""}`;

function page(c: Req, o: { title: string; heading?: string; headingMeta?: string; actions?: string; active: string; body: string }) {
  const org = c.org;
  const entity = org ? db.entity(org.id) : undefined;
  const agent = org ? db.agentsOf(org.id)[0] : undefined;
  const mandate = org ? db.currentMandate(org.id) : undefined;
  return html(c.res, shell({
    title: o.title, heading: o.heading, headingMeta: o.headingMeta, actions: o.actions,
    org: org ? { name: org.name, usdot: entity?.usdot, mc: entity?.mc ?? null, role: org.role } : undefined,
    orgSwitcher: c.session ? db.orgsFor(c.session.user.id).map((x) => ({ id: x.id, name: x.name, active: x.id === org?.id })) : [],
    nav: navFor(org, o.active, c.session?.user.isStaff === 1),
    agent: agent ? { agentId: agent.agentId, status: agent.status, mandateExpiresAt: mandate?.expiresAt, note: agent.status === "LIVE" ? "Online" : agent.lastError ?? agent.status } : undefined,
    staff: o.active === "staff",
    flash: takeFlash(c.session?.session.id),
    disclosure: DISCLOSURE,
    body: o.body,
  }));
}

// ------------------------------------------------------------------- routes

type Handler = (c: Req) => Promise<void> | void;
const routes: { method: string; pattern: RegExp; keys: string[]; need: "none" | "user" | "org" | "staff"; h: Handler }[] = [];
function route(method: string, path: string, need: "none" | "user" | "org" | "staff", h: Handler) {
  const keys: string[] = [];
  const pattern = new RegExp(`^${path.replace(/:([a-zA-Z]+)/g, (_, k: string) => { keys.push(k); return "([^/]+)"; })}$`);
  routes.push({ method, pattern, keys, need, h });
}

// ---- static + health
route("GET", "/app.css", "none", (c) => { c.res.writeHead(200, { "content-type": "text/css; charset=utf-8", "cache-control": "public, max-age=300" }); c.res.end(CSS); });
route("GET", "/healthz", "none", async (c) => {
  const v = await venue.health().then(() => true).catch(() => false);
  const r = await registry.health().then(() => true).catch(() => false);
  json(c.res, { ok: true, venue: v, registry: r, agents: db.allAgents().map((a) => ({ agentId: a.agentId, status: a.status })) });
});

// ---- sessions
route("GET", "/", "none", (c) => redirect(c.res, c.session ? "/desk" : "/login"));
route("GET", "/login", "none", (c) => c.session ? redirect(c.res, "/desk") : html(c.res, plain({ title: "Sign in", body: loginPage("bootstrap"), flash: takeFlash("login") })));
route("POST", "/login", "none", async (c) => {
  const u = db.userByEmail(c.form.email ?? "");
  if (!u || !verifyPassword(c.form.password ?? "", u.pwHash)) {
    db.audit({ event: "auth.login", outcome: "REFUSED", detail: { email: c.form.email } });
    setFlash("login", "bad", "That email and password do not match.");
    return html(c.res, plain({ title: "Sign in", body: loginPage("bootstrap", c.form.email ?? ""), flash: { tone: "bad", text: "That email and password do not match." } }), 401);
  }
  auth.start(c.res, u.id);
  db.audit({ actorUserId: u.id, event: "auth.login", outcome: "ALLOWED" });
  redirect(c.res, "/");
});
route("POST", "/logout", "user", (c) => { db.audit({ actorUserId: c.session!.user.id, event: "auth.logout", outcome: "ALLOWED" }); auth.end(c.req, c.res); redirect(c.res, "/login"); });

route("GET", "/invite/:code", "none", (c) => {
  const i = db.invite(c.params.code!);
  if (!i || i.acceptedAt || new Date(i.expiresAt) < new Date()) return html(c.res, plain({ title: "Invitation", body: `<h1 style="font-size:20px;font-weight:600">That invitation is no longer valid</h1><p class="hint" style="margin-top:8px">Ask whoever sent it for a new one.</p>` }), 404);
  html(c.res, plain({ title: "Set up your account", body: invitePage("bootstrap", i) }));
});
route("POST", "/invite/:code", "none", async (c) => {
  const i = db.invite(c.params.code!);
  if (!i || i.acceptedAt || new Date(i.expiresAt) < new Date()) return html(c.res, plain({ title: "Invitation", body: `<p>That invitation is no longer valid.</p>` }), 404);
  const problems = passwordProblems(c.form.password ?? "");
  if (problems.length || !(c.form.name ?? "").trim()) {
    return html(c.res, plain({ title: "Set up your account", body: invitePage("bootstrap", i), flash: { tone: "bad", text: problems[0] ?? "Tell us your name." } }), 400);
  }
  const userId = newId("usr");
  const orgId = i.orgId ?? newId("org");
  db.tx(() => {
    db.run("INSERT INTO users (id, email, name, pw_hash, created_at, is_staff) VALUES (?, ?, ?, ?, ?, 0)", userId, i.email.toLowerCase(), (c.form.name ?? "").trim(), hashPassword(c.form.password!), new Date().toISOString());
    if (!i.orgId) db.run("INSERT INTO orgs (id, name, role, status, created_at) VALUES (?, ?, ?, 'NEW', ?)", orgId, i.orgName ?? i.email, i.orgRole ?? "broker", new Date().toISOString());
    db.run("INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)", orgId, userId, i.memberRole);
    db.run("UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE code = ?", new Date().toISOString(), userId, i.code);
  });
  db.audit({ actorUserId: userId, orgId, event: "account.created", outcome: "ALLOWED", detail: { email: i.email } });
  auth.start(c.res, userId);
  redirect(c.res, "/onboarding");
});

route("POST", "/switch-org", "user", (c) => {
  const m = db.membership(c.form.orgId ?? "", c.session!.user.id);
  if (m) c.res.setHeader("set-cookie", `fv_org=${encodeURIComponent(c.form.orgId!)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 86400}`);
  redirect(c.res, "/");
});

// ---- onboarding
route("GET", "/onboarding", "org", async (c) => {
  const org = c.org!;
  const e = db.entity(org.id);
  const key = db.principalKey(org.id);
  const mandate = db.currentMandate(org.id);
  const agent = await currentAgentRow(org.id);
  const outstanding = db.one<{ sentTo: string | null }>("SELECT sent_to FROM proofs WHERE org_id = ? AND status = 'PENDING' ORDER BY created_at DESC", org.id);
  // A pending lookup is shown live from the registry; it is not written anywhere until the client says it is them.
  const preview = c.url.searchParams.get("usdot");
  const previewRecord = preview ? (await onboarding.lookup(preview).catch(() => undefined))?.record : undefined;
  page(c, {
    title: "Set up", heading: "Set up", active: "onboarding",
    body: onboardingPage({
      csrf: c.session!.session.csrf, step: stepOf(org.status), orgName: org.name, orgRole: org.role,
      entity: e, snapshot: (previewRecord as Record<string, unknown> | undefined) ?? (e?.snapshot ? JSON.parse(e.snapshot) : undefined),
      proofs: db.proofs(org.id), challengeOutstanding: outstanding ?? undefined,
      keyKid: key?.kid, keyDisclosure: keys.disclosure,
      limits: mandate ? (JSON.parse(mandate.limits) as MandateLimits) : STARTING_LIMITS[org.role],
      mandate: mandate ? { mandateId: mandate.mandateId, expiresAt: mandate.expiresAt, signedAt: mandate.signedAt } : undefined,
      agent: agent ? { agentId: agent.agentId, status: agent.status, credentialId: agent.credentialId, lastError: agent.lastError } : undefined,
      canOperate: may(org.memberRole, "operator"), isStaff: c.session!.user.isStaff === 1,
    }),
  });
});

/** Look the number up and show what the registry says. Nothing is claimed until the client confirms it is them. */
route("POST", "/onboarding/claim", "org", async (c) => {
  const usdot = (c.form.usdot ?? "").trim();
  const look = await onboarding.lookup(usdot).catch(() => undefined);
  if (!look?.found) { setFlash(c.session!.session.id, "bad", `The registry has no record for USDOT ${usdot}.`); return redirect(c.res, "/onboarding"); }
  redirect(c.res, `/onboarding?usdot=${encodeURIComponent(usdot)}${c.url.searchParams.get("org") ? `&org=${encodeURIComponent(c.url.searchParams.get("org")!)}` : ""}`);
});
route("POST", "/onboarding/claim-confirm", "org", async (c) => {
  const r = await onboarding.claimEntity(c.org!.id, c.form.usdot ?? "", c.session!.user.id);
  if (!r.ok) setFlash(c.session!.session.id, "bad", r.error);
  redirect(c.res, "/onboarding");
});
route("POST", "/onboarding/challenge", "org", async (c) => {
  const r = await onboarding.startChallenge(c.org!.id, c.session!.user.id);
  setFlash(c.session!.session.id, r.ok ? "good" : "bad", r.ok ? `The venue sent a code to ${r.sentTo}, the contact point on the public record. We do not see it.` : r.error);
  redirect(c.res, back(c));
});
route("POST", "/onboarding/verify", "org", async (c) => {
  const r = await onboarding.verifyChallenge(c.org!.id, c.form.code ?? "", c.session!.user.id);
  if (!r.ok) setFlash(c.session!.session.id, "bad", r.error);
  redirect(c.res, back(c));
});
route("POST", "/onboarding/attest", "staff", (c) => {
  const r = onboarding.operatorAttest(c.org!.id, c.session!.user.id, c.session!.user.name, c.form.evidence ?? "");
  if (!r.ok) setFlash(c.session!.session.id, "bad", r.error);
  redirect(c.res, back(c));
});
route("POST", "/onboarding/key", "org", async (c) => {
  const r = await onboarding.createKey(c.org!.id, c.session!.user.id);
  if (!r.ok) setFlash(c.session!.session.id, "bad", r.error);
  redirect(c.res, "/onboarding");
});
route("POST", "/onboarding/mandate", "org", async (c) => {
  const limits = limitsFromForm(c.form, c.org!.role);
  const r = await onboarding.signMandate(c.org!.id, limits, c.session!.user.id);
  if (!r.ok) { setFlash(c.session!.session.id, "bad", r.errors.join(" ")); return redirect(c.res, "/onboarding"); }
  redirect(c.res, "/onboarding");
});
route("POST", "/onboarding/agent", "org", async (c) => {
  const r = await onboarding.provisionAndStart(c.org!.id, c.session!.user.id);
  setFlash(c.session!.session.id, r.ok ? "good" : "bad", r.ok ? "Your agent is live." : r.error);
  redirect(c.res, r.ok ? "/desk" : "/onboarding");
});

function limitsFromForm(f: Params, role: OrgRole): MandateLimits {
  const num = (k: string) => (f[k] === undefined || f[k] === "" ? undefined : Number(f[k]));
  const list = (k: string) => (f[k] ?? "").trim().split(/[\s,]+/).filter(Boolean).map((s) => s.toUpperCase());
  return {
    minRatePerLoadUsd: num("minRatePerLoadUsd"), maxRatePerLoadUsd: num("maxRatePerLoadUsd"),
    minRatePerMileUsd: num("minRatePerMileUsd"), maxRatePerMileUsd: num("maxRatePerMileUsd"),
    allowedLaneRegions: list("allowedLaneRegions"),
    allowedEquipment: list("allowedEquipment") as MandateLimits["allowedEquipment"],
    hazmatPermitted: f.hazmatPermitted === "true",
    requiredCounterpartyInsuranceUsd: num("requiredCounterpartyInsuranceUsd") ?? 0,
    maxPerCounterpartyExposureUsd: num("maxPerCounterpartyExposureUsd") ?? 0,
    maxDailyExposureUsd: num("maxDailyExposureUsd") ?? 0,
    requireGuarantee: false,
    requireInsurerAttestation: f.requireInsurerAttestation === "true",
    mayTender: role === "broker",
    maxNegotiationRounds: num("maxNegotiationRounds") ?? 10,
    paymentTermsDays: { min: num("paymentMin") ?? 0, max: num("paymentMax") ?? 45 },
  };
}

// ---- desk
route("GET", "/desk", "org", async (c) => {
  const org = c.org!;
  if (org.status !== "LIVE") return redirect(c.res, "/onboarding");
  const agent = (await currentAgentRow(org.id))!;
  const mandate = db.currentMandate(org.id);
  const limits = mandate ? (JSON.parse(mandate.limits) as MandateLimits) : undefined;
  const mine = agent.agentId;
  const [commitments, tasks, audit] = await Promise.all([
    venue.commitments().catch(() => []),
    venue.tasks().catch(() => []),
    venue.audit().catch(() => []),
  ]);
  const ours = (commitments as unknown as { brokerAgentId: string; carrierAgentId: string; commitmentId: string; loadRef: string; rateUsd: number; status: string }[]).filter((x) => x.brokerAgentId === mine || x.carrierAgentId === mine);
  const today = new Date().toISOString().slice(0, 10);
  const exposureToday = ours.filter((x) => x.status !== "VOIDED").reduce((a, x) => a + (x.rateUsd ?? 0), 0);
  const byCp = new Map<string, number>();
  for (const x of ours) { if (x.status === "VOIDED") continue; const cp = x.brokerAgentId === mine ? x.carrierAgentId : x.brokerAgentId; byCp.set(cp, (byCp.get(cp) ?? 0) + (x.rateUsd ?? 0)); }
  const worstEntry = [...byCp.entries()].sort((a, b) => b[1] - a[1])[0];
  const openTasks = (tasks as unknown as { task: { id: string; status: { state: string } }; loadRef: string; brokerAgentId: string; carrierAgentId: string; round: number; status: string; onTable?: { offer: { rateUsd: number }; by: string } }[])
    .filter((t) => (t.brokerAgentId === mine || t.carrierAgentId === mine) && t.status === "NEGOTIATING");
  const refusals = (audit as { seq: number; ts: string; component: string; event: string; outcome: string; reasonCode?: string; subject?: string; taskId?: string; evidence?: Record<string, unknown> }[])
    .filter((e) => e.outcome === "REFUSED" && JSON.stringify(e.evidence ?? {}).includes(mine) === false && (e.subject === mine || e.taskId !== undefined))
    .slice(-5).reverse()
    .map((e) => ({ seq: e.seq, ts: e.ts, reasonCode: e.reasonCode, component: e.component, detail: (REASONS as Record<string, string>)[e.reasonCode ?? ""] ?? e.event, taskId: e.taskId }));
  const agentAudit = await supervisor.audit(agent).catch(() => [] as Record<string, unknown>[]);
  const selfRefusals = (agentAudit as { ts: string; component: string; event: string; outcome: string; reasonCode?: string; evidence?: Record<string, unknown> }[])
    .filter((e) => e.outcome === "REFUSED" || e.event === "llm-fallback")
    .slice(-4).reverse()
    .map((e) => ({ ts: e.ts, reasonCode: e.reasonCode, event: e.event, detail: (REASONS as Record<string, string>)[e.reasonCode ?? ""] ?? JSON.stringify(e.evidence ?? {}).slice(0, 180) }));
  const regOk = await registry.health().then(() => true).catch(() => false);
  const att = regOk ? await registry.attest(db.entity(org.id)!.usdot).catch(() => undefined) : undefined;

  page(c, {
    title: "Desk", heading: "Desk", headingMeta: new Date().toISOString().slice(0, 16).replace("T", " ") + "Z", active: "desk",
    body: deskPage({
      orgRole: org.role, agentLive: agent.status === "LIVE",
      exposureToday, dailyCap: limits?.maxDailyExposureUsd ?? 0,
      worst: worstEntry ? { name: worstEntry[0], amount: worstEntry[1], cap: limits?.maxPerCounterpartyExposureUsd ?? 0 } : undefined,
      openCount: openTasks.length, committedCount: ours.length,
      refusals,
      open: openTasks.map((t) => ({ taskId: t.task.id, loadRef: t.loadRef, counterparty: t.brokerAgentId === mine ? t.carrierAgentId : t.brokerAgentId, round: t.round, theirs: t.onTable && t.onTable.by !== mine ? t.onTable.offer.rateUsd : undefined, mine: t.onTable && t.onTable.by === mine ? t.onTable.offer.rateUsd : undefined, status: t.status })),
      committed: ours.slice(-8).reverse().map((x) => ({ commitmentId: x.commitmentId, loadRef: x.loadRef, counterparty: x.brokerAgentId === mine ? x.carrierAgentId : x.brokerAgentId, rate: x.rateUsd, status: x.status })),
      selfRefusals,
      registry: { registryId: registry.registryId, ok: regOk, asOf: att?.asOf, upstreamAsOf: att?.upstreamAsOf },
    }),
  });
  void today;
});

// ---- tender
route("GET", "/tender", "org", async (c) => {
  if (c.org!.role !== "broker") return page(c, { title: "Post a load", active: "desk", body: `<div class="empty">Only a broker tenders loads.</div>` });
  const agents = await venue.agents().catch(() => []);
  const mineAgent = (await currentAgentRow(c.org!.id))?.agentId;
  const carriers = (agents as { agentId: string; envelope?: { mayTender?: boolean } }[])
    .filter((a) => a.agentId !== mineAgent)
    .map((a) => ({ agentId: a.agentId, label: a.agentId }));
  page(c, { title: "Post a load", heading: "Post a load", active: "desk", body: tenderPage(c.session!.session.csrf, carriers, new Date().toISOString().slice(0, 10)) });
});
route("POST", "/tender", "org", async (c) => {
  if (!may(c.org!.memberRole, "operator")) { setFlash(c.session!.session.id, "bad", "Only an operator or owner can post a load."); return redirect(c.res, "/tender"); }
  const agent = await currentAgentRow(c.org!.id);
  if (!agent || agent.status !== "LIVE") { setFlash(c.session!.session.id, "bad", "Your agent is not running."); return redirect(c.res, "/desk"); }
  const f = c.form;
  const iso = (d: string, hhmm: string) => `${d}T${hhmm}:00.000Z`;
  const load = {
    loadRef: f.loadRef, origin: { city: f.oCity, state: (f.oState ?? "").toUpperCase(), zip: f.oZip, windowStart: iso(f.pickupDate!, "13:00"), windowEnd: iso(f.pickupDate!, "19:00") },
    destination: { city: f.dCity, state: (f.dState ?? "").toUpperCase(), zip: f.dZip, windowStart: iso(f.deliveryDate!, "13:00"), windowEnd: iso(f.deliveryDate!, "21:00") },
    equipment: f.equipment, weightLbs: Number(f.weightLbs), commodity: f.commodity, miles: Number(f.miles), hazmat: false, subcontractPermitted: false,
  };
  await supervisor.setContext(agent, { customerRateUsd: Number(f.customerRateUsd) }).catch(() => undefined);
  const r = await supervisor.tender(agent, load, { agentId: f.to! }).catch((e: Error) => ({ error: e.message }));
  const taskId = (r as { taskId?: string }).taskId;
  db.audit({ actorUserId: c.session!.user.id, orgId: c.org!.id, event: "load.tendered", outcome: taskId ? "ALLOWED" : "REFUSED", detail: { loadRef: f.loadRef, to: f.to, taskId, result: r } });
  if (!taskId) { setFlash(c.session!.session.id, "bad", `The tender was refused: ${JSON.stringify((r as { refusal?: unknown; error?: unknown }).refusal ?? (r as { error?: unknown }).error ?? r)}`); return redirect(c.res, "/tender"); }
  setFlash(c.session!.session.id, "good", "Tendered. Your agent is negotiating.");
  redirect(c.res, `/loads/${taskId}`);
});

// ---- one load
route("GET", "/loads/:taskId", "org", async (c) => {
  const tasks = await venue.tasks().catch(() => []);
  const t = (tasks as unknown as Record<string, unknown>[]).find((x) => ((x.task as { id: string })?.id) === c.params.taskId);
  if (!t) return page(c, { title: "Load", active: "desk", body: `<div class="empty">That load is not on the venue.</div>` });
  const msgs = await venue.messages(c.params.taskId!).catch(() => []);
  const load = t.load as { origin?: { city: string; state: string }; destination?: { city: string; state: string }; equipment?: string; miles?: number; weightLbs?: number; commodity?: string } | undefined;
  const wire = (msgs as { from?: string; to?: string; data?: { type?: string; offer?: { rateUsd?: number }; terms?: { rateUsd?: number }; noteCode?: string }; ts?: string; round?: number }[]).map((m, i) => ({
    round: m.round ?? i + 1,
    from: String(m.from ?? "—"), to: String(m.to ?? "—"),
    type: String(m.data?.type ?? "—"),
    rate: m.data?.offer?.rateUsd ?? m.data?.terms?.rateUsd,
    noteCode: m.data?.noteCode,
    ts: String(m.ts ?? ""),
  }));
  const outcome = t.outcome as { reasonCode?: string; refusedBy?: string; evidence?: Record<string, unknown> } | undefined;
  page(c, {
    title: String(t.loadRef ?? "Load"), heading: String(t.loadRef ?? "Load"), active: "desk",
    body: loadPage({
      loadRef: String(t.loadRef ?? ""), status: String(t.status ?? ""), taskId: c.params.taskId!,
      lane: load?.origin && load?.destination ? `${load.origin.city}, ${load.origin.state} → ${load.destination.city}, ${load.destination.state}` : undefined,
      equipment: load?.equipment, miles: load?.miles, weightLbs: load?.weightLbs, commodity: load?.commodity,
      wire,
      outcome: { commitmentId: t.commitmentId as string | undefined, ...outcome },
      guarantee: { decision: "UNGUARANTEED" },
    }),
  });
});

route("GET", "/commitments/:id/bundle", "org", async (c) => {
  const b = await venue.bundle(c.params.id!).catch(() => undefined);
  if (!b) return json(c.res, { error: "unknown commitment" }, 404);
  c.res.writeHead(200, { "content-type": "application/json", "content-disposition": `attachment; filename="${c.params.id}.json"` });
  c.res.end(JSON.stringify(b, null, 2));
});

route("GET", "/refusals/:seq", "org", async (c) => {
  const audit = await venue.audit().catch(() => []);
  const e = (audit as { seq: number; ts: string; component: string; event: string; reasonCode?: string; subject?: string; taskId?: string; evidence?: Record<string, unknown> }[]).find((x) => String(x.seq) === c.params.seq);
  if (!e) return page(c, { title: "Refusal", active: "desk", body: `<div class="empty">No such audit entry.</div>` });
  const meaning = (REASONS as Record<string, string>)[e.reasonCode ?? ""] ?? "No description is recorded for this code.";
  page(c, {
    title: "Refusal", heading: "Refusal", headingMeta: `audit #${e.seq}`, active: "desk",
    body: refusalPage({ seq: e.seq, ts: e.ts, reasonCode: e.reasonCode, component: e.component, subject: e.subject, taskId: e.taskId, headline: meaning.split(/[;:]/)[0] ?? meaning, meaning, evidence: e.evidence ?? {} }),
  });
});

// ---- mandate
route("GET", "/mandate", "org", (c) => {
  const m = db.currentMandate(c.org!.id);
  const limits = m ? (JSON.parse(m.limits) as MandateLimits) : STARTING_LIMITS[c.org!.role];
  page(c, {
    title: "Mandate", heading: "Mandate", headingMeta: m ? `${m.mandateId.slice(0, 18)}… · expires ${m.expiresAt.slice(0, 10)}` : "not signed", active: "mandate",
    body: `<div class="card" style="max-width:880px">
      <h2>What your agent may do</h2>
      <p class="lede">Signed with your key, which your agent does not hold. Changing it re-signs it and restarts your agent on the new limits.</p>
      ${mandateForm(c.session!.session.csrf, limits, "/mandate", "Sign and apply")}
    </div>
    <div class="card" style="max-width:880px;margin-top:18px">
      <h2>Where your key lives</h2>
      <p class="small" style="margin-top:8px;line-height:1.6">${esc(keys.disclosure)}</p>
    </div>`,
  });
});
route("POST", "/mandate", "org", async (c) => {
  if (!may(c.org!.memberRole, "operator")) { setFlash(c.session!.session.id, "bad", "Only an operator or owner can change the mandate."); return redirect(c.res, "/mandate"); }
  const limits = limitsFromForm(c.form, c.org!.role);
  const problems = validateLimits(limits);
  if (problems.length) { setFlash(c.session!.session.id, "bad", problems.join(" ")); return redirect(c.res, "/mandate"); }
  const signed = await onboarding.signMandate(c.org!.id, limits, c.session!.user.id);
  if (!signed.ok) { setFlash(c.session!.session.id, "bad", signed.errors.join(" ")); return redirect(c.res, "/mandate"); }
  const agent = await currentAgentRow(c.org!.id);
  if (agent) { supervisor.stop(agent.agentId); await onboarding.provisionAndStart(c.org!.id, c.session!.user.id); }
  setFlash(c.session!.session.id, "good", "Signed. Your agent is running on the new limits.");
  redirect(c.res, "/mandate");
});

// ---- verify
route("GET", "/verify", "org", (c) => {
  page(c, {
    title: "Verify a record", heading: "Verify a record", active: "verify",
    body: `<div class="card" style="max-width:880px">
      <h2>Check a commitment without trusting us</h2>
      <p class="lede">Every commitment downloads as a bundle: the artifact, the ledger entries around it, and the signed words the venue relied on. It verifies on its own machine, against keys you choose.</p>
      <pre class="mono small" style="background:#1A1917;color:#F7F5F0;padding:16px;border-radius:4px;overflow-x:auto">npm run verify -- --bundle &lt;file.json&gt; --pins &lt;pins.json&gt;</pre>
      <p class="hint">The verifier is in this repository and runs offline. It takes the keys you pin — ours, and the registry's — and tells you the one thing that failed first, by a precedence declared in advance.</p>
    </div>`,
  });
});

// ---- staff
route("GET", "/staff", "staff", async (c) => {
  const orgs = db.orgs().map((o) => { const e = db.entity(o.id); const a = db.agentsOf(o.id)[0]; return { id: o.id, name: o.name, role: o.role, status: o.status, usdot: e?.usdot, agentStatus: a?.status, createdAt: o.createdAt }; });
  const vh = await venue.opsHealth().catch(() => undefined);
  const regOk = await registry.health().then(() => true).catch(() => false);
  page(c, {
    title: "Operations", heading: "Operations", active: "staff",
    body: staffPage({
      csrf: c.session!.session.csrf, orgs,
      invites: db.openInvites().map((i) => ({ code: i.code, email: i.email, orgName: i.orgName, expiresAt: i.expiresAt })),
      venue: { ok: !!vh, venueId: vh?.venueId, commitments: vh?.commitments, tasks: vh?.tasks, outbox: vh?.outbox, deadLetter: vh?.deadLetter },
      registry: { registryId: registry.registryId, ok: regOk },
      appUrl: APP_URL,
      audit: db.recentAudit(14).map((a) => ({ ts: a.ts, event: a.event, outcome: a.outcome, orgId: a.orgId, detail: a.detail })),
    }),
  });
});
route("POST", "/staff/invite", "staff", (c) => {
  const code = newInviteCode();
  db.run("INSERT INTO invites (code, email, org_id, org_name, org_role, member_role, created_by, created_at, expires_at) VALUES (?, ?, NULL, ?, ?, 'owner', ?, ?, ?)",
    code, (c.form.email ?? "").toLowerCase(), c.form.orgName ?? null, c.form.orgRole ?? "broker", c.session!.user.id, new Date().toISOString(), new Date(Date.now() + 14 * 86_400_000).toISOString());
  db.audit({ actorUserId: c.session!.user.id, event: "staff.invite", outcome: "ALLOWED", detail: { email: c.form.email, orgName: c.form.orgName } });
  void mail.send({ to: c.form.email!, subject: "You have been invited to Interchange", text: `Set up your account:\n\n${APP_URL}/invite/${code}\n\nThe link is good for 14 days.\n` });
  setFlash(c.session!.session.id, "good", `Invitation created for ${c.form.email}.`);
  redirect(c.res, "/staff");
});
route("GET", "/staff/org/:id", "staff", async (c) => {
  const o = db.org(c.params.id!);
  if (!o) return page(c, { title: "Client", active: "staff", body: `<div class="empty">No such organisation.</div>` });
  const e = db.entity(o.id), a = db.agentsOf(o.id)[0], m = db.currentMandate(o.id);
  page(c, {
    title: o.name, heading: o.name, headingMeta: o.status, active: "staff",
    body: `<div class="card"><dl class="kv">
      <dt>Role</dt><dd>${esc(o.role)}</dd>
      <dt>Entity</dt><dd>${e ? `${esc(e.legalName)} · USDOT ${esc(e.usdot)}` : "not claimed"}</dd>
      <dt>Proof of control</dt><dd>${db.proofs(o.id).map((p) => `${esc(p.method)} ${esc(p.status)}${p.evidence ? ` — ${esc(p.evidence)}` : ""}`).join("<br>") || "none"}</dd>
      <dt>Mandate</dt><dd class="mono">${m ? `${esc(m.mandateId.slice(0, 20))}… expires ${esc(m.expiresAt.slice(0, 10))}` : "not signed"}</dd>
      <dt>Agent</dt><dd class="mono">${a ? `${esc(a.agentId)} · ${esc(a.status)} · port ${a.port}${a.lastError ? ` · ${esc(a.lastError)}` : ""}` : "not provisioned"}</dd>
      <dt>Members</dt><dd>${db.membersOf(o.id).map((u) => `${esc(u.name)} &lt;${esc(u.email)}&gt; (${esc(u.memberRole)})`).join("<br>")}</dd>
    </dl></div>
    <div class="card" style="margin-top:18px"><h2>Their activity</h2><div style="margin-top:10px">${db.auditFor(o.id, 30).map((x) => `<div style="padding:7px 0;border-top:1px solid #EFEBE2;display:flex;gap:10px"><span class="mono small muted" style="width:70px">${esc(when(x.ts))}</span><span class="mono small" style="flex-grow:1">${esc(x.event)}</span><span class="small">${esc(x.outcome)}</span></div>`).join("")}</div></div>`,
  });
});

// ------------------------------------------------------------------ dispatch

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", APP_URL);
  const method = req.method ?? "GET";
  try {
    const match = routes.find((r) => r.method === method && r.pattern.test(url.pathname));
    if (!match) return html(res, plain({ title: "Not found", body: `<h1 style="font-size:20px;font-weight:600">Not found</h1>` }), 404);
    const m = url.pathname.match(match.pattern)!;
    const params: Params = {};
    match.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1] ?? "")));
    const form = method === "POST" ? await readForm(req) : {};
    const session = auth.current(req);

    if (match.need !== "none" && !session) return redirect(res, "/login");
    if (match.need === "staff" && session!.user.isStaff !== 1) return html(res, plain({ title: "Not allowed", body: `<p>That is an operator page.</p>` }), 403);
    // Every state-changing request carries the session's CSRF token.
    if (method === "POST" && session && url.pathname !== "/login" && !url.pathname.startsWith("/invite/")) {
      if (form.csrf !== session.session.csrf) return html(res, plain({ title: "Expired", body: `<p>That form expired. Go back and try again.</p>` }), 400);
    }
    let org: (OrgRow & { memberRole: MemberRole }) | undefined;
    if (session) {
      const mine = db.orgsFor(session.user.id);
      const want = cookie(req, "fv_org");
      org = mine.find((o) => o.id === want) ?? mine[0];
      // A staff member helping a client works inside that client's context: any organisation, with owner rights,
      // and every action they take there is written to that client's own activity log under their user id.
      const asOrg = url.searchParams.get("org");
      if (session.user.isStaff === 1 && asOrg) {
        const target = db.org(asOrg);
        if (target) org = { ...target, memberRole: "owner" as MemberRole };
      }
    }
    if (match.need === "org" && !org) return html(res, plain({ title: "No organisation", body: `<p>Your account is not attached to a company yet. Ask whoever invited you.</p>` }), 403);
    await match.h({ req, res, url, params, form, session, org });
  } catch (e) {
    console.error("[app]", e);
    if (!res.headersSent) html(res, plain({ title: "Something broke", body: `<h1 style="font-size:20px;font-weight:600">Something broke</h1><p class="hint">It is in the server log. Nothing was signed.</p>` }), 500);
  }
});

// ----------------------------------------------------------------- bootstrap

async function main() {
  db.sweepSessions();
  setInterval(() => db.sweepSessions(), 3_600_000).unref();

  const haveUsers = db.one<{ n: number }>("SELECT COUNT(*) AS n FROM users");
  if ((haveUsers?.n ?? 0) === 0) {
    const email = process.env.APP_BOOTSTRAP_EMAIL;
    const pw = process.env.APP_BOOTSTRAP_PASSWORD;
    if (email && pw) {
      const id = newId("usr");
      db.run("INSERT INTO users (id, email, name, pw_hash, created_at, is_staff) VALUES (?, ?, ?, ?, ?, 1)", id, email.toLowerCase(), "Operator", hashPassword(pw), new Date().toISOString());
      db.audit({ actorUserId: id, event: "bootstrap.operator", outcome: "ALLOWED", detail: { email } });
      console.log(`[app] created the first operator account: ${email}`);
    } else {
      console.log("[app] no users yet. Set APP_BOOTSTRAP_EMAIL and APP_BOOTSTRAP_PASSWORD and restart to create the first operator.");
    }
  }

  await supervisor.recover();
  supervisor.watch();
  server.listen(PORT, process.env.APP_HOST ?? "127.0.0.1", () => {
    console.log(`[app] console on ${APP_URL}`);
    console.log(`[app] venue ${venue.url} · registry ${registry.url} (${registry.registryId}) · key custody: ${keys.kind} · mail: ${mail.kind}`);
    // The venue takes this service's word about a hand-verification only if it pins this key. Print the line to paste.
    console.log(`[app] control verifier "${verifierId}" kid ${verifierKp.kid}`);
    console.log(`[app] to let operators verify clients by hand, set on the venue:\n  VENUE_CONTROL_METHODS=REGISTRY_CONTACT_CHALLENGE,OPERATOR_ATTESTED\n  VENUE_CONTROL_VERIFIERS='${JSON.stringify([{ verifierId, publicKey: verifierKp.publicJwk, methods: ["OPERATOR_ATTESTED"] }])}'`);
  });
  const bye = () => { supervisor.stopAll(); server.close(); db.close(); process.exit(0); };
  process.on("SIGINT", bye);
  process.on("SIGTERM", bye);
}

void main();
