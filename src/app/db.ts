/**
 * The tenant application's own store, separate from the venue's.
 *
 * This process is NOT the venue. It is the operator of the principals' side:
 * it holds accounts, the custody record for each principal's signing key, and
 * the agents it runs on their behalf. It reaches the venue over HTTP like any
 * other client, and holds nothing the venue would have to trust it about.
 *
 * Plain relational rows rather than the venue's key/value tables: this data is
 * queried by humans (who is in this org, which agents are down, which
 * onboardings are stuck) rather than loaded wholesale into a working set.
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type OrgStatus = "NEW" | "ENTITY_CLAIMED" | "CONTROL_PROVEN" | "MANDATE_SIGNED" | "LIVE" | "SUSPENDED";
export type OrgRole = "broker" | "carrier";
export type MemberRole = "owner" | "operator" | "viewer";

export interface OrgRow { id: string; name: string; role: OrgRole; status: OrgStatus; createdAt: string }
export interface UserRow { id: string; email: string; name: string; pwHash: string; createdAt: string; lastLoginAt: string | null; isStaff: number }
export interface MembershipRow { orgId: string; userId: string; role: MemberRole }
export interface SessionRow { id: string; userId: string; createdAt: string; expiresAt: string; csrf: string }
export interface InviteRow { code: string; email: string; orgId: string | null; orgName: string | null; orgRole: OrgRole | null; memberRole: MemberRole; createdBy: string; createdAt: string; expiresAt: string; acceptedAt: string | null; acceptedBy: string | null }
export interface EntityRow { orgId: string; usdot: string; mc: string | null; legalName: string; entityType: string; registryAsOf: string | null; snapshot: string | null }
export interface ProofRow { id: string; orgId: string; method: string; status: "PENDING" | "VERIFIED" | "FAILED"; challenge: string | null; sentTo: string | null; createdAt: string; verifiedAt: string | null; operatorUserId: string | null; evidence: string | null; subjectKid: string | null; proof: string | null }
export interface PrincipalKeyRow { orgId: string; kid: string; publicJwk: string; store: string; wrapped: string | null; createdAt: string; retiredAt: string | null }
export interface AgentRow { id: string; orgId: string; agentId: string; role: OrgRole; port: number; dataDir: string; status: "PROVISIONED" | "STARTING" | "LIVE" | "STOPPED" | "FAILED"; controlToken: string; credentialId: string | null; pid: number | null; startedAt: string | null; lastHealthAt: string | null; lastError: string | null; privateContext: string }
export interface MandateRow { id: string; orgId: string; agentId: string; mandateId: string; limits: string; signedAt: string; expiresAt: string; registeredAt: string | null; supersededAt: string | null }
export interface AuditRow { seq: number; ts: string; actorUserId: string | null; orgId: string | null; event: string; outcome: string; detail: string | null }

const SCHEMA = `
CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, pw_hash TEXT NOT NULL,
  created_at TEXT NOT NULL, last_login_at TEXT, is_staff INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS memberships (
  org_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (org_id, user_id));
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, csrf TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY, email TEXT NOT NULL, org_id TEXT, org_name TEXT, org_role TEXT,
  member_role TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  accepted_at TEXT, accepted_by TEXT);
CREATE TABLE IF NOT EXISTS entities (
  org_id TEXT PRIMARY KEY, usdot TEXT NOT NULL, mc TEXT, legal_name TEXT NOT NULL, entity_type TEXT NOT NULL,
  registry_as_of TEXT, snapshot TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS entities_usdot ON entities (usdot);
CREATE TABLE IF NOT EXISTS proofs (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL, method TEXT NOT NULL, status TEXT NOT NULL, challenge TEXT,
  sent_to TEXT, created_at TEXT NOT NULL, verified_at TEXT, operator_user_id TEXT, evidence TEXT,
  subject_kid TEXT, proof TEXT);
CREATE INDEX IF NOT EXISTS proofs_org ON proofs (org_id);
CREATE TABLE IF NOT EXISTS principal_keys (
  org_id TEXT NOT NULL, kid TEXT NOT NULL, public_jwk TEXT NOT NULL, store TEXT NOT NULL, wrapped TEXT,
  created_at TEXT NOT NULL, retired_at TEXT, PRIMARY KEY (org_id, kid));
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL, agent_id TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
  port INTEGER NOT NULL, data_dir TEXT NOT NULL, status TEXT NOT NULL, control_token TEXT NOT NULL,
  credential_id TEXT, pid INTEGER, started_at TEXT, last_health_at TEXT, last_error TEXT,
  private_context TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS mandates (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL, agent_id TEXT NOT NULL, mandate_id TEXT NOT NULL,
  limits TEXT NOT NULL, signed_at TEXT NOT NULL, expires_at TEXT NOT NULL, registered_at TEXT, superseded_at TEXT);
CREATE INDEX IF NOT EXISTS mandates_org ON mandates (org_id);
CREATE TABLE IF NOT EXISTS app_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor_user_id TEXT, org_id TEXT,
  event TEXT NOT NULL, outcome TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS app_audit_org ON app_audit (org_id, seq);
`;

const camel = <T>(r: Record<string, unknown> | undefined): T | undefined =>
  r === undefined ? undefined : (Object.fromEntries(Object.entries(r).map(([k, v]) => [k.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase()), v])) as T);

export class AppDb {
  readonly db: DatabaseSync;
  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA);
  }
  run(sql: string, ...args: (string | number | null)[]) { this.db.prepare(sql).run(...args); }
  one<T>(sql: string, ...args: (string | number | null)[]): T | undefined { return camel<T>(this.db.prepare(sql).get(...args) as Record<string, unknown> | undefined); }
  many<T>(sql: string, ...args: (string | number | null)[]): T[] { return (this.db.prepare(sql).all(...args) as Record<string, unknown>[]).map((r) => camel<T>(r)!); }
  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try { const v = fn(); this.db.exec("COMMIT"); return v; } catch (e) { this.db.exec("ROLLBACK"); throw e; }
  }

  // ------------------------------------------------------------- queries
  org(id: string) { return this.one<OrgRow>("SELECT * FROM orgs WHERE id = ?", id); }
  orgs() { return this.many<OrgRow>("SELECT * FROM orgs ORDER BY created_at DESC"); }
  user(id: string) { return this.one<UserRow>("SELECT * FROM users WHERE id = ?", id); }
  userByEmail(email: string) { return this.one<UserRow>("SELECT * FROM users WHERE email = ?", email.toLowerCase()); }
  membership(orgId: string, userId: string) { return this.one<MembershipRow>("SELECT * FROM memberships WHERE org_id = ? AND user_id = ?", orgId, userId); }
  orgsFor(userId: string) { return this.many<OrgRow & { memberRole: MemberRole }>("SELECT o.*, m.role AS member_role FROM orgs o JOIN memberships m ON m.org_id = o.id WHERE m.user_id = ? ORDER BY o.created_at", userId); }
  membersOf(orgId: string) { return this.many<UserRow & { memberRole: MemberRole }>("SELECT u.*, m.role AS member_role FROM users u JOIN memberships m ON m.user_id = u.id WHERE m.org_id = ? ORDER BY u.created_at", orgId); }
  entity(orgId: string) { return this.one<EntityRow>("SELECT * FROM entities WHERE org_id = ?", orgId); }
  entityByUsdot(usdot: string) { return this.one<EntityRow>("SELECT * FROM entities WHERE usdot = ?", usdot); }
  proofs(orgId: string) { return this.many<ProofRow>("SELECT * FROM proofs WHERE org_id = ? ORDER BY created_at DESC", orgId); }
  /** The proof that will be presented when this org's agent registers its key. */
  provenControl(orgId: string) { return this.one<ProofRow>("SELECT * FROM proofs WHERE org_id = ? AND status = 'VERIFIED' AND proof IS NOT NULL ORDER BY verified_at DESC", orgId); }
  principalKey(orgId: string) { return this.one<PrincipalKeyRow>("SELECT * FROM principal_keys WHERE org_id = ? AND retired_at IS NULL", orgId); }
  agentsOf(orgId: string) { return this.many<AgentRow>("SELECT * FROM agents WHERE org_id = ? ORDER BY agent_id", orgId); }
  allAgents() { return this.many<AgentRow>("SELECT * FROM agents ORDER BY agent_id"); }
  agentByAgentId(agentId: string) { return this.one<AgentRow>("SELECT * FROM agents WHERE agent_id = ?", agentId); }
  currentMandate(orgId: string) { return this.one<MandateRow>("SELECT * FROM mandates WHERE org_id = ? AND superseded_at IS NULL ORDER BY signed_at DESC", orgId); }
  invite(code: string) { return this.one<InviteRow>("SELECT * FROM invites WHERE code = ?", code); }
  openInvites() { return this.many<InviteRow>("SELECT * FROM invites WHERE accepted_at IS NULL ORDER BY created_at DESC"); }

  /** Append-only record of who did what in this application — distinct from the venue's own audit chain. */
  audit(e: { actorUserId?: string | null; orgId?: string | null; event: string; outcome: string; detail?: unknown }) {
    this.run("INSERT INTO app_audit (ts, actor_user_id, org_id, event, outcome, detail) VALUES (?, ?, ?, ?, ?, ?)",
      new Date().toISOString(), e.actorUserId ?? null, e.orgId ?? null, e.event, e.outcome, e.detail === undefined ? null : JSON.stringify(e.detail));
  }
  auditFor(orgId: string, limit = 100) { return this.many<AuditRow>("SELECT * FROM app_audit WHERE org_id = ? ORDER BY seq DESC LIMIT ?", orgId, limit); }
  recentAudit(limit = 200) { return this.many<AuditRow>("SELECT * FROM app_audit ORDER BY seq DESC LIMIT ?", limit); }

  sweepSessions() { this.run("DELETE FROM sessions WHERE expires_at < ?", new Date().toISOString()); }
  close() { this.db.close(); }
}
