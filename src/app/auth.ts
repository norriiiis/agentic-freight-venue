/**
 * Accounts, sessions and the small amount of web security a server-rendered
 * application owes its users: scrypt password hashing, opaque session ids in
 * an httpOnly cookie, and a per-session CSRF token on every state-changing
 * form. No framework, no dependency; all of it is in node:crypto.
 *
 * Sign-up is invite-only. This is a closed pilot: an account exists because
 * someone at the operator created an invitation for a named email, and that
 * fact is in the application's audit log.
 */
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AppDb, MemberRole, OrgRole, SessionRow, UserRow } from "./db";

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
const SESSION_COOKIE = "fv_session";
const SESSION_DAYS = 14;

export function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  const h = scryptSync(pw, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64")}$${h.toString("base64")}`;
}

export function verifyPassword(pw: string, stored: string): boolean {
  const [scheme, N, r, p, salt, hash] = stored.split("$");
  if (scheme !== "scrypt" || !N || !r || !p || !salt || !hash) return false;
  const want = Buffer.from(hash, "base64");
  const got = scryptSync(pw, Buffer.from(salt, "base64"), want.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 });
  return got.length === want.length && timingSafeEqual(got, want);
}

/** At least 12 characters, and not one of the handful everybody picks. */
export function passwordProblems(pw: string): string[] {
  const out: string[] = [];
  if (pw.length < 12) out.push("Use at least 12 characters.");
  if (/^[a-z]+$/i.test(pw)) out.push("Mix in a digit or a symbol.");
  if (/^(password|freight|interchange|changeme|letmein)/i.test(pw)) out.push("That is one of the first passwords anyone tries.");
  return out;
}

export interface Session { session: SessionRow; user: UserRow }

export class Auth {
  constructor(private readonly db: AppDb, private readonly secureCookies: boolean) {}

  start(res: ServerResponse, userId: string): SessionRow {
    const row: SessionRow = {
      id: randomBytes(32).toString("base64url"),
      userId,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + SESSION_DAYS * 86_400_000).toISOString(),
      csrf: randomBytes(24).toString("base64url"),
    };
    this.db.run("INSERT INTO sessions (id, user_id, created_at, expires_at, csrf) VALUES (?, ?, ?, ?, ?)", row.id, row.userId, row.createdAt, row.expiresAt, row.csrf);
    this.db.run("UPDATE users SET last_login_at = ? WHERE id = ?", row.createdAt, userId);
    res.setHeader("set-cookie", `${SESSION_COOKIE}=${row.id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${this.secureCookies ? "; Secure" : ""}`);
    return row;
  }

  end(req: IncomingMessage, res: ServerResponse) {
    const id = cookie(req, SESSION_COOKIE);
    if (id) this.db.run("DELETE FROM sessions WHERE id = ?", id);
    res.setHeader("set-cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${this.secureCookies ? "; Secure" : ""}`);
  }

  current(req: IncomingMessage): Session | undefined {
    const id = cookie(req, SESSION_COOKIE);
    if (!id) return undefined;
    const session = this.db.one<SessionRow>("SELECT * FROM sessions WHERE id = ?", id);
    if (!session) return undefined;
    if (new Date(session.expiresAt) <= new Date()) { this.db.run("DELETE FROM sessions WHERE id = ?", id); return undefined; }
    const user = this.db.user(session.userId);
    return user ? { session, user } : undefined;
  }
}

export function cookie(req: IncomingMessage, name: string): string | undefined {
  const raw = req.headers.cookie;
  if (!raw) return undefined;
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return undefined;
}

export function newInviteCode(): string { return randomBytes(16).toString("base64url"); }
export function newId(prefix: string): string { return `${prefix}_${randomUUID()}`; }

/** Membership answers "may this user act for this org, in this way". */
export const RANK: Record<MemberRole, number> = { viewer: 0, operator: 1, owner: 2 };
export function may(role: MemberRole | undefined, need: MemberRole): boolean {
  return role !== undefined && RANK[role] >= RANK[need];
}

export interface Ctx {
  session?: Session;
  org?: { id: string; name: string; role: OrgRole; memberRole: MemberRole };
  csrf?: string;
}
