/**
 * The venue's own record of challenges it sent and proofs it has spent.
 *
 * The challenge is the one proof of control the venue does not have to trust
 * anybody for: it reads the contact point off the registry's signed record,
 * sends a code there itself, and waits for it to come back. Whoever is
 * registering a key never sees the code unless they can read that contact
 * point — which is the entire claim being made, and the reason the old stub
 * (a token any caller could fetch) proved nothing at all.
 *
 * Three things this store is careful about, each of which is an attack if it
 * is not: a challenge is bound to the key it was issued for, so a code that
 * leaks cannot bind a different key; wrong answers are counted and the
 * challenge dies after a few, so a six-digit code cannot be guessed; and a
 * satisfied challenge is consumed exactly once, so it cannot be spent twice.
 *
 * It also refuses to send repeatedly to the same entity. Otherwise anyone
 * could use this venue to post a code to any carrier on the public record,
 * as often as they liked.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { mkdirSync } from "node:fs";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { writeFileAtomic } from "../protocol/fsatomic";
import type { SatisfiedChallenge } from "../protocol/control";

export interface ChallengeRow {
  challengeId: string;
  usdot: string;
  subjectKid: string;
  /** Never returned over HTTP; the response says only where it went, masked. */
  code: string;
  sentTo: string;
  channel: string;
  issuedAt: string;
  expiresAt: string;
  attempts: number;
  satisfiedAt?: string;
  consumedAt?: string;
  deadAt?: string;
}

export interface ControlStoreOptions {
  /** How long a code is good for. Short: this is a person reading an email, not a batch job. */
  ttlMs?: number;
  /** Wrong answers before the challenge dies. */
  maxAttempts?: number;
  /** Least time between challenges for the same entity, so this venue cannot be used to pester a carrier. */
  cooldownMs?: number;
}

const constantEq = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

export class ControlStore {
  private challenges = new Map<string, ChallengeRow>();
  /** Attestation ids already spent, with when, so a replay is refused rather than silently honoured. */
  private spent = new Map<string, string>();
  private readonly dir: string;
  readonly ttlMs: number;
  readonly maxAttempts: number;
  readonly cooldownMs: number;

  constructor(dataDir: string, o: ControlStoreOptions = {}) {
    this.dir = join(dataDir, "identity");
    mkdirSync(this.dir, { recursive: true });
    this.ttlMs = o.ttlMs ?? 30 * 60_000;
    this.maxAttempts = o.maxAttempts ?? 5;
    this.cooldownMs = o.cooldownMs ?? 10 * 60_000;
    const f = join(this.dir, "control.json");
    if (existsSync(f)) {
      const raw = JSON.parse(readFileSync(f, "utf8")) as { challenges?: ChallengeRow[]; spent?: [string, string][] };
      for (const c of raw.challenges ?? []) this.challenges.set(c.challengeId, c);
      for (const [k, v] of raw.spent ?? []) this.spent.set(k, v);
    }
  }
  private persist() {
    writeFileAtomic(join(this.dir, "control.json"), JSON.stringify({ challenges: [...this.challenges.values()], spent: [...this.spent.entries()] }, null, 2));
  }

  /** A six-digit code a person can read aloud over the phone. The entropy that matters is the attempt limit, not the length. */
  private static code(): string { return String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0"); }

  /**
   * How long before this entity may be challenged again. Counts EVERY challenge sent, not only live ones: a
   * challenge that died from wrong guesses must not let the guesser immediately post another code to the carrier.
   * With sane settings the code outlives the cooldown, so this never delays somebody who is simply slow to answer.
   */
  cooldownRemainingMs(usdot: string, now = new Date()): number {
    let newest = 0;
    for (const c of this.challenges.values()) if (c.usdot === usdot) newest = Math.max(newest, new Date(c.issuedAt).getTime());
    return newest ? Math.max(0, this.cooldownMs - (now.getTime() - newest)) : 0;
  }

  issue(input: { usdot: string; subjectKid: string; sentTo: string; channel: string }, now = new Date()): { challengeId: string; code: string; expiresAt: string } {
    const row: ChallengeRow = {
      challengeId: `chl_${randomUUID()}`,
      usdot: input.usdot,
      subjectKid: input.subjectKid,
      code: ControlStore.code(),
      sentTo: input.sentTo,
      channel: input.channel,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.ttlMs).toISOString(),
      attempts: 0,
    };
    this.challenges.set(row.challengeId, row);
    this.persist();
    return { challengeId: row.challengeId, code: row.code, expiresAt: row.expiresAt };
  }

  /** Redeem a code. The answer says only whether it worked and how many tries remain; it never echoes the code. */
  verify(challengeId: string, code: string, now = new Date()): { ok: true; challenge: SatisfiedChallenge } | { ok: false; why: string; attemptsLeft?: number } {
    const c = this.challenges.get(challengeId);
    if (!c) return { ok: false, why: "no such challenge" };
    if (c.deadAt) return { ok: false, why: "that challenge is closed; ask for a new code" };
    if (c.consumedAt) return { ok: false, why: "that challenge has already been used" };
    if (new Date(c.expiresAt) <= now) { c.deadAt = now.toISOString(); this.persist(); return { ok: false, why: "that code has expired; ask for a new one" }; }
    if (c.satisfiedAt) return { ok: true, challenge: this.view(c) };
    c.attempts += 1;
    if (!constantEq(c.code, code.trim())) {
      const left = this.maxAttempts - c.attempts;
      if (left <= 0) c.deadAt = now.toISOString();
      this.persist();
      return { ok: false, why: left > 0 ? "that code does not match" : "too many wrong answers; that challenge is closed", attemptsLeft: Math.max(0, left) };
    }
    c.satisfiedAt = now.toISOString();
    this.persist();
    return { ok: true, challenge: this.view(c) };
  }

  private view(c: ChallengeRow): SatisfiedChallenge {
    return { challengeId: c.challengeId, usdot: c.usdot, subjectKid: c.subjectKid, satisfiedAt: c.satisfiedAt!, sentTo: c.sentTo, consumedAt: c.consumedAt };
  }

  /** What `evaluateControl` reads: only challenges that were actually answered. */
  satisfied(challengeId: string): SatisfiedChallenge | undefined {
    const c = this.challenges.get(challengeId);
    return c?.satisfiedAt ? this.view(c) : undefined;
  }

  /** Spend a proof. Called after the credential is issued, so a failed issuance does not burn the client's challenge. */
  consume(p: { challengeId?: string; jti?: string }, now = new Date()) {
    if (p.challengeId) {
      const c = this.challenges.get(p.challengeId);
      if (c) c.consumedAt = now.toISOString();
    }
    if (p.jti) this.spent.set(p.jti, now.toISOString());
    this.persist();
  }
  seen(jti: string): boolean { return this.spent.has(jti); }

  /** Housekeeping: drop challenges nobody will come back for. */
  sweep(now = new Date(), keepMs = 7 * 86_400_000) {
    let changed = false;
    for (const [id, c] of this.challenges) {
      const end = new Date(c.consumedAt ?? c.deadAt ?? c.expiresAt).getTime();
      if (now.getTime() - end > keepMs) { this.challenges.delete(id); changed = true; }
    }
    if (changed) this.persist();
    return this.challenges.size;
  }
  all(): ChallengeRow[] { return [...this.challenges.values()]; }
}
