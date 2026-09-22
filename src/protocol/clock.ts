/**
 * Every tolerance this system applies to a timestamp, in one place, each
 * with the reason it has the value it has. Clocks disagree; the question is
 * by how much before a difference means something. A deployment tunes these
 * through the environment (VENUE_CLOCK_* — see clockFromEnv); code never
 * carries a bare number of milliseconds.
 */
export interface ClockPolicy {
  /** How far apart two honest clocks may be. A signature dated further in the future than this was made on a wrong clock. */
  skewMs: number;
  /** A signed message or bearer token older than this is a replay or was delayed past usefulness. */
  messageMaxAgeMs: number;
  /** Root-signed operator requests and rotation claims: deliberate acts, so a short life. */
  operatorRequestMaxAgeMs: number;
  /** A routinely rotated credential stays accepted this long for messages already in flight. */
  rotationGraceMs: number;
  /** Default freshness for relying on a registry's signed word (a venue embeds its own policy in each artifact). */
  registryMaxAgeMs: number;
  /** A verifier's tolerance for the age of the newest witness receipt. */
  witnessStalenessMs: number;
}

export const DEFAULT_CLOCK: ClockPolicy = {
  skewMs: 60_000,
  messageMaxAgeMs: 5 * 60_000,
  operatorRequestMaxAgeMs: 5 * 60_000,
  rotationGraceMs: 10 * 60_000,
  registryMaxAgeMs: 5 * 60_000,
  witnessStalenessMs: 15 * 60_000,
};

/** VENUE_CLOCK_SKEW_MS, VENUE_MSG_MAX_AGE_MS, VENUE_OPERATOR_REQUEST_MAX_AGE_MS, VENUE_ROTATION_GRACE_MS, VENUE_REGISTRY_MAX_AGE_MS, VENUE_WITNESS_STALENESS_MS. */
export function clockFromEnv(env: NodeJS.ProcessEnv = process.env, prefix = "VENUE_"): ClockPolicy {
  const n = (k: string, d: number) => {
    const v = env[`${prefix}${k}`];
    if (v === undefined || v === "") return d;
    const x = Number(v);
    if (!Number.isFinite(x) || x < 0) throw new Error(`${prefix}${k}=${v}: not a non-negative number of milliseconds`);
    return x;
  };
  return {
    skewMs: n("CLOCK_SKEW_MS", DEFAULT_CLOCK.skewMs),
    messageMaxAgeMs: n("MSG_MAX_AGE_MS", DEFAULT_CLOCK.messageMaxAgeMs),
    operatorRequestMaxAgeMs: n("OPERATOR_REQUEST_MAX_AGE_MS", DEFAULT_CLOCK.operatorRequestMaxAgeMs),
    rotationGraceMs: n("ROTATION_GRACE_MS", DEFAULT_CLOCK.rotationGraceMs),
    registryMaxAgeMs: n("REGISTRY_MAX_AGE_MS", DEFAULT_CLOCK.registryMaxAgeMs),
    witnessStalenessMs: n("WITNESS_STALENESS_MS", DEFAULT_CLOCK.witnessStalenessMs),
  };
}
