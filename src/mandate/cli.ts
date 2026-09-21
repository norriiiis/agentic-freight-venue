/**
 * The principal's tool. A mandate is signed by a human-controlled key that
 * the agent never sees; this is how that human makes one.
 *
 *   npm run mandate -- keygen   --out principal.key.json
 *   npm run mandate -- template --role broker|carrier            > limits.json
 *   npm run mandate -- issue    --key principal.key.json --principal "Name" --agent <agentId> --limits limits.json [--days 30] [--disclose disclose.json] [--out-dir <agent data dir>]
 *   npm run mandate -- show     <mandate.json> [--envelope envelope.json]
 *   npm run mandate -- verify   <mandate.json> [--principal-public principal.pub.json]
 *
 * `issue` refuses limits that cannot be meant (validateLimits) and prints,
 * in plain language, what the agent will be allowed to do and what the venue
 * will see (the envelope) — so the signature is over something the human
 * read. The private key is written by `keygen` and read by `issue`; nothing
 * here ever puts it in an agent's data dir.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { exportPrivateJwk, generateKeyPair, importKeyPair, importPublicKey, type OkpJwk } from "../protocol/crypto";
import type { MandateEnvelope } from "../protocol/types";
import { issueEnvelope, issueMandate, verifyEnvelope, verifyMandate } from "./sign";
import type { Mandate, MandateLimits } from "./types";
import { describeLimits, validateLimits } from "./validate";

export const TEMPLATES: Record<"broker" | "carrier", MandateLimits> = {
  broker: { maxRatePerLoadUsd: 3200, minRatePerLoadUsd: 900, maxRatePerMileUsd: 4.0, allowedLaneRegions: ["TX", "OK", "KS", "MO", "AR", "LA"], allowedEquipment: ["VAN", "REEFER"], hazmatPermitted: false, requiredCounterpartyInsuranceUsd: 1_000_000, requireInsurerAttestation: true, maxPerCounterpartyExposureUsd: 12_000, maxDailyExposureUsd: 30_000, requireGuarantee: true, mayTender: true, maxNegotiationRounds: 12, paymentTermsDays: { min: 15, max: 45 } },
  carrier: { minRatePerLoadUsd: 1500, minRatePerMileUsd: 1.9, allowedLaneRegions: ["TX", "OK", "KS", "MO", "NE", "IA", "CO"], allowedEquipment: ["VAN"], hazmatPermitted: false, requiredCounterpartyInsuranceUsd: 75_000, maxPerCounterpartyExposureUsd: 15_000, maxDailyExposureUsd: 20_000, requireGuarantee: false, mayTender: false, maxNegotiationRounds: 12, paymentTermsDays: { min: 0, max: 30 } },
};

type Out = (line: string) => void;

function parse(argv: string[]): { cmd: string; pos: string[]; opt: Record<string, string> } {
  const [cmd = "", ...rest] = argv;
  const pos: string[] = [];
  const opt: Record<string, string> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a.startsWith("--")) { opt[a.slice(2)] = rest[i + 1] && !rest[i + 1]!.startsWith("--") ? rest[++i]! : "true"; } else pos.push(a);
  }
  return { cmd, pos, opt };
}

const readJson = <T>(p: string): T => JSON.parse(readFileSync(p, "utf8")) as T;

/** Returns the process exit code. Pure apart from the files it is told to read and write. */
export function main(argv: string[], out: Out = console.log, now = new Date()): number {
  const { cmd, pos, opt } = parse(argv);
  const need = (k: string) => { const v = opt[k]; if (!v || v === "true") throw new Error(`--${k} is required`); return v; };
  try {
    switch (cmd) {
      case "keygen": {
        const to = need("out");
        if (existsSync(to) && opt.force !== "true") throw new Error(`${to} exists; pass --force to overwrite a principal key (agents pinned to the old one will refuse the new mandates)`);
        const kp = generateKeyPair();
        writeFileSync(to, JSON.stringify(exportPrivateJwk(kp), null, 2), { mode: 0o600 });
        const pub = to.replace(/(\.key)?\.json$/, "") + ".pub.json";
        writeFileSync(pub, JSON.stringify(kp.publicJwk, null, 2));
        out(`principal key written: ${to} (private, mode 600 — keep it away from the agent)`);
        out(`public half:           ${pub} (kid ${kp.kid}) — this is what goes in the agent's config as principal.publicKey`);
        return 0;
      }
      case "template": {
        const role = (opt.role ?? pos[0]) as "broker" | "carrier";
        if (!TEMPLATES[role]) throw new Error(`--role must be broker or carrier`);
        out(JSON.stringify(TEMPLATES[role], null, 2));
        return 0;
      }
      case "issue": {
        const kp = importKeyPair(readJson<OkpJwk>(need("key")));
        const limits = readJson<unknown>(need("limits"));
        const problems = validateLimits(limits);
        if (problems.length) {
          out(`refusing to issue: ${problems.length} problem(s) with ${opt.limits}`);
          for (const p of problems) out(`  - ${p}`);
          return 2;
        }
        const days = Number(opt.days ?? 30);
        if (!Number.isFinite(days) || days <= 0 || days > 365) throw new Error("--days must be 1..365");
        const m = issueMandate(kp, need("principal"), need("agent"), limits as MandateLimits, days, now);
        const disclose = opt.disclose ? readJson<Partial<MandateEnvelope["limits"]>>(opt.disclose) : {};
        const e = issueEnvelope(kp, m, disclose);
        const dir = opt["out-dir"] ?? ".";
        writeFileSync(join(dir, "mandate.json"), JSON.stringify(m, null, 2));
        writeFileSync(join(dir, "envelope.json"), JSON.stringify(e, null, 2));
        out(`mandate ${m.mandateId} for ${m.agentId}, signed by ${m.principal.name} (kid ${kp.kid}), valid ${m.issuedAt.slice(0, 10)} → ${m.expiresAt.slice(0, 10)}`);
        out(`the agent may:`);
        for (const l of describeLimits(m.limits)) out(`  - ${l}`);
        out(`the venue will see (envelope): ${Object.entries(e.limits).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join("  ")}`);
        const hidden = (Object.keys(m.limits) as (keyof MandateLimits)[]).filter((k) => !(k in e.limits));
        out(`kept private from the venue: ${hidden.join(", ")}`);
        out(`written: ${join(dir, "mandate.json")}, ${join(dir, "envelope.json")}`);
        return 0;
      }
      case "show": {
        const m = readJson<Mandate>(pos[0] ?? need("mandate"));
        const v = verifyMandate(m, now);
        out(`${m.mandateId} for ${m.agentId} — principal ${m.principal.name} (kid ${m.principal.kid}) — ${v.ok ? "signature valid" : `INVALID: ${v.error}`} — ${m.issuedAt.slice(0, 10)} → ${m.expiresAt.slice(0, 10)}`);
        const problems = validateLimits(m.limits);
        for (const p of problems) out(`  ! ${p}`);
        for (const l of describeLimits(m.limits)) out(`  - ${l}`);
        const ep = opt.envelope ?? join(pos[0] ?? ".", "..", "envelope.json");
        if (existsSync(ep)) {
          const e = readJson<MandateEnvelope>(ep);
          const ev = verifyEnvelope(e, now);
          out(`envelope: ${ev.ok ? "signature valid" : `INVALID: ${ev.error}`}${e.principalKid === m.principal.kid ? "" : " — DIFFERENT PRINCIPAL"}${e.agentId === m.agentId ? "" : " — DIFFERENT AGENT"}`);
          for (const [k, val] of Object.entries(e.limits)) {
            const mine = (m.limits as unknown as Record<string, unknown>)[k];
            if (val !== undefined && JSON.stringify(mine) !== JSON.stringify(val)) out(`  envelope discloses ${k}=${JSON.stringify(val)} while the mandate holds ${JSON.stringify(mine)}${typeof val === "number" && typeof mine === "number" && (k.startsWith("max") ? val < mine : val > mine) ? " — the envelope is TIGHTER than the mandate; the venue would refuse what the agent may do" : ""}`);
          }
        }
        return v.ok && !problems.length ? 0 : 1;
      }
      case "verify": {
        const m = readJson<Mandate>(pos[0] ?? need("mandate"));
        const v = verifyMandate(m, now);
        if (!v.ok) { out(`NOT VALID: ${v.error}`); return 1; }
        if (opt["principal-public"]) {
          const pub = readJson<OkpJwk>(opt["principal-public"]);
          importPublicKey(pub);
          if (pub.kid !== m.principal.kid) { out(`NOT VALID: signed by kid ${m.principal.kid}, not the pinned principal ${pub.kid}`); return 1; }
        }
        out(`VALID: ${m.mandateId} for ${m.agentId}, principal ${m.principal.name} (kid ${m.principal.kid}), expires ${m.expiresAt}`);
        return 0;
      }
      default:
        out("usage: mandate keygen --out <file> | template --role broker|carrier | issue --key <file> --principal <name> --agent <id> --limits <file> [--days N] [--disclose <file>] [--out-dir <dir>] | show <mandate.json> | verify <mandate.json> [--principal-public <file>]");
        return 2;
    }
  } catch (e) {
    out(`error: ${(e as Error).message}`);
    return 2;
  }
}

if (process.argv[1] && /mandate\/cli\.ts$/.test(process.argv[1])) process.exit(main(process.argv.slice(2)));
