/**
 * Static import-boundary check. Run via `npm run check:boundaries` or from the isolation test.
 *
 * The rule: agent code may depend only on stateless library code (protocol,
 * mandate engine, agentkit) — never on the other agent, the venue, or any
 * venue-side service. The venue never imports agent code, and never imports
 * the registry process: the registry's word reaches it only as signatures.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SRC = join(ROOT, "src");

export interface BoundaryRule {
  scope: string; // dir under src
  allowed: string[]; // dirs under src that may be imported
}

export const RULES: BoundaryRule[] = [
  { scope: "agents/broker", allowed: ["protocol", "mandate", "agentkit", "agents/broker"] },
  { scope: "agents/carrier", allowed: ["protocol", "mandate", "agentkit", "agents/carrier"] },
  { scope: "agentkit", allowed: ["protocol", "mandate", "agentkit"] },
  { scope: "venue", allowed: ["protocol", "mandate", "identity", "underwriting", "ledger", "venue"] },
  { scope: "witness", allowed: ["protocol", "ledger", "witness"] },
  // The registry is its own trust domain: the venue reaches it only over HTTP and holds only what it signs.
  { scope: "registry", allowed: ["protocol", "registry"] },
  { scope: "identity", allowed: ["protocol", "identity"] },
  { scope: "ledger", allowed: ["protocol", "ledger"] },
  { scope: "underwriting", allowed: ["protocol", "mandate", "ledger", "underwriting"] },
  { scope: "mandate", allowed: ["protocol", "mandate"] },
  { scope: "protocol", allowed: ["protocol"] },
];

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
  });
}

export interface Violation { file: string; specifier: string; resolvedTo: string; rule: string }

export function checkBoundaries(): Violation[] {
  const violations: Violation[] = [];
  for (const rule of RULES) {
    for (const file of walk(join(SRC, rule.scope))) {
      const src = readFileSync(file, "utf8");
      for (const m of src.matchAll(/from\s+["']([^"']+)["']|import\(["']([^"']+)["']\)/g)) {
        const spec = m[1] ?? m[2]!;
        if (!spec.startsWith(".")) continue; // node builtins / packages
        const target = resolve(dirname(file), spec);
        const rel = relative(SRC, target);
        const ok = rule.allowed.some((a) => rel === a || rel.startsWith(a + "/"));
        if (!ok) violations.push({ file: relative(ROOT, file), specifier: spec, resolvedTo: rel, rule: rule.scope });
      }
    }
  }
  return violations;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const v = checkBoundaries();
  for (const x of v) console.log(`VIOLATION [${x.rule}] ${x.file} imports ${x.specifier} -> ${x.resolvedTo}`);
  console.log(v.length ? `${v.length} boundary violation(s)` : `boundaries OK: ${RULES.map((r) => r.scope).join(", ")}`);
  process.exit(v.length ? 1 : 0);
}
