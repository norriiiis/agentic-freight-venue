/**
 * Scenario runner.
 *   npm run demo                       happy path with full transcript, artifact verification, EDI mapping
 *   npm run sim -- --all               every adversarial scenario
 *   npm run sim -- --scenario <id>     one scenario
 *   npm run sim -- --list
 *   add --verbose to see process stdout, --json for machine-readable results
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Harness } from "./harness";
import { SCENARIOS, ADVERSARIAL } from "./scenarios/index";
import { checkExpectation, renderResult, renderWire } from "./transcript";
import type { Scenario, ScenarioResult } from "./scenario";
import { verifyArtifact, type CommitmentArtifact } from "../ledger/artifact";
import { toRateConfirmation, toX12Outline } from "../edi/mapping";
import type { OkpJwk } from "../protocol/crypto";

const args = process.argv.slice(2);
const has = (f: string) => args.includes(f);
const opt = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const verbose = has("--verbose");
const json = has("--json");
const ROOT = resolve(import.meta.dirname, "../..");
const RUN_ROOT = join(ROOT, ".sim", new Date().toISOString().replace(/[:.]/g, "-"));

const ROLES: Record<string, string> = { "northline-broker-agent": "BROKER", "prairie-wind-carrier-agent": "CARRIER", "blue-mesa-carrier-agent": "CARRIER2", "spoof-carrier-agent": "SPOOFER", "quikhaul-agent": "quikhaul", venue: "venue" };

async function runScenario(sc: Scenario, index: number): Promise<{ res: ScenarioResult; pass: boolean; workspace: string }> {
  const workspace = join(RUN_ROOT, sc.id);
  mkdirSync(workspace, { recursive: true });
  const h = new Harness({ workspace, quiet: !verbose });
  const notes: string[] = [];
  console.log(`\n${"═".repeat(100)}\n  [${index}] ${sc.title}\n${"═".repeat(100)}`);
  console.log(`  ${sc.summary}\n`);
  try {
    const res = await sc.run({ h, say: (l) => { notes.push(l); console.log(`  ▸ ${l}`); } });
    const wire = renderWire(await h.venue.messages(), ROLES, ["happy-path", "non-convergence", "exposure-mid-negotiation", "insurance-lapsed", "negotiation-timeout", "key-rotation", "venue-key-rotation", "root-key-rotation"].includes(sc.id) ? res.taskId : undefined);
    if (wire.length) {
      console.log("\n  wire (venue log):");
      for (const l of wire) console.log(l);
    }
    const pass = checkExpectation(sc, res);
    for (const l of renderResult(sc, res, pass)) console.log(l);
    writeFileSync(join(workspace, "result.json"), JSON.stringify({ scenario: sc.id, expect: sc.expect, pass, result: res, notes }, null, 2));
    console.log(`\n  workspace: ${workspace.replace(ROOT + "/", "")}`);
    return { res, pass, workspace };
  } finally {
    await h.stop();
  }
}

async function demoExtras(workspace: string) {
  const brokerDir = join(workspace, "northline-broker-agent");
  const { readdirSync } = await import("node:fs");
  const file = readdirSync(join(brokerDir, "commitments"))[0]!;
  const artifact = JSON.parse(readFileSync(join(brokerDir, "commitments", file), "utf8")) as CommitmentArtifact;
  const venueRoot = JSON.parse(readFileSync(join(workspace, "venue", "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
  console.log(`\n${"─".repeat(100)}\n  Independent verification of the broker's copy of the artifact (no venue process involved)\n${"─".repeat(100)}`);
  const v = verifyArtifact(artifact, { pinnedRootKey: venueRoot });
  for (const c of v.checks) console.log(`  ${c.ok ? "PASS" : "FAIL"}  ${c.name}`);
  console.log(`  → ${v.ok ? "VERIFIED: both parties signed these exact terms." : `NOT VERIFIED: ${v.reasonCode}`}`);
  console.log(`  re-run yourself:  npm run verify -- ${join(brokerDir, "commitments", file).replace(ROOT + "/", "")} --venue-root ${join(workspace, "venue", "venue-root-public.jwk.json").replace(ROOT + "/", "")} --ledger ${join(workspace, "venue", "ledger.jsonl").replace(ROOT + "/", "")}`);

  console.log(`\n${"─".repeat(100)}\n  Underwriting\n${"─".repeat(100)}`);
  const u = artifact.underwriting;
  console.log(`  decision ${u.decision}  P(loss) ${u.riskScore}  ${u.guarantee ? `covered $${u.guarantee.coveredAmountUsd} premium $${u.guarantee.premiumUsd} (${((u.guarantee.premiumUsd / u.guarantee.coveredAmountUsd) * 100).toFixed(2)}% of guaranteed value)` : ""}`);
  if (u.guarantee) {
    console.log(`  scope:      ${u.guarantee.scope.map((s) => s.split(":")[0]).join(", ")}`);
    console.log(`  exclusions: ${u.guarantee.exclusions.map((s) => s.split(":")[0]).join(", ")}`);
  }

  console.log(`\n${"─".repeat(100)}\n  Document compatibility: rate confirmation + X12 outline\n${"─".repeat(100)}`);
  const rc = toRateConfirmation(artifact);
  console.log(`  RATE CONFIRMATION ${rc.confirmationNumber}`);
  console.log(`  ${rc.broker.legalName} (${rc.broker.mc})  ⇄  ${rc.carrier.legalName} (${rc.carrier.mc})`);
  console.log(`  ${rc.load.reference}  ${rc.load.equipment}  ${rc.load.weightLbs.toLocaleString()} lbs  ${rc.load.commodity}  ${rc.load.miles} mi`);
  for (const s of rc.stops) console.log(`  ${s.type.padEnd(8)} ${s.city}, ${s.state} ${s.zip}   ${s.windowStart} → ${s.windowEnd}`);
  console.log(`  linehaul $${rc.rate.linehaulUsd}  total $${rc.rate.totalUsd}  ${rc.paymentTerms}  subcontracting ${rc.subcontractingProhibited ? "PROHIBITED" : "permitted"}`);
  console.log(`  signed: broker ${rc.signatures.broker.signedAt} (kid ${rc.signatures.broker.kid.slice(0, 10)}…)  carrier ${rc.signatures.carrier.signedAt} (kid ${rc.signatures.carrier.kid.slice(0, 10)}…)`);
  for (const set of toX12Outline(artifact)) {
    console.log(`\n  X12 ${set.set} — ${set.purpose}`);
    console.log(`    ${set.segments.join("~\n    ")}~`);
  }
  writeFileSync(join(workspace, "rate-confirmation.json"), JSON.stringify(rc, null, 2));
}

async function main() {
  if (has("--list")) {
    for (const s of SCENARIOS) console.log(`${s.id.padEnd(26)} ${s.title}`);
    return;
  }
  const mode = args[0] === "demo" ? "demo" : has("--all") ? "all" : opt("--scenario") ? "one" : "help";
  if (mode === "help") {
    console.log("usage: npm run demo | npm run sim -- --all | npm run sim -- --scenario <id> | npm run sim -- --list");
    process.exit(2);
  }
  const list = mode === "demo" ? SCENARIOS.filter((s) => s.id === "happy-path") : mode === "all" ? ADVERSARIAL : SCENARIOS.filter((s) => s.id === opt("--scenario"));
  if (!list.length) { console.error(`unknown scenario ${opt("--scenario")}`); process.exit(2); }
  console.log(`freight-venue simulator · ${list.length} scenario(s) · each runs venue + agents as separate processes with separate data dirs under ${RUN_ROOT.replace(ROOT + "/", "")}`);
  const results: { id: string; pass: boolean; res: ScenarioResult }[] = [];
  let i = 0;
  for (const sc of list) {
    const { res, pass, workspace } = await runScenario(sc, ++i);
    results.push({ id: sc.id, pass, res });
    if (mode === "demo") await demoExtras(workspace);
  }
  console.log(`\n${"═".repeat(100)}\n  SUMMARY\n${"═".repeat(100)}`);
  for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.id.padEnd(26)} ${r.res.outcome}${r.res.reasonCode ? `  ${r.res.reasonCode}` : ""}${r.res.refusedBy ? `  (${r.res.refusedBy})` : ""}`);
  if (json) writeFileSync(join(RUN_ROOT, "results.json"), JSON.stringify(results, null, 2));
  const failed = results.filter((r) => !r.pass).length;
  console.log(`\n  ${results.length - failed}/${results.length} scenarios behaved as expected`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
