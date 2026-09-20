/**
 * Independent artifact verifier. Usage:
 *   npm run verify -- path/to/commitment.json [--venue-root venue-root-public.jwk.json] [--key-history venue-keys.json]
 *                                             [--ledger ledger.jsonl] [--status-list credential-status.json]
 *                                             [--witness-key witness-public.jwk.json[,id]]... [--as-of ISO]
 * --venue-root   pin the venue ROOT key (recommended); operational keys are accepted only via root-signed certificates
 * --key-history  the venue's published key history (certs + revocations): needed to detect a VENUE key compromise
 * --status-list  the venue's published credential status list: needed to detect an AGENT key compromise
 * --witness-key  pin an independent witness (repeatable): the lists are then known complete only up to the latest time
 *                a pinned witness cosigned their head, and must be fresh as of --as-of (default: now) or the verdict is
 *                STATUS_STALE. --max-staleness-ms (default 900000 = 15 min) is the tolerance when judging "now"; use 0
 *                with a past --as-of for a strict answer. Without witness keys the lists' own asOf is the venue's word.
 * Without the two lists the signatures still verify; a compromise declared after signing is invisible offline.
 * Uses nothing from the venue process. Exit code 0 iff the artifact verifies.
 */
import { readFileSync } from "node:fs";
import { artifactHash, verifyArtifact, type CommitmentArtifact, type KeyHistoryInput } from "./artifact";
import { verifyChain, type LedgerEntry } from "./chain";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--"));
if (!file) {
  console.error("usage: verify <artifact.json> [--venue-key key.json] [--ledger ledger.jsonl]");
  process.exit(2);
}
const opt = (name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const opts = (name: string) => args.map((a, i) => (a === name ? args[i + 1] : undefined)).filter((x): x is string => !!x);
const artifact = JSON.parse(readFileSync(file, "utf8")) as CommitmentArtifact;
const pinned = opt("--venue-root") ? JSON.parse(readFileSync(opt("--venue-root")!, "utf8")) : undefined;
const statusFile = opt("--status-list");
const statusList = statusFile ? (JSON.parse(readFileSync(statusFile, "utf8")) as { entries?: unknown[] } | unknown[]) : undefined;
const keyHistory = opt("--key-history") ? (JSON.parse(readFileSync(opt("--key-history")!, "utf8")) as KeyHistoryInput) : undefined;
const witnessKeys = opts("--witness-key").map((spec, i) => {
  const [file, id] = spec.split(",");
  const key = JSON.parse(readFileSync(file!, "utf8")) as { kid?: string; witnessId?: string };
  return { witnessId: id ?? key.witnessId ?? `witness-${i + 1}`, publicKey: key as never };
});
const ledgerEntries = opt("--ledger") ? readFileSync(opt("--ledger")!, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry) : undefined;
const asOf = opt("--as-of") ? new Date(opt("--as-of")!) : undefined;
const maxStalenessMs = opt("--max-staleness-ms") ? Number(opt("--max-staleness-ms")) : undefined;
const res = verifyArtifact(artifact, { pinnedRootKey: pinned, keyHistory, statusList: statusList as never, witnessKeys: witnessKeys.length ? witnessKeys : undefined, asOf, maxStalenessMs, ledger: ledgerEntries });

console.log(`Commitment ${artifact.commitmentId}`);
console.log(`  load      ${res.summary.loadRef}`);
console.log(`  rate      $${res.summary.rateUsd.toLocaleString()}`);
console.log(`  broker    ${res.summary.broker}`);
console.log(`  carrier   ${res.summary.carrier}`);
console.log(`  guarantee ${res.summary.guaranteed ? "attached" : "none"}`);
console.log(`  venue root ${pinned ? "PINNED (supplied by you)" : "EMBEDDED (untrusted unless you pin it)"}; venue keys used: ${artifact.venue.certs.map((c) => c.kid.slice(0, 10) + "…").join(", ")}`);
console.log(`  history    ${keyHistory ? "venue key history supplied — venue-key compromise is checked" : "no key history — a VENUE key compromise declared later cannot be detected offline"}`);
console.log(`  status     ${statusList ? "credential status list supplied — agent-key compromise is checked" : "no status list — an AGENT key compromise declared later cannot be detected offline"}`);
console.log(`  witnesses  ${witnessKeys.length ? `${witnessKeys.map((w) => w.witnessId).join(", ")} pinned — lists are trusted only up to the latest witnessed time${res.witnessed?.statusAsOf ? ` (status ${res.witnessed.statusAsOf}` : ""}${res.witnessed?.keysAsOf ? `, keys ${res.witnessed.keysAsOf})` : res.witnessed?.statusAsOf ? ")" : ""}; judged as of ${(asOf ?? new Date()).toISOString()}` : "none pinned — the lists' asOf is the venue's own word"}`);
console.log("");
for (const c of res.checks) console.log(`  ${c.ok ? "PASS" : "FAIL"}  ${c.name}${!c.ok && c.detail ? `  — ${c.detail}` : ""}`);

const ledgerPath = opt("--ledger");
if (ledgerPath) {
  const entries = ledgerEntries!;
  const chain = verifyChain(entries, { rootPublicKey: pinned ?? artifact.venue.rootPublicKey, revocations: keyHistory?.revocations });
  const inc = entries.find((e) => e.seq === artifact.ledger.seq);
  const included = !!inc && inc.prevHash === artifact.ledger.prevHash && (inc.payload as { commitmentId?: string; artifactHash?: string }).commitmentId === artifact.commitmentId && (inc.payload as { artifactHash?: string }).artifactHash === artifactHash(artifact);
  console.log("");
  console.log(`  ${chain.ok ? "PASS" : "FAIL"}  ledger.chain (${chain.entries} entries, ${chain.keysSeen?.length ?? 1} venue key(s))${chain.ok ? "" : ` — ${chain.error}${chain.firstBadSeq !== undefined ? ` at seq ${chain.firstBadSeq}` : ""}`}`);
  console.log(`  ${included ? "PASS" : "FAIL"}  ledger.inclusion (seq ${artifact.ledger.seq})`);
  if (!chain.ok || !included) process.exit(1);
}
console.log("");
console.log(res.ok ? "VERIFIED: both parties signed these exact terms." : res.reasonCode === "STATUS_STALE" || res.reasonCode === "STATUS_NOT_WITNESSED" ? `SIGNATURES GENUINE, STATUS UNCERTAIN: ${res.reasonCode} — a revocation or compromise after the witnessed time would be invisible; fetch a fresher list` : `NOT VERIFIED: ${res.reasonCode}`);
process.exit(res.ok ? 0 : 1);
