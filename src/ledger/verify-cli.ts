/**
 * Independent artifact verifier. Usage:
 *   npm run verify -- path/to/commitment.json [--venue-root venue-root-public.jwk.json] [--key-history venue-keys.json]
 *                                             [--ledger ledger.jsonl] [--status-list credential-status.json]
 * --venue-root   pin the venue ROOT key (recommended); operational keys are accepted only via root-signed certificates
 * --key-history  the venue's published key history (certs + revocations): needed to detect a VENUE key compromise
 * --status-list  the venue's published credential status list: needed to detect an AGENT key compromise
 * Without the two lists the signatures still verify; a compromise declared after signing is invisible offline.
 * Uses nothing from the venue process. Exit code 0 iff the artifact verifies.
 */
import { readFileSync } from "node:fs";
import { artifactHash, verifyArtifact, type CommitmentArtifact } from "./artifact";
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
const artifact = JSON.parse(readFileSync(file, "utf8")) as CommitmentArtifact;
const pinned = opt("--venue-root") ? JSON.parse(readFileSync(opt("--venue-root")!, "utf8")) : undefined;
const statusFile = opt("--status-list");
const statusList = statusFile ? (JSON.parse(readFileSync(statusFile, "utf8")) as { entries?: unknown[] } | unknown[]) : undefined;
const keyHistory = opt("--key-history") ? (JSON.parse(readFileSync(opt("--key-history")!, "utf8")) as { certs: never[]; revocations: never[] }) : undefined;
const res = verifyArtifact(artifact, { pinnedRootKey: pinned, keyHistory, statusList: statusList ? ((Array.isArray(statusList) ? statusList : statusList.entries) as never) : undefined });

console.log(`Commitment ${artifact.commitmentId}`);
console.log(`  load      ${res.summary.loadRef}`);
console.log(`  rate      $${res.summary.rateUsd.toLocaleString()}`);
console.log(`  broker    ${res.summary.broker}`);
console.log(`  carrier   ${res.summary.carrier}`);
console.log(`  guarantee ${res.summary.guaranteed ? "attached" : "none"}`);
console.log(`  venue root ${pinned ? "PINNED (supplied by you)" : "EMBEDDED (untrusted unless you pin it)"}; venue keys used: ${artifact.venue.certs.map((c) => c.kid.slice(0, 10) + "…").join(", ")}`);
console.log(`  history    ${keyHistory ? "venue key history supplied — venue-key compromise is checked" : "no key history — a VENUE key compromise declared later cannot be detected offline"}`);
console.log(`  status     ${statusList ? "credential status list supplied — agent-key compromise is checked" : "no status list — an AGENT key compromise declared later cannot be detected offline"}`);
console.log("");
for (const c of res.checks) console.log(`  ${c.ok ? "PASS" : "FAIL"}  ${c.name}${!c.ok && c.detail ? `  — ${c.detail}` : ""}`);

const ledgerPath = opt("--ledger");
if (ledgerPath) {
  const entries = readFileSync(ledgerPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
  const chain = verifyChain(entries, { rootPublicKey: pinned ?? artifact.venue.rootPublicKey, revocations: keyHistory?.revocations });
  const inc = entries.find((e) => e.seq === artifact.ledger.seq);
  const included = !!inc && inc.prevHash === artifact.ledger.prevHash && (inc.payload as { commitmentId?: string; artifactHash?: string }).commitmentId === artifact.commitmentId && (inc.payload as { artifactHash?: string }).artifactHash === artifactHash(artifact);
  console.log("");
  console.log(`  ${chain.ok ? "PASS" : "FAIL"}  ledger.chain (${chain.entries} entries, ${chain.keysSeen?.length ?? 1} venue key(s))${chain.ok ? "" : ` — ${chain.error}${chain.firstBadSeq !== undefined ? ` at seq ${chain.firstBadSeq}` : ""}`}`);
  console.log(`  ${included ? "PASS" : "FAIL"}  ledger.inclusion (seq ${artifact.ledger.seq})`);
  if (!chain.ok || !included) process.exit(1);
}
console.log("");
console.log(res.ok ? "VERIFIED: both parties signed these exact terms." : `NOT VERIFIED: ${res.reasonCode}`);
process.exit(res.ok ? 0 : 1);
