/**
 * Independent artifact verifier. Usage:
 *   npm run verify -- path/to/commitment.json [--venue-key path/to/venue-public.jwk.json] [--ledger path/to/ledger.jsonl]
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
const pinned = opt("--venue-key") ? JSON.parse(readFileSync(opt("--venue-key")!, "utf8")) : undefined;
const res = verifyArtifact(artifact, { pinnedVenueKey: pinned });

console.log(`Commitment ${artifact.commitmentId}`);
console.log(`  load      ${res.summary.loadRef}`);
console.log(`  rate      $${res.summary.rateUsd.toLocaleString()}`);
console.log(`  broker    ${res.summary.broker}`);
console.log(`  carrier   ${res.summary.carrier}`);
console.log(`  guarantee ${res.summary.guaranteed ? "attached" : "none"}`);
console.log(`  venue key ${pinned ? "PINNED (supplied by you)" : "EMBEDDED (untrusted unless you pin it)"}`);
console.log("");
for (const c of res.checks) console.log(`  ${c.ok ? "PASS" : "FAIL"}  ${c.name}${!c.ok && c.detail ? `  — ${c.detail}` : ""}`);

const ledgerPath = opt("--ledger");
if (ledgerPath) {
  const entries = readFileSync(ledgerPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
  const chain = verifyChain(entries, pinned ?? artifact.venue.publicKey);
  const inc = entries.find((e) => e.seq === artifact.ledger.seq);
  const included = !!inc && inc.prevHash === artifact.ledger.prevHash && (inc.payload as { commitmentId?: string; artifactHash?: string }).commitmentId === artifact.commitmentId && (inc.payload as { artifactHash?: string }).artifactHash === artifactHash(artifact);
  console.log("");
  console.log(`  ${chain.ok ? "PASS" : "FAIL"}  ledger.chain (${chain.entries} entries)${chain.ok ? "" : ` — ${chain.error} at seq ${chain.firstBadSeq}`}`);
  console.log(`  ${included ? "PASS" : "FAIL"}  ledger.inclusion (seq ${artifact.ledger.seq})`);
  if (!chain.ok || !included) process.exit(1);
}
console.log("");
console.log(res.ok ? "VERIFIED: both parties signed these exact terms." : `NOT VERIFIED: ${res.reasonCode}`);
process.exit(res.ok ? 0 : 1);
