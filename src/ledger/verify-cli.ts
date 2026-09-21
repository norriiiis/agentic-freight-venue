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
 * --min-witnesses N      require N distinct pinned witnesses on the SAME head (default 1; use ≥2 against split views)
 * --party-witnesses      also pin both parties' keys from the artifact itself (they witness their own transactions)
 * --require-witness id   a witness that MUST have cosigned the head (repeatable): your counterparty, your insurer, yourself
 * --equivocation-proof f a witness-signed proof file (repeatable); any valid one for this venue voids its publications
 * --registry-key f[,id]  pin a registry (vetting-provider) signer (repeatable): the artifact must carry signed word on
 *                        both parties from --min-registries of them (default: the venue's declared quorum), each no older
 *                        at commitment than --max-registry-age-ms (default: the venue's declared policy), and the standing
 *                        check is rerun over EVERY one — they must be unanimous (REGISTRY_STALE / _QUORUM_NOT_MET /
 *                        _CONTRADICTS_COMMITMENT / _DISAGREEMENT)
 * --require-registry id  a registry that MUST vouch in the artifact (repeatable): the venue cannot drop one you name
 * --registry-attestation f  a registry's word fetched today (repeatable): was the party in good standing at the
 *                        commitment time in the artifact? Needs nothing from the venue.
 * Without the two lists the signatures still verify; a compromise declared after signing is invisible offline.
 * Uses nothing from the venue process. Exit code 0 iff the artifact verifies.
 */
import { readFileSync } from "node:fs";
import { artifactHash, partyWitnessKeys, verifyArtifact, type CommitmentArtifact, type KeyHistoryInput } from "./artifact";
import type { WitnessKey } from "../protocol/witness";
import type { OkpJwk } from "../protocol/crypto";
import type { RegistryAttestation, RegistryKey } from "../protocol/registry";
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
const witnessKeys: WitnessKey[] = opts("--witness-key").map((spec, i) => {
  const [file, id] = spec.split(",");
  const key = JSON.parse(readFileSync(file!, "utf8")) as OkpJwk & { witnessId?: string };
  return { witnessId: id ?? key.witnessId ?? `witness-${i + 1}`, publicKey: key };
});
const ledgerEntries = opt("--ledger") ? readFileSync(opt("--ledger")!, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry) : undefined;
const asOf = opt("--as-of") ? new Date(opt("--as-of")!) : undefined;
const maxStalenessMs = opt("--max-staleness-ms") ? Number(opt("--max-staleness-ms")) : undefined;
const minWitnesses = opt("--min-witnesses") ? Number(opt("--min-witnesses")) : undefined;
if (args.includes("--party-witnesses")) witnessKeys.push(...partyWitnessKeys(artifact));
const requiredWitnesses = opts("--require-witness");
const equivocationProofs = opts("--equivocation-proof").flatMap((f) => { const j = JSON.parse(readFileSync(f, "utf8")); return Array.isArray(j) ? j : [j]; });
const registryKeys: RegistryKey[] = opts("--registry-key").map((spec) => {
  const [file, id] = spec.split(",");
  const key = JSON.parse(readFileSync(file!, "utf8")) as OkpJwk & { registryId?: string };
  return { registryId: id ?? key.registryId ?? artifact.registry?.registries[0]?.registryId ?? "registry", publicKey: key };
});
const minRegistries = opt("--min-registries") ? Number(opt("--min-registries")) : undefined;
const requiredRegistries = opts("--require-registry");
const currentAttestations = opts("--registry-attestation").map((f) => JSON.parse(readFileSync(f, "utf8")) as RegistryAttestation);
const maxRegistryAgeMs = opt("--max-registry-age-ms") ? Number(opt("--max-registry-age-ms")) : undefined;
const res = verifyArtifact(artifact, { pinnedRootKey: pinned, keyHistory, statusList: statusList as never, witnessKeys: witnessKeys.length ? witnessKeys : undefined, minWitnesses, requiredWitnesses: requiredWitnesses.length ? requiredWitnesses : undefined, equivocationProofs: equivocationProofs.length ? equivocationProofs : undefined, registryKeys: registryKeys.length ? registryKeys : undefined, minRegistries, requiredRegistries: requiredRegistries.length ? requiredRegistries : undefined, currentAttestations: currentAttestations.length ? currentAttestations : undefined, maxRegistryAgeMs, asOf, maxStalenessMs, ledger: ledgerEntries });

console.log(`Commitment ${artifact.commitmentId}`);
console.log(`  load      ${res.summary.loadRef}`);
console.log(`  rate      $${res.summary.rateUsd.toLocaleString()}`);
console.log(`  broker    ${res.summary.broker}`);
console.log(`  carrier   ${res.summary.carrier}`);
console.log(`  guarantee ${res.summary.guaranteed ? "attached" : "none"}`);
console.log(`  venue root ${pinned ? "PINNED (supplied by you)" : "EMBEDDED (untrusted unless you pin it)"}; venue keys used: ${artifact.venue.certs.map((c) => c.kid.slice(0, 10) + "…").join(", ")}`);
console.log(`  history    ${keyHistory ? "venue key history supplied — venue-key compromise is checked" : "no key history — a VENUE key compromise declared later cannot be detected offline"}`);
console.log(`  status     ${statusList ? "credential status list supplied — agent-key compromise is checked" : "no status list — an AGENT key compromise declared later cannot be detected offline"}`);
console.log(`  registry   ${artifact.registry ? `word from ${artifact.registry.registries.map((r) => r.registryId).join(", ")} embedded (venue policy ${artifact.registry.policy.maxAgeMs}ms, quorum ${artifact.registry.policy.quorum}); keys ${registryKeys.length ? `PINNED (${registryKeys.map((k) => k.registryId).join(", ")} — supplied by you${requiredRegistries.length ? `; required: ${requiredRegistries.join(", ")}` : ""})` : "EMBEDDED (the venue's choice of registries — pin your own)"}${currentAttestations.length ? `; ${currentAttestations.length} current attestation(s) supplied` : ""}` : registryKeys.length ? "NONE embedded — the venue's standing checks are unverifiable" : "none embedded (pre-attestation artifact)"}`);
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
console.log(res.ok ? "VERIFIED: both parties signed these exact terms." : res.reasonCode === "VENUE_EQUIVOCATION" ? "NOT VERIFIED: VENUE_EQUIVOCATION — witnesses hold proof this venue showed different ledgers to different parties; do not rely on anything it publishes" : res.reasonCode === "STATUS_STALE" || res.reasonCode === "STATUS_NOT_WITNESSED" || res.reasonCode === "WITNESS_QUORUM_NOT_MET" ? `SIGNATURES GENUINE, STATUS UNCERTAIN: ${res.reasonCode} — a revocation or compromise after the witnessed time would be invisible; fetch a fresher, better-witnessed list` : res.reasonCode === "REGISTRY_STALE" ? "NOT VERIFIED: REGISTRY_STALE — the venue committed on registry word older than its own policy; whether the parties were in good standing is unknown from this artifact. Fetch the registry's word today (--registry-attestation) to settle it" : res.reasonCode === "REGISTRY_CONTRADICTS_COMMITMENT" ? "NOT VERIFIED: REGISTRY_CONTRADICTS_COMMITMENT — a registry's signed record shows a party was not in good standing when this commitment was made; the venue committed against the registry's word" : res.reasonCode === "REGISTRY_QUORUM_NOT_MET" ? "NOT VERIFIED: REGISTRY_QUORUM_NOT_MET — too few of the registries you pin vouch in this artifact, or one you named is absent; the venue's choice of registries is not yours" : res.reasonCode === "REGISTRY_DISAGREEMENT" ? "SIGNATURES GENUINE, STANDING UNCERTAIN: REGISTRY_DISAGREEMENT — the registries the venue relied on differ on the facts standing rests on; fetch their word today" : `NOT VERIFIED: ${res.reasonCode}`);
process.exit(res.ok ? 0 : 1);
