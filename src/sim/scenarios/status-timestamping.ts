import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { LedgerEntry } from "../../ledger/chain";
import type { OkpJwk } from "../../protocol/crypto";

export const statusTimestamping: Scenario = {
  id: "status-timestamping",
  title: "Third-party timestamps for the published status list: a stale copy is judged stale, and a rolled-back ledger cannot get a witness",
  summary: "The status list and key history are projections of the ledger at a head. An independent WITNESS process, with its own key and clock, cosigns each new head only if it extends the last one it cosigned. Part 1: a verifier pinning the witness learns the time W up to which the list is complete, and confirms completeness against the ledger. Part 2: the carrier's credential is revoked after a verifier took its copy — with the stale copy the verdict is STATUS_STALE, not 'trusted'; with a fresh copy the revocation is visible. Part 3: the venue rolls its ledger back to before the revocation and republishes a list with a current asOf — the witness detects the fork and refuses; the fresh-looking list carries only an old witnessed head, and the verifier says so.",
  expect: { outcome: "REFUSED", reasonCode: "STATUS_STALE", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    const witness = await h.startWitness("witness-1", 300);
    const witnessKey = { witnessId: "witness-1", publicKey: (await witness.status()).publicKey };
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const ledger = () => readFileSync(join(h.venue.dir, "ledger.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
    const findings: Finding[] = [];

    // ---- Part 1: a commitment, witnessed; the verifier learns W and checks completeness.
    const a = await negotiate(h, broker, carrier, LOAD);
    const art = JSON.parse(readFileSync(join(broker.dir, "commitments", `${a.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    await witness.poll();
    const list1 = await h.venue.statusList();
    const keys1 = await h.venue.venueKeys();
    // Judge the moment the commitment was made — a past instant, so the check can be strict.
    const v1 = verifyArtifact(art, { pinnedRootKey: root, statusList: list1, keyHistory: keys1, witnessKeys: [witnessKey], ledger: ledger(), asOf: new Date(art.createdAt), maxStalenessMs: 0 });
    say(`part 1: witness-1 cosigned head seq ${list1.witnessed?.head.seq} at ${list1.witnessed?.receipts[0]?.at.slice(11, 23)}Z (its own clock); status list has ${list1.entries.length} entries, venue asOf ${list1.asOf.slice(11, 23)}Z`);
    say(`   verifier pinning witness-1 (judging strictly as of the commitment, ${art.createdAt.slice(11, 23)}Z): ${v1.ok ? "VERIFIED" : v1.reasonCode} — ${v1.checks.filter((c) => /^(status|keys)\./.test(c.name)).map((c) => `${c.name}:${c.ok ? "ok" : "FAIL"}`).join(", ")}`);
    if (!v1.ok || !v1.witnessed?.statusAsOf) throw new Error("part 1: witnessed verification failed");
    findings.push({ label: "part 1: witnessed status", detail: `status.witnessed by ${v1.witnessed.by.join(", ")} at ${v1.witnessed.statusAsOf}; status.complete-to-witnessed-head checked against the ledger; the list's own asOf is ignored` });

    // ---- Part 2: revoke AFTER the verifier took its copy; judge with the stale copy vs a fresh one.
    const staleList = list1;
    await new Promise((r) => setTimeout(r, 50));
    const revokeAt = new Date();
    await h.venue.revoke(carrier.spec.agentId, "FMCSA authority revocation notice", { source: "stub:fmcsa-li-daily-feed" });
    await witness.poll();
    const freshList = await h.venue.statusList();
    const freshKeys = await h.venue.venueKeys();
    // The question: "was this credential in good standing as of X?" where X is just after the revocation.
    const X = new Date(revokeAt.getTime() + 10);
    const vStale = verifyArtifact(art, { pinnedRootKey: root, statusList: staleList, keyHistory: keys1, witnessKeys: [witnessKey], asOf: X, maxStalenessMs: 0 });
    const vStaleNoWitness = verifyArtifact(art, { pinnedRootKey: root, statusList: staleList, keyHistory: keys1 });
    const vFresh = verifyArtifact(art, { pinnedRootKey: root, statusList: freshList, keyHistory: freshKeys, witnessKeys: [witnessKey], asOf: X, maxStalenessMs: 0, ledger: ledger() });
    const revEntry = ledger().find((e) => e.type === "CREDENTIAL_STATUS");
    say(`part 2: carrier credential revoked at ${revokeAt.toISOString().slice(11, 23)}Z → CREDENTIAL_STATUS on the ledger at seq ${revEntry?.seq}; witness cosigned seq ${(await witness.status()).lastCosigned?.seq}`);
    say(`   stale copy (witnessed ${staleList.witnessed?.receipts[0]?.at.slice(11, 23)}Z), judged strictly as of ${X.toISOString().slice(11, 23)}Z → ${vStale.reasonCode ?? "VERIFIED"}: ${vStale.checks.find((c) => c.name === "status.fresh-as-of")?.detail}`);
    say(`   the same stale copy WITHOUT pinned witnesses → ${vStaleNoWitness.ok ? "VERIFIED (the old behaviour: no entry, so 'trusted')" : vStaleNoWitness.reasonCode}`);
    say(`   fresh copy (witnessed ${freshList.witnessed?.receipts[0]?.at.slice(11, 23)}Z, ${freshList.entries.length} entries) → ${vFresh.ok ? "VERIFIED" : vFresh.reasonCode}: ${vFresh.checks.find((c) => c.name === "carrier.credential.trusted-at-signing")?.detail}`);
    if (vStale.reasonCode !== "STATUS_STALE" || !vStaleNoWitness.ok || !vFresh.ok) throw new Error("part 2: freshness judgement wrong");
    const staleEv = Object.fromEntries(vStale.checks.filter((c) => !c.ok).map((c) => [c.name, c.detail]));
    findings.push({ label: "part 2: stale copy", reasonCode: "STATUS_STALE", by: "ledger/verify", detail: "signatures genuine, status uncertain — the verifier is told exactly until when the list is known complete, and that it asked about a later moment; a fresh witnessed copy shows the revocation happened after the signature (so the artifact still verifies)" });

    // ---- Part 3: rollback. The venue drops the ledger entries after the commitment (incl. the revocation) and republishes.
    const headBefore = await h.venue.ledgerHead();
    const rb = await h.venue.truncateLedger(revEntry!.seq - 1);
    const poll = await witness.poll();
    const forks = await witness.forks();
    const rolledList = await h.venue.statusList();
    const vRolled = verifyArtifact(art, { pinnedRootKey: root, statusList: rolledList, keyHistory: await h.venue.venueKeys(), witnessKeys: [witnessKey], asOf: X, maxStalenessMs: 0 });
    say(`part 3: venue rolls its ledger back from seq ${headBefore.seq} to seq ${rb.head.seq} (the revocation is gone) and republishes: asOf ${rolledList.asOf.slice(11, 23)}Z, ${rolledList.entries.length} entries, venue-signed`);
    say(`   witness-1 on its next poll → ${poll.fork ? `REFUSED: ${poll.fork}` : poll.receipt ? "cosigned (!)" : poll.skipped}; forks recorded: ${forks.length}`);
    say(`   the republished list's latest witnessed head is seq ${rolledList.witnessed?.head.seq} at ${rolledList.witnessed?.receipts[0]?.at.slice(11, 23)}Z; verifier judging as of ${X.toISOString().slice(11, 23)}Z → ${vRolled.reasonCode ?? "VERIFIED"}`);
    if (!poll.fork || forks.length !== 1 || vRolled.reasonCode !== "STATUS_STALE" || (rolledList.witnessed?.head.seq ?? 99) >= (revEntry?.seq ?? 0)) throw new Error("part 3: rollback was not caught");
    findings.push(
      { label: "part 3: rollback", reasonCode: "LEDGER_FORK_DETECTED", by: "witness", detail: `the witness refuses to cosign a head that does not extend the last one it cosigned (${forks[0]?.why}); the venue can republish whatever it likes with a current asOf, but cannot make a witness say it is fresh — a verifier sees a witnessed head older than its question` },
      { label: "what a witness is", detail: "an independent party with its own key and clock: an insurer, an industry body, a timestamping service — or the counterparties themselves. Its key is learned out of band, like a CT log key; the venue cannot mint one" },
      { label: "what is still not solved", detail: "a venue can DELAY recording a revocation; no witness can cosign what it was never shown. The guarantee is 'complete as of W', never 'nothing has happened'" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "STATUS_STALE",
      refusedBy: "ledger/verify",
      evidence: staleEv,
      guaranteeWouldHavePaid: "N/A — this is the verifier refusing to over-trust a copy. A claim adjudicated on a stale list would be adjudicated on incomplete evidence; the witnessed time bounds exactly how incomplete.",
      taskId: a.task!.task.id,
      commitmentId: a.task!.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "witnessed" || e.event === "ledger-rollback"), ...pickAudit(await (async () => JSON.parse(JSON.stringify((await import("node:fs")).readFileSync(join(witness.dir, "audit.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)))))(), "witness", (e) => e.outcome === "REFUSED")],
    };
  },
};
