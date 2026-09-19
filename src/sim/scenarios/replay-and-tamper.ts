import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario } from "../scenario";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { rpcCall } from "../../protocol/rpc";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { verifyChain, type LedgerEntry } from "../../ledger/chain";
import type { OkpJwk } from "../../protocol/crypto";

export const replayAndTamper: Scenario = {
  id: "replay-and-tamper",
  title: "Replayed signed message; tampered commitment artifact; tampered ledger",
  summary: "After a real commitment: (1) the carrier's signed ACCEPT is captured off the wire and replayed to the venue; (2) the same message is replayed with a fresh nonce; (3) the broker's copy of the artifact has its rate altered and is run through the independent verifier; (4) a ledger entry is edited and the chain is verified.",
  expect: { outcome: "REFUSED", reasonCode: "NONCE_REUSED", refusedBy: "venue.protocol" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h);
    const first = await negotiate(h, broker, carrier);
    say(`commitment ${first.task!.commitmentId} recorded`);

    // (1) Replay the carrier's ACCEPT verbatim (an attacker holding a wire capture).
    const captured = (await h.venue.messages()).find((m) => m.direction === "IN" && m.note === "ACCEPT" && (m.message.metadata as { senderAgentId: string }).senderAgentId === carrier.spec.agentId)!.message;
    const replay = await rpcCall(`${h.venue.url}/a2a`, "message/send", { message: captured });
    const replayData = (replay.error?.data ?? {}) as { reasonCode?: string; refusedBy?: string; evidence?: Record<string, unknown>; guaranteeWouldHavePaid?: string };
    say(`replay verbatim → ${replayData.reasonCode}`);

    // (2) Replay with a fresh nonce: the nonce is inside the signed surface, so the signature no longer verifies.
    const fresh = { ...captured, metadata: { ...captured.metadata, nonce: "attacker-fresh-nonce", ts: new Date().toISOString() } };
    const replay2 = await rpcCall(`${h.venue.url}/a2a`, "message/send", { message: fresh });
    const replay2Data = (replay2.error?.data ?? {}) as { reasonCode?: string };
    say(`replay with fresh nonce → ${replay2Data.reasonCode}`);

    // (3) Tamper with the broker's own copy of the artifact.
    const artPath = join(broker.dir, "commitments", `${first.task!.commitmentId}.json`);
    const artifact = JSON.parse(readFileSync(artPath, "utf8")) as CommitmentArtifact;
    const venueKey = (await h.venue.publicKey()) as unknown as OkpJwk;
    const genuine = verifyArtifact(artifact, { pinnedVenueKey: venueKey });
    const tampered: CommitmentArtifact = structuredClone(artifact);
    tampered.terms.rateUsd = artifact.terms.rateUsd + 900;
    const tv = verifyArtifact(tampered, { pinnedVenueKey: venueKey });
    say(`artifact genuine → ${genuine.ok ? "VERIFIED" : "FAIL"}; rate +$900 → ${tv.ok ? "VERIFIED (!)" : `${tv.reasonCode} (${tv.checks.filter((c) => !c.ok).length} checks fail)`}`);

    // (4) Tamper with the ledger file.
    const ledgerPath = join(h.venue.dir, "ledger.jsonl");
    const entries = readFileSync(ledgerPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
    const chainOk = verifyChain(entries, venueKey);
    const edited = structuredClone(entries);
    (edited[1]!.payload as { rateUsd: number }).rateUsd = 999;
    const chainBad = verifyChain(edited, venueKey);
    writeFileSync(join(h.opts.workspace, "tampered-artifact.json"), JSON.stringify(tampered, null, 2));
    say(`ledger chain intact → ${chainOk.ok}; after editing seq 1 → ${chainBad.ok ? "ok (!)" : `broken at seq ${chainBad.firstBadSeq}: ${chainBad.error}`}`);

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: replayData.reasonCode,
      refusedBy: replayData.refusedBy,
      evidence: replayData.evidence,
      guaranteeWouldHavePaid: replayData.guaranteeWouldHavePaid,
      taskId: first.task!.task.id,
      commitmentId: first.task!.commitmentId,
      findings: [
        { label: "replay with fresh nonce", reasonCode: replay2Data.reasonCode, by: "venue.identity", detail: "nonce and timestamp are inside the signed surface; changing them invalidates the signature" },
        { label: "tampered artifact (independent verifier)", reasonCode: tv.reasonCode, by: "ledger/verify", detail: tv.checks.filter((c) => !c.ok).map((c) => c.name).join(", ") },
        { label: "tampered ledger entry", reasonCode: "CHAIN_BROKEN", by: "ledger/verifyChain", detail: `${chainBad.error} at seq ${chainBad.firstBadSeq}` },
        { label: "genuine artifact", detail: `${genuine.checks.length} checks pass with pinned venue key; original commitment unaffected` },
      ],
      auditRefs: pickAudit(audit, "venue", (e) => e.outcome === "REFUSED" && (e.reasonCode === "NONCE_REUSED" || e.reasonCode === "IDENTITY_SIGNATURE_INVALID")),
    };
  },
};
