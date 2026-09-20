import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { verifyEquivocationProof } from "../../protocol/witness";
import type { OkpJwk } from "../../protocol/crypto";

export const witnessEquivocation: Scenario = {
  id: "witness-equivocation",
  title: "Split view: the venue shows one witness a ledger without the revocation — gossip between witnesses produces a self-contained proof, and a verifier requiring a quorum was never fooled",
  summary: "Two independent witnesses. After a revocation, the venue keeps two books: the real chain for witness-1 and a fork without the revocation for witness-2 (and for anyone the venue wants to fool). Each witness's own consistency check passes — each chain extends what it saw. Part 1: a verifier pinning only witness-2 accepts the fork as fresh and witnessed. Part 2: the witnesses gossip; at the common seq their receipts carry different hashes; paired, they are proof of equivocation that anyone can check with the witness keys alone; both halt. Part 3: a verifier requiring 2 witnesses on the same head could never have been fooled, and one holding the proof trusts nothing the venue publishes.",
  expect: { outcome: "REFUSED", reasonCode: "VENUE_EQUIVOCATION", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    // Two witnesses that know each other (keys exchanged out of band). Long poll intervals: the sim drives them.
    const w1 = await h.startWitness("witness-1", 60_000);
    const w2 = await h.startWitness("witness-2", 60_000, [w1]);
    await w1.addPeers([w2]);
    const keys = [{ witnessId: "witness-1", publicKey: (await w1.status()).publicKey }, { witnessId: "witness-2", publicKey: (await w2.status()).publicKey }];
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const findings: Finding[] = [];

    const a = await negotiate(h, broker, carrier, LOAD);
    const art = JSON.parse(readFileSync(join(broker.dir, "commitments", `${a.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    await w1.poll();
    await w2.poll();
    const headBefore = await h.venue.ledgerHead();
    say(`both witnesses cosigned the real head seq ${headBefore.seq}; quorum-2 verification: ${verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: keys, minWitnesses: 2, asOf: new Date(art.createdAt), maxStalenessMs: 0 }).ok ? "VERIFIED" : "FAIL"}`);

    // ---- The revocation, a later commitment, and the venue's second book for witness-2.
    const revokeAt = new Date();
    await h.venue.revoke(carrier.spec.agentId, "FMCSA authority revocation notice", { source: "stub:fmcsa-li-daily-feed" });
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 60 }));
    const b = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-262-0470", commodity: "Paper products, palletized", weightLbs: 40_100 });
    await h.venue.equivocate("witness-2", headBefore.seq);
    const p1 = await w1.poll();
    const p2 = await w2.poll();
    say(`carrier credential revoked at ${revokeAt.toISOString().slice(11, 23)}Z (CREDENTIAL_STATUS at seq ${headBefore.seq + 1}); a later load committed with another carrier → ${b.task!.status}; venue now shows witness-2 a fork from seq ${headBefore.seq} with the revocation omitted and the later commitment re-signed in its place`);
    const realAt2 = (await (await fetch(`${h.venue.url}/ledger.jsonl?from=${headBefore.seq + 1}`)).json() as { seq: number; hash: string; type: string }[]).find((e) => e.seq === headBefore.seq + 1)!;
    say(`   witness-1 cosigns real seq ${p1.receipt?.seq} (${p1.receipt?.hash.slice(0, 10)}…), having verified seq ${realAt2.seq} = ${realAt2.hash.slice(0, 10)}… (${realAt2.type}); witness-2 cosigns fork seq ${p2.receipt?.seq} = ${p2.receipt?.hash.slice(0, 10)}… — each chain extends what that witness saw, so neither's own consistency check fires`);
    if (!p1.receipt || !p2.receipt || p2.receipt.seq !== realAt2.seq || p2.receipt.hash === realAt2.hash) throw new Error("setup: expected the fork to disagree with the real chain at the first seq after the split");

    // ---- Part 1: a verifier that pins only witness-2 and asks the venue (which shows it the fork) is fooled.
    const X = new Date(revokeAt.getTime() + 10);
    const forkList = await h.venue.statusListAs("witness-2");
    const forkKeys = await h.venue.venueKeysAs("witness-2");
    const fooled = verifyArtifact(art, { pinnedRootKey: root, statusList: forkList, keyHistory: forkKeys, witnessKeys: [keys[1]!], minWitnesses: 1, asOf: X, maxStalenessMs: 0 });
    say(`part 1: a verifier pinning only witness-2, judging as of ${X.toISOString().slice(11, 23)}Z with the list the venue shows it (${forkList.entries.length} entries, witnessed seq ${forkList.witnessed?.head.seq} by ${forkList.witnessed?.receipts.map((r) => r.witnessId).join(",")}) → ${fooled.ok ? "VERIFIED — fooled: the revocation is invisible and the copy looks fresh" : fooled.reasonCode}`);
    if (!fooled.ok) throw new Error("part 1: expected the single-witness verifier to be fooled");
    findings.push({ label: "part 1: single witness, no gossip", detail: "a witness shown a fork cannot know it is a fork; a verifier trusting one witness inherits that blindness — fresh, witnessed, and wrong" });

    // ---- Part 2: gossip. witness-2 tells witness-1 its latest receipt (and vice versa); the hashes differ at the same seq.
    await w2.gossip();
    await new Promise((r) => setTimeout(r, 150)); // proof propagation back to witness-2
    const s1 = await w1.status();
    const s2 = await w2.status();
    const proof = (await w1.equivocations())[0] ?? (await w2.equivocations())[0];
    say(`part 2: witnesses gossip → witness-2 pushes its receipt for seq ${p2.receipt.seq}; witness-1 verified that seq as ${realAt2.hash.slice(0, 10)}…, signs a receipt for it and pairs the two → proof at seq ${proof?.seq} (detected by ${proof?.detectedBy}); witness-1 halted: ${!!s1.halted}; witness-2 received the proof and halted: ${!!s2.halted}`);
    say(`   the proof verifies with the two witness keys alone: ${proof ? verifyEquivocationProof(proof, keys) : false}; with a forged receipt inside: ${proof ? verifyEquivocationProof({ ...proof, receipts: [proof.receipts[0], { ...proof.receipts[1], hash: "f".repeat(64) }] }, keys) : false}`);
    const halted = await w2.poll();
    say(`   witness-2 asked to cosign again → ${halted.halted ? `refuses: ${halted.halted}` : "cosigned (!)"}`);
    if (!proof || !s1.halted || !s2.halted || !halted.halted || !verifyEquivocationProof(proof, keys)) throw new Error("part 2: gossip did not produce and propagate a proof");
    findings.push({ label: "part 2: gossip → proof → halt", reasonCode: "LEDGER_FORK_DETECTED", by: "witness", detail: `two witness-signed receipts for seq ${proof.seq} with different hashes; needs no cooperation from the venue to verify; both witnesses stop cosigning this venue and the proof is pushed to peers` });

    // ---- Part 3: a verifier requiring a quorum of 2 on the same head, and one holding the proof.
    const quorum = verifyArtifact(art, { pinnedRootKey: root, statusList: forkList, keyHistory: forkKeys, witnessKeys: keys, minWitnesses: 2, asOf: X, maxStalenessMs: 0 });
    const withProof = verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: keys, minWitnesses: 2, equivocationProofs: [proof], asOf: X, maxStalenessMs: 0 });
    say(`part 3: the same fooled copy judged with quorum 2 → ${quorum.reasonCode ?? "VERIFIED"}: ${quorum.checks.find((c) => c.name === "status.witness-quorum")?.detail}`);
    say(`   any copy, with the proof in hand → ${withProof.reasonCode ?? "VERIFIED"}: ${withProof.checks.find((c) => c.name === "venue.no-equivocation")?.detail}`);
    if (quorum.reasonCode !== "WITNESS_QUORUM_NOT_MET" || withProof.reasonCode !== "VENUE_EQUIVOCATION") throw new Error("part 3: quorum/proof did not protect the verifier");
    findings.push(
      { label: "part 3: quorum", reasonCode: "WITNESS_QUORUM_NOT_MET", by: "ledger/verify", detail: "to publish a fresh head cosigned by k witnesses the venue must show the SAME head to k witnesses — and those witnesses gossip. With k ≥ 2 the split view fails before any proof exists" },
      { label: "what is still not solved", detail: "collusion: if the venue controls or bribes k witnesses, quorum is met and gossip among them is silent. The defense is who the witnesses are — the insurer, an industry body, the counterparties themselves — not the protocol. And delay remains: nothing recorded, nothing to disagree about" },
    );

    const audit = await h.venue.audit();
    const w2audit = readFileSync(join(w2.dir, "audit.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    return {
      outcome: "REFUSED",
      reasonCode: "VENUE_EQUIVOCATION",
      refusedBy: "ledger/verify",
      evidence: { seq: proof.seq, receipts: proof.receipts.map((r) => ({ witnessId: r.witnessId, hash: r.hash, at: r.at })), detectedBy: proof.detectedBy },
      guaranteeWouldHavePaid: "N/A — a venue caught equivocating has forfeited the trust every guarantee rests on; the proof is the evidence a claimant or regulator would take to the insurer backing it.",
      taskId: a.task!.task.id,
      commitmentId: a.task!.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "equivocation-fault"), ...pickAudit(w2audit, "witness-2", (e) => e.event === "equivocation")],
    };
  },
};
