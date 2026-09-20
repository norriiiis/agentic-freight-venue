import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { partyWitnessKeys, verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { makeEquivocationProof, verifyEquivocationProof, type WitnessReceipt } from "../../protocol/witness";
import { rpcCall } from "../../protocol/rpc";
import type { OkpJwk } from "../../protocol/crypto";

export const witnessCollusion: Scenario = {
  id: "witness-collusion",
  title: "Colluding witnesses: 'any k' is defeated, a named counterparty cannot be conjured, one honest peer is enough, and every colluder signs its own confession",
  summary: "The venue controls both independent witnesses the broker pinned. After a revocation the venue shows the broker and its pets a fork without it, and the pets sign whatever they are handed — the fork for the broker, the real chain for everyone else. Part 1: a verifier requiring 'any 3 witnesses' is fooled. Part 2: the parties witness their own transactions with keys the other side already trusts; a verifier that REQUIRES its counterparty's receipt on the head cannot be fooled — the venue cannot conjure that signature. Part 3: the broker's own agent, gossiping with one honest witness its principal added, produces a proof and halts. Part 4: the pets' two receipts for the same position, collected at claim time, prove their own equivocation.",
  expect: { outcome: "REFUSED", reasonCode: "WITNESS_QUORUM_NOT_MET", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    const pet1 = await h.startWitness("witness-1", 60_000);
    const pet2 = await h.startWitness("witness-2", 60_000, [pet1]);
    const honest = await h.startWitness("witness-3", 60_000); // the carrier's insurer's witness; the broker does not know it yet
    await broker.addWitnessPeers([pet1, pet2]);   // the broker's principal pinned the venue-recommended witnesses
    await carrier.addWitnessPeers([honest]);      // the carrier's principal pinned its insurer's
    const petKeys = [{ witnessId: "witness-1", publicKey: (await pet1.status()).publicKey }, { witnessId: "witness-2", publicKey: (await pet2.status()).publicKey }];
    const honestKey = { witnessId: "witness-3", publicKey: (await honest.status()).publicKey };
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const findings: Finding[] = [];
    const brokerId = broker.spec.agentId;
    const carrierId = carrier.spec.agentId;

    const a = await negotiate(h, broker, carrier, LOAD);
    const art = JSON.parse(readFileSync(join(broker.dir, "commitments", `${a.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const parties = partyWitnessKeys(art);
    await new Promise((r) => setTimeout(r, 300)); // parties witness the head on COMMITTED
    for (const w of [pet1, pet2, honest]) await w.poll();
    const headBefore = await h.venue.ledgerHead();
    const bw = await broker.witnessStatus();
    const cw = await carrier.witnessStatus();
    say(`commitment on seq ${headBefore.seq}; witnessed by both PARTIES with their own credential keys (broker seq ${bw.lastCosigned?.seq}, carrier seq ${cw.lastCosigned?.seq}) and by witnesses 1, 2, 3`);
    const v0 = verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: [...petKeys, ...parties], minWitnesses: 3, requiredWitnesses: [carrierId], asOf: new Date(art.createdAt), maxStalenessMs: 0 });
    say(`   broker's policy — 3 witnesses incl. the counterparty, as of the commitment → ${v0.ok ? "VERIFIED" : v0.reasonCode}`);
    if (!v0.ok) throw new Error("setup: expected the honest state to verify");

    // ---- The split view is armed BEFORE the revocation is recorded: from now on the broker and its pets are shown a
    // chain that omits every status change. (A party that witnesses continuously pins the chain for itself — a fork
    // from before its last cosigned head is caught as a rollback at once — so the venue must fork forward from here.)
    await h.venue.equivocate(["witness-1", "witness-2", brokerId], headBefore.seq);
    await pet1.collude(); await pet2.collude();
    const revokeAt = new Date();
    await h.venue.revoke(carrierId, "FMCSA authority revocation notice", { source: "stub:fmcsa-li-daily-feed" });
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 60 }));
    const b = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-262-0480", commodity: "Paper products, palletized", weightLbs: 40_100 });
    await new Promise((r) => setTimeout(r, 300)); // the broker's agent witnesses B's head — the fork's
    const [p1, p2, p3] = await Promise.all([pet1.poll(), pet2.poll(), honest.poll()]);
    const cwn = await carrier.witnessNow();
    const realHead = await h.venue.ledgerHead();
    // The pets also sign the REAL chain blindly (at the fork's own seq and at the head), so the real chain looks pet-witnessed to everyone else.
    const realAtForkSeq = (await (await fetch(`${h.venue.url}/ledger.jsonl?from=${p1.receipt!.seq}`)).json() as { seq: number; hash: string; ts: string }[]).find((e) => e.seq === p1.receipt!.seq)!;
    for (const pet of [pet1, pet2]) {
      for (const head of [{ seq: realAtForkSeq.seq, hash: realAtForkSeq.hash, ts: realAtForkSeq.ts }, realHead]) {
        const r = (await pet.signBlindly(realHead.venueId, head)).receipt!;
        await rpcCall(`${h.venue.url}/a2a`, "venue/witness", { receipt: r });
      }
    }
    const brokerLast = (await broker.witnessStatus()).lastCosigned!;
    say(`carrier revoked at ${revokeAt.toISOString().slice(11, 23)}Z; later load with another carrier → ${b.task!.status}; venue shows a fork (no revocation) to witness-1, witness-2 and the broker's own agent`);
    say(`   fork head seq ${p1.receipt?.seq} ${p1.receipt?.hash.slice(0, 10)}… cosigned by witness-1, witness-2 and the broker (seq ${brokerLast.seq} ${brokerLast.hash.slice(0, 10)}…); real head seq ${realHead.seq} ${realHead.hash.slice(0, 10)}… cosigned by witness-3 (${p3.receipt?.hash.slice(0, 10)}…) and the carrier (${cwn.poll.receipt?.hash.slice(0, 10)}…); the pets ALSO sign the real head blindly`);
    if (!p1.receipt || !p2.receipt || !p3.receipt || !cwn.poll.receipt || brokerLast.hash !== p1.receipt.hash) throw new Error("setup: expected the broker and its pets on the fork head, the carrier and witness-3 on the real one");

    // ---- Part 1: "any 3 witnesses" — fooled.
    const X = new Date(revokeAt.getTime() + 10);
    const forkList = await h.venue.statusListAs(brokerId);
    const forkKeys = await h.venue.venueKeysAs(brokerId);
    const anyK = verifyArtifact(art, { pinnedRootKey: root, statusList: forkList, keyHistory: forkKeys, witnessKeys: [...petKeys, ...parties], minWitnesses: 3, asOf: X, maxStalenessMs: 0 });
    say(`part 1: broker verifies with 'any 3 of {witness-1, witness-2, broker, carrier}' on the list the venue shows it (${forkList.entries.length} entries; witnessed by ${forkList.witnessed?.receipts.map((r) => r.witnessId).join(", ")}) → ${anyK.ok ? "VERIFIED — fooled" : anyK.reasonCode}`);
    if (!anyK.ok) throw new Error("part 1: expected the any-k verifier to be fooled");
    findings.push({ label: "part 1: any-k quorum under collusion", detail: "the venue controls 2 of the 3 witnesses the broker accepts and the broker's own view; 3 receipts on the fork head satisfy 'any 3'" });

    // ---- Part 2: require the counterparty.
    const named = verifyArtifact(art, { pinnedRootKey: root, statusList: forkList, keyHistory: forkKeys, witnessKeys: [...petKeys, ...parties], minWitnesses: 3, requiredWitnesses: [carrierId], asOf: X, maxStalenessMs: 0 });
    say(`part 2: same list, policy 'the counterparty must be among them' → ${named.reasonCode ?? "VERIFIED"}: ${named.checks.find((c) => c.name === "status.witness-quorum")?.detail}`);
    if (named.reasonCode !== "WITNESS_QUORUM_NOT_MET") throw new Error("part 2: the named-witness policy did not protect the broker");
    findings.push({ label: "part 2: named counterparty", reasonCode: "WITNESS_QUORUM_NOT_MET", by: "ledger/verify", detail: `the carrier cosigned the real chain with the key the broker transacted with (from the artifact, no venue trust needed); the fork head carries no such receipt and the venue cannot forge one` });

    // ---- Part 3: one honest peer. The broker's principal adds the carrier's insurer's witness; the broker's own agent detects.
    await broker.addWitnessPeers([honest]);
    const g = await broker.witnessNow();
    const bws = await broker.witnessStatus();
    const proofs = await broker.witnessEquivocations();
    say(`part 3: broker's agent gossips with witness-3 (honest, sees the real chain) → ${g.gossip.proofs.length} proof(s) at seq ${proofs[0]?.seq}: broker's verified ${proofs[0]?.receipts[0]?.hash.slice(0, 10)}… vs witness-3's ${proofs[0]?.receipts[1]?.hash.slice(0, 10)}…; broker's witness halted: ${!!bws.halted}`);
    if (!proofs.length || !bws.halted) throw new Error("part 3: one honest peer did not produce a proof");
    const withProof = verifyArtifact(art, { pinnedRootKey: root, statusList: forkList, keyHistory: forkKeys, witnessKeys: [...petKeys, ...parties, honestKey], minWitnesses: 1, equivocationProofs: proofs, asOf: X, maxStalenessMs: 0 });
    say(`   any verification with that proof in hand → ${withProof.reasonCode}`);
    findings.push({ label: "part 3: one honest peer", reasonCode: "VENUE_EQUIVOCATION", by: "witness", detail: "the broker's own agent is a witness the venue cannot control; the moment it gossips with one witness that saw the other chain, it holds a proof — collusion must be total to be silent" });

    // ---- Part 4: accountability. At claim time the adjuster collects receipts from everyone.
    const S = realAtForkSeq.seq;
    const pet1Receipts = await pet1.receipts();
    const forkR = pet1Receipts.find((r) => r.seq === S && r.hash !== realAtForkSeq.hash)!;
    const realR = pet1Receipts.find((r) => r.seq === S && r.hash === realAtForkSeq.hash)!;
    const selfProof = makeEquivocationProof(forkR, realR, "claims-adjuster")!;
    const brokerAtS = (await broker.witnessReceiptFor(S))!;
    const carrierAtS = (await carrier.witnessReceiptFor(S))!;
    const partiesProof = makeEquivocationProof(brokerAtS, carrierAtS, "claims-adjuster")!;
    say(`part 4: witness-1 signed seq ${S} twice — ${forkR.hash.slice(0, 10)}… for the broker and ${realR.hash.slice(0, 10)}… for everyone else: self-contradiction proof verifies with its key alone: ${verifyEquivocationProof(selfProof, petKeys)}`);
    say(`   the two PARTIES' receipts for seq ${S} (broker: ${brokerAtS.hash.slice(0, 10)}…, carrier: ${carrierAtS.hash.slice(0, 10)}…) also prove the venue's equivocation with no independent witness at all: ${verifyEquivocationProof(partiesProof, parties)}`);
    if (!verifyEquivocationProof(selfProof, petKeys) || !verifyEquivocationProof(partiesProof, parties)) throw new Error("part 4: accountability proofs failed");
    findings.push(
      { label: "part 4: colluders sign their own confession", reasonCode: "VENUE_EQUIVOCATION", by: "ledger/verify", detail: "a witness that signs two chains has produced two receipts that, once they meet, prove its own equivocation; and the two parties alone — no third party — can prove the venue's" },
      { label: "what this leaves", detail: "a verifier that pins nobody outside the venue's control is unprotected by construction, and delay remains: nothing recorded, nothing to disagree about. What the protocol removed is the venue's power to choose the verifier's witnesses" },
    );

    const audit = await h.venue.audit();
    const brokerAudit = await broker.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "WITNESS_QUORUM_NOT_MET",
      refusedBy: "ledger/verify",
      evidence: Object.fromEntries(named.checks.filter((c) => !c.ok).map((c) => [c.name, c.detail])),
      guaranteeWouldHavePaid: "N/A — the broker declined to act on a list its counterparty never vouched for. A claim adjudicated on it would rest on witnesses the venue chose; the counterparty's receipt is the one signature in the room the venue cannot supply.",
      taskId: a.task!.task.id,
      commitmentId: a.task!.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "equivocation-fault").slice(0, 2), ...pickAudit(brokerAudit, "broker", (e) => e.event === "party-witness:equivocation")],
    };
  },
};
