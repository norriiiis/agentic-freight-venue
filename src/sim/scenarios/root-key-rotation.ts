import { readFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { Scenario, Finding } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { verifyChain, type LedgerEntry } from "../../ledger/chain";
import type { OkpJwk } from "../../protocol/crypto";
import { buildMessage, venueSignMessage } from "../../protocol/envelope";
import { rpcCall } from "../../protocol/rpc";

export const rootKeyRotation: Scenario = {
  id: "root-key-rotation",
  title: "Root key rotation by pre-commitment: a stolen root cannot rotate, a planned rotation re-pins every agent automatically, and a compromised root is replaced without touching the venue's genuine keys",
  summary: "The root is the trust anchor; nothing above it can vouch for a successor. Each root establishment therefore commits to the hash of the NEXT root, held offline. Part 1: a planned rotation reveals the pre-committed root mid-negotiation — agents that pinned the founding root re-pin the new one through the chain, old certificates stay trusted, the ledger and artifacts verify from the founding root. Part 2: a thief holding the current root tries to rotate to their own key — refused: it does not match the commitment, and the stolen root's countersignature is worthless. Part 3: the thief certifies an operational key of their own; the operator declares the root compromised as of T and rotates to the pre-committed successor, re-certifying the venue's genuine key — agents now refuse the thief's key and keep accepting the genuine one; everything verifies from the founding root.",
  expect: { outcome: "REFUSED", reasonCode: "ROOT_ROTATION_UNAUTHORIZED", refusedBy: "venue.identity" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 400 }, carrier: { thinkMs: 60 } });
    const findings: Finding[] = [];
    const foundingRoot = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const commodities = ["Consumer packaged goods, palletized", "Paper products, palletized", "Canned goods, palletized", "Pet food, palletized"];
    const loadIds = (n: number) => ({ ...LOAD, loadRef: `L-2026-262-046${n}`, commodity: commodities[n]!, weightLbs: LOAD.weightLbs + n * 1000 });
    const ledger = () => readFileSync(join(h.venue.dir, "ledger.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
    const brokerPinned = () => (JSON.parse(readFileSync(join(broker.dir, "venue-root.pinned.json"), "utf8")) as OkpJwk).kid!;

    const a = await negotiate(h, broker, carrier, loadIds(0));
    const artA = JSON.parse(readFileSync(join(broker.dir, "commitments", `${a.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const r0 = brokerPinned();
    say(`founding root ${r0.slice(0, 10)}… pinned by both agents; its establishment event commits to H(R1), which only the operator holds`);

    // ---- Part 1: planned rotation mid-negotiation.
    const r1task = await broker.tender(loadIds(1), { agentId: carrier.spec.agentId });
    await h.venue.waitRound(r1task.taskId!, 2);
    const rot = await h.venue.rotateRoot("ROTATION");
    if (rot.error) throw new Error(`part 1: root rotation refused ${JSON.stringify(rot.error.data)}`);
    const r1 = rot.result!.rootKid;
    say(`part 1: operator reveals the pre-committed R1 ${r1.slice(0, 10)}… (event signed by R1, countersigned by R0, committing to H(R2)); ROOT_ROTATION on the ledger`);
    const t1 = await h.venue.waitTerminal(r1task.taskId!);
    await Promise.all([broker.waitStatus(r1task.taskId!, ["COMMITTED"]), carrier.waitStatus(r1task.taskId!, ["COMMITTED"])]);
    await Promise.all([broker.refreshVenueKeys(), carrier.refreshVenueKeys()]);
    const bId = await broker.identity();
    const repinned = (await broker.audit()).filter((e) => e.event === "venue-root-rotated").length;
    const art1 = JSON.parse(readFileSync(join(broker.dir, "commitments", `${t1.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const chain1 = verifyChain(ledger(), { rootPublicKey: foundingRoot });
    const v1 = verifyArtifact(art1, { pinnedRootKey: foundingRoot });
    const vA = verifyArtifact(artA, { pinnedRootKey: foundingRoot, keyHistory: await h.venue.venueKeys() });
    say(`   in-flight negotiation → ${t1.status}; broker re-pinned ${brokerPinned().slice(0, 10)}… via the chain (audit venue-root-rotated: ${repinned}); roots known ${bId.venueRootsKnown.length}; operational key unchanged and its R0-issued cert still trusted`);
    say(`   ledger verifies from the FOUNDING root across the root rotation: ${chain1.ok} (${chain1.rootsSeen?.length} roots); new artifact (names R1) verifies with the founding root pinned: ${v1.ok} — pinned-reaches-embedded via the embedded root log; pre-rotation artifact: ${vA.ok}`);
    if (t1.status !== "COMMITTED" || brokerPinned() !== r1 || !chain1.ok || !v1.ok || !vA.ok) throw new Error("part 1: planned root rotation disturbed the system");
    findings.push({ label: "part 1: planned root rotation", reasonCode: "COMMITTED", by: "venue.commitment", detail: "pre-rotation: the event's authority is the previous root's commitment plus the new root's own signature; agents walk from whatever root they pinned and re-pin the successor automatically; ledger and artifacts carry the root log" });

    // ---- Part 2: a thief holding the CURRENT root (R1) cannot rotate.
    const bad = await h.venue.rotateRootUnauthorized();
    const badData = (bad.error?.data ?? {}) as { reasonCode?: string; evidence?: Record<string, unknown> };
    say(`part 2: thief holding R1 signs a rotation to their own key, countersigned by R1 → ${badData.reasonCode ?? "ACCEPTED (!)"} (${badData.evidence?.error})`);
    if (badData.reasonCode !== "ROOT_ROTATION_UNAUTHORIZED") throw new Error("part 2: a stolen root rotated the venue");
    findings.push({ label: "part 2: stolen root cannot rotate", reasonCode: "ROOT_ROTATION_UNAUTHORIZED", by: "venue.identity", detail: `the presented key does not hash to R1's pre-commitment; previousRootCountersigned=${badData.evidence?.previousRootCountersigned} and it changes nothing`, evidence: badData.evidence });

    // ---- Part 3: root compromise. The thief certifies an operational key; the operator rotates to R2 and re-certifies the genuine key.
    await new Promise((r) => setTimeout(r, 30));
    const T = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 30));
    const thief = h.venue.certifyThiefOperationalKey();
    const forge = () => {
      const m = buildMessage({ role: "agent", data: { type: "REFUSED", loadRef: LOAD.loadRef, reasonCode: "PROTOCOL_VIOLATION", refusedBy: "venue.protocol", evidence: {} }, taskId: `task_${randomUUID()}`, contextId: "ctx_forged", senderAgentId: "venue", credentialId: "venue" });
      return venueSignMessage(m, thief.kp);
    };
    // Agents learn keys only from the venue's own published history, which the thief cannot write to; the real
    // exposure is a VERIFIER handed the thief's certificate directly — modelled below with `verifierView`.
    const before = await rpcCall(`${carrier.url}/a2a`, "message/send", { message: forge() });
    say(`part 3: T=${T.slice(11, 23)}Z; thief certifies operational key ${thief.kp.kid.slice(0, 10)}… with the stolen R1 (cert seq 99, off-venue). A thief-signed venue message to the carrier before any remediation → ${before.error ? `refused (${before.error.message})` : "ACCEPTED"} — the agent only learns keys from the venue's own history, which the thief cannot write to; but a verifier handed the thief's certificate would trust it, because R1 signed it`);
    const comp = await h.venue.rotateRoot("COMPROMISE", T);
    if (comp.error) throw new Error(`part 3: compromise rotation refused ${JSON.stringify(comp.error.data)}`);
    const r2 = comp.result!.rootKid;
    await Promise.all([broker.refreshVenueKeys(), carrier.refreshVenueKeys()]);
    const history = await h.venue.venueKeys();
    const chain3 = verifyChain(ledger(), { rootPublicKey: foundingRoot });
    const genuineKid = (await (await fetch(`${h.venue.url}/health`)).json() as { kid: string }).kid;
    const after = await rpcCall(`${carrier.url}/a2a`, "message/send", { message: forge() });
    const { makeResolver } = await import("../../protocol/venue-keys");
    const verifierView = makeResolver(foundingRoot, { ...history, certs: [...history.certs, thief.cert] });
    const thiefTrusted = verifierView.untrustedAt(thief.kp.kid, new Date());
    const genuineTrusted = verifierView.untrustedAt(genuineKid, new Date(new Date(T).getTime() - 10));
    const genuineTrustedAfter = verifierView.untrustedAt(genuineKid, new Date());
    const d = await negotiate(h, broker, carrier, loadIds(2));
    const artD = JSON.parse(readFileSync(join(broker.dir, "commitments", `${d.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const vD = verifyArtifact(artD, { pinnedRootKey: foundingRoot, keyHistory: history });
    const vAnow = verifyArtifact(artA, { pinnedRootKey: foundingRoot, keyHistory: history });
    say(`   operator declares R1 compromised as of T, reveals pre-committed R2 ${r2.slice(0, 10)}…, re-certifies the genuine operational key ${genuineKid.slice(0, 10)}… under R2 with its original validFrom (${comp.result!.recertified ? "done" : "MISSING"})`);
    say(`   a verifier holding the thief's R1-signed certificate now says: thief's key → ${thiefTrusted ? `UNTRUSTED (${thiefTrusted})` : "trusted (!)"}; genuine key before T → ${genuineTrusted ? "untrusted (!)" : "trusted"}; genuine key now → ${genuineTrustedAfter ? "untrusted (!)" : "trusted"}`);
    say(`   agents re-pinned ${brokerPinned().slice(0, 10)}…; thief-signed message to the carrier → ${after.error ? "refused" : "ACCEPTED (!)"}; ledger verifies from the founding root: ${chain3.ok} (${chain3.rootsSeen?.length} roots); next load under the re-certified key → ${d.task!.status}, artifact verifies: ${vD.ok}; pre-compromise artifact still verifies: ${vAnow.ok}`);
    if (!comp.result!.recertified || brokerPinned() !== r2 || !thiefTrusted || genuineTrusted || genuineTrustedAfter || !after.error || !chain3.ok || d.task!.status !== "COMMITTED" || !vD.ok || !vAnow.ok) throw new Error("part 3: root compromise remediation incomplete");
    findings.push(
      { label: "part 3: root compromise", reasonCode: "VENUE_KEY_UNTRUSTED", by: "venue.identity", detail: `the COMPROMISE root event marks R1 untrusted from T; certificates R1 signed after T (the thief's) are untrusted; the genuine operational key is re-certified under R2 for its whole tenure, so nothing it signed needs re-signing; R2 commits to H(R3) for next time` },
      { label: "what a stolen root buys", detail: "certifying keys until the compromise is declared — never rotating the root, and never keeping those certificates alive afterwards. The blast radius is bounded by detection time, not by possession" },
      { label: "what is still out of band", detail: "the founding ceremony itself (generating R0 and R1), custody of the next root, and detecting the compromise. Pre-rotation makes recovery mechanical; it does not make detection automatic" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "ROOT_ROTATION_UNAUTHORIZED",
      refusedBy: "venue.identity",
      evidence: badData.evidence ?? {},
      guaranteeWouldHavePaid: "N/A — refused before anything changed. If a stolen root could rotate, the thief would own the venue's identity permanently.",
      taskId: r1task.taskId,
      commitmentId: t1.commitmentId,
      findings,
      auditRefs: pickAudit(audit, "venue", (e) => e.event === "root-rotation"),
    };
  },
};
