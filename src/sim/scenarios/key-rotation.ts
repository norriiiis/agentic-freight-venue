import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { OkpJwk } from "../../protocol/crypto";
import type { SignedMeta } from "../../protocol/envelope";

export const keyRotation: Scenario = {
  id: "key-rotation",
  title: "Agent key rotation: routine rotation mid-negotiation is invisible; a key cannot rotate itself; a compromised key is replaced by the principal and its post-compromise deals are voided",
  summary: "Part 1: the carrier's principal rotates the agent key between the carrier's ACCEPT and the broker's countersign; the commitment records the credential that actually signed, verifies, and survives the pre-pickup check. Part 2: the agent (or a thief holding its key) tries to rotate on its own — refused. Part 3: the principal declares the key compromised as of T; the venue voids the commitment signed after T, releases its guarantee, locks the old key out, and the principal re-provisions the agent with a new key it never shared with the old process.",
  expect: { outcome: "REFUSED", reasonCode: "ROTATION_UNAUTHORIZED", refusedBy: "venue.identity" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 500 }, carrier: { thinkMs: 60 } });
    const findings: Finding[] = [];
    const venueKey = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const id0 = await carrier.identity();

    // ---- Part 1: routine rotation in the window between the carrier's ACCEPT and the broker's countersign.
    const rA = await broker.tender(LOAD, { agentId: carrier.spec.agentId });
    const start = Date.now();
    while (Date.now() - start < 8000) {
      const t = (await h.venue.tasks()).find((x) => x.task.id === rA.taskId);
      if (t?.status === "COUNTERSIGN") break;
      await new Promise((r) => setTimeout(r, 15));
    }
    const rot = await carrier.rotate("ROTATION");
    if (!rot.ok) throw new Error(`part 1: rotation refused ${rot.reasonCode}`);
    const id1 = await carrier.identity();
    say(`part 1: carrier ACCEPTed under ${id0.kid.slice(0, 10)}…; principal-authorized rotation while the broker deliberates → new key ${id1.kid.slice(0, 10)}…, credential ${id1.credentialId?.slice(0, 18)}… supersedes ${rot.superseded.credentialId.slice(0, 18)}… (grace until ${rot.superseded.graceUntil?.slice(11, 19)}Z)`);
    const tA = await h.venue.waitTerminal(rA.taskId!);
    await Promise.all([broker.waitStatus(rA.taskId!, ["COMMITTED"]), carrier.waitStatus(rA.taskId!, ["COMMITTED"])]);
    if (tA.status !== "COMMITTED") throw new Error(`part 1: expected COMMITTED, got ${tA.status} ${tA.outcome?.reasonCode}`);
    const artA = JSON.parse(readFileSync(join(broker.dir, "commitments", `${tA.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const signingCredA = artA.credentials.carrier.credentialId;
    const statusList = await h.venue.credentialStatus();
    const vA = verifyArtifact(artA, { pinnedRootKey: venueKey, statusList });
    const pre = await h.venue.prePickupChecks();
    const stillActive = (await h.venue.commitments()).find((c) => c.commitmentId === tA.commitmentId)?.status;
    say(`   committed ${tA.commitmentId}: artifact embeds the SIGNING credential for the carrier (${signingCredA.slice(0, 18)}… = old ${signingCredA === rot.superseded.credentialId}); verifies with status list: ${vA.ok} (${vA.checks.find((c) => c.name === "carrier.credential.trusted-at-signing")?.detail}); pre-pickup check voided ${pre.voided.length} → still ${stillActive}`);
    if (signingCredA !== rot.superseded.credentialId || !vA.ok || stillActive !== "ACTIVE") throw new Error("part 1: rotation disturbed the in-flight commitment");
    const b = await negotiate(h, broker, carrier, { ...LOAD, loadRef: "L-2026-262-0440", commodity: "Pet food, palletized", weightLbs: 39_800 });
    const artB = JSON.parse(readFileSync(join(broker.dir, "commitments", `${b.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    say(`   next load under the new key → ${b.task!.status}; artifact embeds ${artB.credentials.carrier.credentialId.slice(0, 18)}… (new: ${artB.credentials.carrier.credentialId === id1.credentialId})`);
    findings.push({ label: "part 1: routine rotation mid-negotiation", reasonCode: "COMMITTED", by: "venue.commitment", detail: "credential lineage (supersedes), old key accepted inside its grace window, artifact embeds the signing credential per acceptance, pre-pickup check uses the CURRENT credential for standing and the SIGNING credential only for compromise-before-signature" });

    // ---- Part 2: the agent alone (or whoever stole its key) cannot rotate.
    await carrier.rotatePrepare();
    const self = await carrier.rotateSubmit({ authorization: { kind: "CURRENT_KEY_ONLY" }, reason: "ROTATION" });
    const id2 = await carrier.identity();
    say(`part 2: rotation signed only by the agent's current key → ${self.ok ? "ACCEPTED (!)" : `REFUSED ${self.reasonCode}`}; key unchanged: ${id2.kid === id1.kid}`);
    if (self.ok || id2.kid !== id1.kid) throw new Error("part 2: an agent key rotated itself");
    const refusal = (await h.venue.audit()).find((e) => e.event === "rotate" && e.outcome === "REFUSED")!;
    findings.push({ label: "part 2: self-rotation refused", reasonCode: "ROTATION_UNAUTHORIZED", by: "venue.identity", detail: `signature by the current key was valid (${(refusal.evidence as { currentKeySignatureValid?: boolean }).currentKeySignatureValid}) and still insufficient — a stolen key must not be able to rebind itself`, evidence: refusal.evidence });

    // ---- Part 3: compromise. The principal declares the key compromised as of T; a deal signed after T is voided;
    // the old process is locked out; the principal re-provisions the agent with a key the old process never held.
    await new Promise((r) => setTimeout(r, 30));
    const T = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 30));
    const c = await negotiate(h, broker, carrier, { ...LOAD, loadRef: "L-2026-262-0441", commodity: "Office furniture, palletized", weightLbs: 37_900 });
    const artC = JSON.parse(readFileSync(join(broker.dir, "commitments", `${c.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const signedC = (artC.acceptances.carrier.metadata as SignedMeta).ts;
    say(`part 3: T=${T.slice(11, 23)}Z; a further load committed with the carrier's acceptance signed at ${signedC.slice(11, 23)}Z (after T) — the deal the thief made`);
    const comp = await h.principalRotate(carrier, "COMPROMISE", T);
    if (!comp.ok) throw new Error(`part 3: principal rotation refused ${comp.reasonCode}`);
    const cNow = (await h.venue.commitments()).find((x) => x.commitmentId === c.task!.commitmentId)!;
    const aNow = (await h.venue.commitments()).find((x) => x.commitmentId === tA.commitmentId)!;
    const gC = (await h.venue.guarantees()).find((g) => g.commitmentId === c.task!.commitmentId)!;
    await Promise.all([broker.waitStatus(c.task!.task.id, ["VOIDED"]), carrier.waitStatus(c.task!.task.id, ["VOIDED"])]);
    say(`   principal rotates with reason COMPROMISE (no grace): venue voided ${comp.voidedCommitments.length} commitment(s) → ${cNow.commitmentId.slice(0, 16)}… ${cNow.status} (${cNow.voided?.reasonCode}), guarantee ${gC.status}; pre-T commitment ${aNow.commitmentId.slice(0, 16)}… still ${aNow.status}; both parties notified`);
    const lockedOut = await carrier.send({ type: "REJECT", loadRef: LOAD.loadRef, round: 1, reasonCode: "OTHER", from: { agentId: carrier.spec.agentId, usdot: carrier.spec.entity.usdot, mc: carrier.spec.entity.mc } }, c.task!.task.id, c.task!.task.contextId);
    say(`   the old process (still holding the compromised key) tries to act → ${lockedOut.refusal?.reasonCode}`);
    const carrier2 = await h.reprovisionAgent(carrier, comp.newKp, comp.credential);
    const id3 = await carrier2.identity();
    const d = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-262-0442", commodity: "Sporting goods, palletized", weightLbs: 36_400 });
    say(`   principal re-provisions the agent with the new key (${id3.kid.slice(0, 10)}…, credential ${id3.credentialId?.slice(0, 18)}…) → next load ${d.task!.status}`);
    const statusList2 = await h.venue.credentialStatus();
    const vC = verifyArtifact(artC, { pinnedRootKey: venueKey, statusList: statusList2 });
    const vA2 = verifyArtifact(artA, { pinnedRootKey: venueKey, statusList: statusList2 });
    const vCoffline = verifyArtifact(artC, { pinnedRootKey: venueKey });
    say(`   offline verifier with the published status list: post-T artifact → ${vC.ok ? "VERIFIED (!)" : vC.reasonCode}; pre-T artifact → ${vA2.ok ? "VERIFIED" : vA2.reasonCode}; post-T artifact WITHOUT the status list → ${vCoffline.ok ? "VERIFIED (signatures are genuine; compromise is invisible offline)" : vCoffline.reasonCode}`);
    if (cNow.status !== "VOIDED" || aNow.status !== "ACTIVE" || lockedOut.refusal?.reasonCode !== "CREDENTIAL_SUPERSEDED" || d.task!.status !== "COMMITTED" || vC.ok || !vA2.ok) throw new Error("part 3: compromise handling failed");
    findings.push(
      { label: "part 3: compromise", reasonCode: "COMMITMENT_UNDER_COMPROMISED_KEY", by: "venue.commitment", detail: `commitment signed after T voided (guarantee ${gC.status}); pre-T commitment untouched; old key refused as CREDENTIAL_SUPERSEDED with no grace; the principal rotated WITHOUT the agent's cooperation and re-provisioned it` },
      { label: "offline verification", detail: `with the venue's published credential-status list the post-T artifact fails carrier.credential.trusted-at-signing; without it the signatures still verify — which is why the status list is published at /.well-known/credential-status.json` },
      { label: "guarantee position", detail: "a stolen agent key is the principal's custody failure (PRINCIPAL_KEY_COMPROMISE exclusion); the venue's job is to make the blast radius small and the recovery fast, not to insure the principal's key hygiene" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "ROTATION_UNAUTHORIZED",
      refusedBy: "venue.identity",
      evidence: refusal.evidence,
      guaranteeWouldHavePaid: "N/A — refused before any transaction. A refused self-rotation is the control working: a stolen key cannot rebind itself.",
      taskId: rA.taskId,
      commitmentId: tA.commitmentId,
      findings,
      auditRefs: pickAudit(audit, "venue", (e) => e.event === "rotate" || e.reasonCode === "COMMITMENT_UNDER_COMPROMISED_KEY" || e.reasonCode === "CREDENTIAL_SUPERSEDED"),
    };
  },
};
