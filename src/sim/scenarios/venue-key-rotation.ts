import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import { verifyChain, type LedgerEntry } from "../../ledger/chain";
import type { OkpJwk } from "../../protocol/crypto";

export const venueKeyRotation: Scenario = {
  id: "venue-key-rotation",
  title: "Venue key rotation: the venue cannot certify its own successor; routine rotation is invisible; a compromised venue key is replaced by the operator's root and everything it signed after the compromise is re-signed",
  summary: "The venue signs credentials, every forwarded message, every ledger entry and every attestation with an operational key certified by an offline ROOT held by the operator. Part 1: a certificate not signed by the root is refused. Part 2: a routine rotation happens while a negotiation is in flight — agents learn the new key from the root-signed history, old credentials still verify, the chain verifies from the root alone. Part 3: the operator declares the operational key compromised as of T: credentials issued after T are re-issued, commitments attested after T are re-attested, ledger entries after T are resealed, and an offline verifier with the published history rejects the un-remediated artifact but accepts the re-attested one.",
  expect: { outcome: "REFUSED", reasonCode: "VENUE_KEY_ROTATION_UNAUTHORIZED", refusedBy: "venue.identity" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 400 }, carrier: { thinkMs: 60 } });
    const findings: Finding[] = [];
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const kid0 = (await h.venue.venueKeys()).certs[0]!.kid;
    const commodities = ["Consumer packaged goods, palletized", "Paper products, palletized", "Canned goods, palletized", "Pet food, palletized"];
    const loadIds = (n: number) => ({ ...LOAD, loadRef: `L-2026-262-045${n}`, commodity: commodities[n]!, weightLbs: LOAD.weightLbs + n * 1000 });

    // A commitment under the original venue key, before anything happens.
    const a = await negotiate(h, broker, carrier, loadIds(0));
    const artA = JSON.parse(readFileSync(join(broker.dir, "commitments", `${a.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;

    // ---- Part 1: a certificate signed by anyone but the root is refused.
    const bad = await h.venue.rotateVenueKeyUnauthorized();
    const badData = (bad.error?.data ?? {}) as { reasonCode?: string; evidence?: Record<string, unknown> };
    say(`part 1: key-rotation commit with a certificate signed by an impostor root → ${badData.reasonCode ?? "ACCEPTED (!)"}`);
    if (badData.reasonCode !== "VENUE_KEY_ROTATION_UNAUTHORIZED") throw new Error("part 1: unauthorized certificate was accepted");
    const refusal = (await h.venue.audit()).find((e) => e.reasonCode === "VENUE_KEY_ROTATION_UNAUTHORIZED" && e.event === "key-rotation/prepare") ?? { evidence: badData.evidence };

    // ---- Part 2: routine rotation while a negotiation is in flight.
    const r1 = await broker.tender(loadIds(1), { agentId: carrier.spec.agentId });
    await h.venue.waitRound(r1.taskId!, 2);
    const rot = await h.venue.rotateVenueKey("ROTATION");
    if (rot.error) throw new Error(`part 2: rotation refused ${JSON.stringify(rot.error.data)}`);
    const kid1 = rot.result!.kid;
    say(`part 2: operator rotates the venue key mid-negotiation → ${kid0.slice(0, 10)}… retired, ${kid1.slice(0, 10)}… active (cert seq ${rot.result!.seq}); the KEY_ROTATION ledger entry is signed by the successor and carries its root-signed certificate`);
    const t1 = await h.venue.waitTerminal(r1.taskId!);
    await Promise.all([broker.waitStatus(r1.taskId!, ["COMMITTED"]), carrier.waitStatus(r1.taskId!, ["COMMITTED"])]);
    const bId = await broker.identity();
    const cId = await carrier.identity();
    const learned = (await broker.audit()).filter((e) => e.event === "venue-keys-refreshed").length;
    const art1 = JSON.parse(readFileSync(join(broker.dir, "commitments", `${t1.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    say(`   in-flight negotiation → ${t1.status}; agents learned the new key from the root-signed history on first sight (broker refreshes: ${learned}; kids known: broker ${bId.venueKidsKnown.length}, carrier ${cId.venueKidsKnown.length}); credentials issued under ${kid0.slice(0, 10)}… still verify (issuer kid ${bId.issuerKid?.slice(0, 10)}…)`);
    const ledger = () => readFileSync(join(h.venue.dir, "ledger.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
    const chain2 = verifyChain(ledger(), { rootPublicKey: root });
    const v1 = verifyArtifact(art1, { pinnedRootKey: root });
    say(`   ledger verifies from the root alone across the rotation: ${chain2.ok} (${chain2.keysSeen?.length} venue keys); new artifact embeds certs for ${art1.venue.certs.length} venue keys (attestation by ${art1.venueAttestations[0]!.kid.slice(0, 10)}…, credentials issued by ${art1.credentials.broker.issuer.kid.slice(0, 10)}…) → ${v1.ok ? "VERIFIED" : v1.reasonCode}`);
    if (t1.status !== "COMMITTED" || !chain2.ok || !v1.ok || art1.venue.certs.length !== 2) throw new Error("part 2: routine rotation disturbed the system");
    findings.push({ label: "part 2: routine rotation mid-negotiation", reasonCode: "COMMITTED", by: "venue.commitment", detail: `agents pin the ROOT and accept any operational key with a root-signed certificate, refreshing from /.well-known/venue-keys.json on an unfamiliar kid; the ledger and artifacts carry the certificates a verifier needs` });

    // ---- Part 3: compromise of the operational key as of T.
    await new Promise((r) => setTimeout(r, 30));
    const T = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 30));
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 60 })); // credential issued AFTER T under the soon-to-be-compromised key
    const c = await negotiate(h, broker, carrier, loadIds(2));            // commitment attested AFTER T
    const cCommitmentId = c.task!.commitmentId!;
    const cId2before = await carrier2.identity();
    const artCbefore = JSON.parse(readFileSync(join(broker.dir, "commitments", `${cCommitmentId}.json`), "utf8")) as CommitmentArtifact;
    say(`part 3: T=${T.slice(11, 23)}Z; after T the venue issued a credential (${cId2before.credentialId?.slice(0, 18)}… for ${carrier2.spec.agentId}) and attested a commitment (${cCommitmentId.slice(0, 16)}…) under ${kid1.slice(0, 10)}…`);
    const comp = await h.venue.rotateVenueKey("COMPROMISE", T);
    if (comp.error) throw new Error(`part 3: compromise rotation refused ${JSON.stringify(comp.error.data)}`);
    const kid2 = comp.result!.kid;
    await new Promise((r) => setTimeout(r, 400));
    const cId2after = await carrier2.identity();
    const bIdAfter = await broker.identity();
    const artCafter = JSON.parse(readFileSync(join(broker.dir, "commitments", `${cCommitmentId}.json`), "utf8")) as CommitmentArtifact;
    const history = await h.venue.venueKeys();
    const chain3 = verifyChain(ledger(), { rootPublicKey: root });
    say(`   operator declares ${kid1.slice(0, 10)}… compromised as of T and certifies ${kid2.slice(0, 10)}…: ${comp.result!.credentialsReissued.length} credential(s) re-issued, ${comp.result!.commitmentsReattested.length} commitment(s) re-attested, ledger entries ${comp.result!.resealed ? `${comp.result!.resealed.fromSeq}–${comp.result!.resealed.toSeq}` : "none"} resealed`);
    say(`   ${carrier2.spec.agentId}'s credential now issued by ${cId2after.issuerKid?.slice(0, 10)}… (was ${cId2before.issuerKid?.slice(0, 10)}…); broker's pre-T credential untouched (issuer ${bIdAfter.issuerKid?.slice(0, 10)}…); broker's copy of the post-T artifact now attested by ${artCafter.venueAttestations.at(-1)!.kid.slice(0, 10)}… with re-issued credentials (the old attestation no longer binds the new content and is dropped); ledger verifies from the root with the reseal: ${chain3.ok}`);
    const vOld = verifyArtifact(artCbefore, { pinnedRootKey: root, keyHistory: history });
    const vNew = verifyArtifact(artCafter, { pinnedRootKey: root, keyHistory: history });
    const vA = verifyArtifact(artA, { pinnedRootKey: root, keyHistory: history });
    const vOldNoHistory = verifyArtifact(artCbefore, { pinnedRootKey: root });
    say(`   offline verifier with the published key history: un-remediated post-T artifact → ${vOld.ok ? "VERIFIED (!)" : vOld.reasonCode}; re-attested copy → ${vNew.ok ? "VERIFIED" : vNew.reasonCode}; pre-T artifact → ${vA.ok ? "VERIFIED" : vA.reasonCode}; post-T artifact WITHOUT the history → ${vOldNoHistory.ok ? "VERIFIED (compromise invisible offline)" : vOldNoHistory.reasonCode}`);
    const d = await negotiate(h, broker, carrier2, loadIds(3));
    say(`   business continues under ${kid2.slice(0, 10)}…: ${carrier2.spec.agentId} (re-issued credential) commits a new load → ${d.task!.status}`);
    if (cId2after.issuerKid !== kid2 || bIdAfter.issuerKid !== kid0 || artCafter.venueAttestations.at(-1)!.kid !== kid2 || !chain3.ok || vOld.ok || !vNew.ok || !vA.ok || d.task!.status !== "COMMITTED") throw new Error("part 3: compromise remediation incomplete");
    findings.push(
      { label: "part 3: venue key compromise", reasonCode: "VENUE_KEY_UNTRUSTED", by: "venue.identity", detail: `root-signed revocation with compromisedAt=T; credentials issued after T re-signed (same id; signedAt updated), commitments attested after T re-attested under the new key with their re-issued credentials, ledger entries after T RESEALed by the new key; agents received CREDENTIAL_REISSUED / COMMITMENT_REATTESTED` },
      { label: "offline verification", detail: `with /.well-known/venue-keys.json the un-remediated post-T artifact fails venue.attestation.any-trusted; the re-attested one passes; the pre-T one passes; without the history the compromise is invisible — same story as agent-key compromise` },
      { label: "what the venue process cannot do", detail: "certify its own successor. Both the certificate and the revocation come from the operator's root, which the process never holds — the same principle as agent keys (principal) and mandates (principal)" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "VENUE_KEY_ROTATION_UNAUTHORIZED",
      refusedBy: "venue.identity",
      evidence: (refusal as { evidence?: Record<string, unknown> }).evidence ?? {},
      guaranteeWouldHavePaid: "N/A — refused before anything changed. A venue that could certify its own successor would make a stolen operational key a permanent takeover.",
      taskId: r1.taskId,
      commitmentId: t1.commitmentId,
      findings,
      auditRefs: pickAudit(audit, "venue", (e) => e.event === "venue-key-rotation" || e.reasonCode === "VENUE_KEY_ROTATION_UNAUTHORIZED"),
    };
  },
};
