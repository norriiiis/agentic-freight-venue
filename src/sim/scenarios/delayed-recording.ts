import { readFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { Scenario, Finding } from "../scenario";
import { LOAD, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup, negotiate } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { LedgerEntry } from "../../ledger/chain";
import type { OkpJwk } from "../../protocol/crypto";

export const delayedRecording: Scenario = {
  id: "delayed-recording",
  title: "Delayed recording: a venue that acknowledges a revocation must record it or be proven to have broken its word; one that refuses to acknowledge leaves an unanswered public claim",
  summary: "Status changes arrive as SOURCE-signed notices (here: the registry feed). The venue must answer with a signed inclusion promise before it can do anything else. Part 1: honest — promise, entry, witness sees inclusion. Part 2: the venue acknowledges and then quietly does not record; the source lodges the promise with a witness; past the deadline the witness holds proof the promise was broken and halts; a verifier with the proof — or with just the promise and the ledger — refuses. Part 3: the venue refuses to acknowledge at all; the source lodges the unanswered notice with the witness, which publishes it as PENDING; a verifier pinning that witness sees status as uncertain — until the venue records it, which resolves the pending notice.",
  expect: { outcome: "REFUSED", reasonCode: "INCLUSION_PROMISE_BROKEN", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    h.opts.venue = { inclusionDelayMs: 1200 };
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    const witness = await h.startWitness("witness-1", 60_000);
    const witnessKey = { witnessId: "witness-1", publicKey: (await witness.status()).publicKey };
    const feed = await h.startNoticeSource("fmcsa-li-feed");
    const feedKey = { witnessId: feed.sourceId, publicKey: feed.kp.publicJwk };
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const ledger = () => readFileSync(join(h.venue.dir, "ledger.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
    const findings: Finding[] = [];

    const a = await negotiate(h, broker, carrier, LOAD);
    const art = JSON.parse(readFileSync(join(broker.dir, "commitments", `${a.task!.commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const carrierCred = (await carrier.identity()).credentialId!;
    await witness.poll();

    // ---- Part 1: honest path. Notice → promise → entry with provenance → witness sees it.
    const n1 = feed.sign({ noticeId: `ntc_${randomUUID().slice(0, 8)}`, subject: { credentialId: carrierCred }, assertion: "INSURANCE_CANCELLED", effectiveAt: new Date().toISOString(), reason: "BMC-91X cancellation filed by Great Plains Mutual" });
    const s1 = await h.venue.submitNotice(n1);
    await witness.watch({ promise: s1.promise! });
    await witness.poll();
    const e1 = ledger().find((e) => (e.payload as { noticeHash?: string }).noticeHash === s1.promise!.noticeHash);
    const v1 = verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: [witnessKey], inclusionPromises: [s1.promise!], ledger: ledger(), asOf: new Date(), maxStalenessMs: 5000 });
    say(`part 1: registry feed submits a source-signed INSURANCE_CANCELLED notice for the carrier → venue returns a signed inclusion promise (by ${s1.promise!.includeBy.slice(11, 23)}Z) and records it at seq ${e1?.seq} with provenance (source ${(e1?.payload as { sourceId?: string }).sourceId}); witness resolved the promise: ${(await witness.resolved()).length}`);
    say(`   verifier holding the promise + ledger → ${v1.ok ? "VERIFIED" : v1.reasonCode}: ${v1.checks.find((c) => c.name.startsWith("inclusion["))?.detail}`);
    if (!s1.recorded || !e1 || !v1.ok) throw new Error("part 1: honest inclusion failed");
    findings.push({ label: "part 1: promise honoured", detail: `a CREDENTIAL_STATUS entry now carries the source's signed notice hash; the entry's provenance is the feed's assertion, not the venue's` });

    // ---- Part 2: acknowledge, then suppress.
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 60 }));
    const c2Cred = (await carrier2.identity()).credentialId!;
    await h.venue.noticeFault({ suppressNotices: true });
    const n2 = feed.sign({ noticeId: `ntc_${randomUUID().slice(0, 8)}`, subject: { credentialId: c2Cred }, assertion: "AUTHORITY_REVOKED", effectiveAt: new Date().toISOString(), reason: "FMCSA revocation notice" });
    const s2 = await h.venue.submitNotice(n2);
    await witness.watch({ promise: s2.promise! });
    say(`part 2: notice for ${carrier2.spec.agentId} → venue returns a promise (by ${s2.promise!.includeBy.slice(11, 23)}Z) and then does NOT record it; the feed lodges the promise with witness-1`);
    // Something else lands on the ledger after the deadline so the witness cosigns a head past it.
    await new Promise((r) => setTimeout(r, 1400));
    await h.venue.noticeFault(null);
    const b = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-262-0490", commodity: "Paper products, palletized", weightLbs: 40_100 });
    const p2 = await witness.poll();
    const brokenList = await witness.broken();
    const ws = await witness.status();
    say(`   deadline passes; a later commitment (${b.task!.status}) advances the chain; witness cosigns seq ${p2.receipt?.seq} at ${p2.receipt?.at.slice(11, 23)}Z → promise ${brokenList[0]?.promise.noticeId} BROKEN: ${brokenList.length} proof(s); witness halted: ${!!ws.halted}`);
    const vBroken = verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: [witnessKey], brokenPromises: brokenList, ledger: ledger(), asOf: new Date(), maxStalenessMs: 5000 });
    const vPromise = verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: [witnessKey], inclusionPromises: [s2.promise!], ledger: ledger(), asOf: new Date(), maxStalenessMs: 5000 });
    say(`   verifier with the witness's proof → ${vBroken.reasonCode ?? "VERIFIED"}; verifier with just the promise + ledger + witnessed list → ${vPromise.reasonCode ?? "VERIFIED"}: ${vPromise.checks.find((c) => c.name.startsWith("inclusion["))?.detail}`);
    if (brokenList.length !== 1 || !ws.halted || vBroken.reasonCode !== "INCLUSION_PROMISE_BROKEN" || vPromise.reasonCode !== "INCLUSION_PROMISE_BROKEN") throw new Error("part 2: broken promise not proven");
    findings.push({ label: "part 2: acknowledged, then suppressed", reasonCode: "INCLUSION_PROMISE_BROKEN", by: "witness", detail: "the venue signed 'received, will record by T'; a witness-cosigned head past T does not contain it; the promise plus that receipt is the proof, and the witness halts. A verifier can also check any promise it holds itself against the ledger" });

    // ---- Part 3: refuse to acknowledge. The floor. (witness-1 has halted — correctly, it will never trust this
    // venue's chain again — so a second, still-trusting witness carries the pending notice.)
    const witness2 = await h.startWitness("witness-2", 60_000);
    const witness2Key = { witnessId: "witness-2", publicKey: (await witness2.status()).publicKey };
    await witness2.poll();
    await h.venue.noticeFault({ dropNotices: true });
    const brokerCred = (await broker.identity()).credentialId!;
    const n3 = feed.sign({ noticeId: `ntc_${randomUUID().slice(0, 8)}`, subject: { credentialId: brokerCred }, assertion: "REVOKED", effectiveAt: new Date().toISOString(), reason: "BMC-84 bond cancelled" });
    const s3 = await h.venue.submitNotice(n3);
    await witness2.watch({ notice: n3, submissionOutcome: s3.failure ?? "no acknowledgment" });
    const pendingList = await witness2.pending();
    const vPending = verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: [witness2Key], pendingNotices: pendingList, noticeSources: [feedKey], ledger: ledger(), asOf: new Date(), maxStalenessMs: 5000 });
    say(`part 3: notice for the broker's credential → venue refuses to acknowledge (${s3.failure}); the feed lodges the raw notice with witness-2, which publishes it as PENDING (${pendingList.length})`);
    say(`   verifier pinning witness-2 → ${vPending.reasonCode ?? "VERIFIED"}: ${vPending.checks.find((c) => c.name === "status.no-pending-notices")?.detail}`);
    if (!s3.failure || pendingList.length !== 1 || vPending.reasonCode !== "NOTICE_PENDING") throw new Error("part 3: pending notice not surfaced");
    // The venue comes clean: notice resubmitted, recorded; the witness resolves it on its next verified chain.
    await h.venue.noticeFault(null);
    const s3b = await h.venue.submitNotice(n3);
    await witness2.poll();
    const pendingAfter = await witness2.pending();
    const vAfter = verifyArtifact(art, { pinnedRootKey: root, statusList: await h.venue.statusList(), keyHistory: await h.venue.venueKeys(), witnessKeys: [witness2Key], pendingNotices: pendingAfter, noticeSources: [feedKey], ledger: ledger(), asOf: new Date(), maxStalenessMs: 5000 });
    say(`   venue later records it (promise by ${s3b.promise?.includeBy.slice(11, 23)}Z, recorded ${s3b.recorded}); witness-2 resolves the pending notice on its next verified chain → pending now ${pendingAfter.length}; verifier → ${vAfter.ok ? "VERIFIED (the revocation is now visible and post-dates the signature)" : vAfter.reasonCode}`);
    if (pendingAfter.length !== 0 || !vAfter.ok) throw new Error("part 3: pending notice did not resolve");
    findings.push(
      { label: "part 3: never acknowledged", reasonCode: "NOTICE_PENDING", by: "witness", detail: "no promise, so no proof of breach — but the source-signed claim is public through a witness the verifier pins, and status is 'uncertain', not 'fine', until the venue records it. That is the floor: an unanswered claim, not silence" },
      { label: "what this leaves", detail: "a source that never notifies anyone — the insurer that cancels and tells no one but the registry — and a registry the venue does not read. The venue's own polling of feeds is a convenience; the guarantee is only as good as sources that push and demand a promise" },
    );

    const audit = await h.venue.audit();
    const waudit = readFileSync(join(witness.dir, "audit.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    return {
      outcome: "REFUSED",
      reasonCode: "INCLUSION_PROMISE_BROKEN",
      refusedBy: "ledger/verify",
      evidence: { promise: { noticeId: s2.promise!.noticeId, receivedAt: s2.promise!.receivedAt, includeBy: s2.promise!.includeBy }, headReceipt: { witnessId: brokenList[0]!.headReceipt.witnessId, seq: brokenList[0]!.headReceipt.seq, at: brokenList[0]!.headReceipt.at }, detectedBy: brokenList[0]!.detectedBy },
      guaranteeWouldHavePaid: "N/A — a venue proven to break an inclusion promise has forfeited the trust every guarantee rests on; the promise and the witness receipt are the evidence a regulator or the insurer backing the guarantee would act on.",
      taskId: a.task!.task.id,
      commitmentId: a.task!.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.event === "notice-suppressed" || e.event === "notice-dropped"), ...pickAudit(waudit, "witness-1", (e) => e.reasonCode === "INCLUSION_PROMISE_BROKEN")],
    };
  },
};
