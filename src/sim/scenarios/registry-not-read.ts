import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup, negotiate, resultFromTask } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { OkpJwk } from "../../protocol/crypto";
import type { InsuranceFiling } from "../../protocol/registry";

const cancelBipd = (insurance: InsuranceFiling[], on: string) => insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: on } : f));

export const registryNotRead: Scenario = {
  id: "registry-not-read",
  title: "Source never notifies: the insurer cancels with the registry and tells no one; a venue that does not ask the registry commits an uninsured carrier — and its own artifact proves it",
  summary: "Insurers file cancellations with FMCSA, not with venues. So the venue must ASK: before every step it obtains the registry's signed word no older than its freshness policy, and at commitment it obtains it anew and embeds it in the artifact. Part 1: honest venue, nobody notified it — the registry's word says lapsed, refused. Part 2: a venue that read the registry at onboarding and never again — its artifact carries the registry's word from before the cancellation, older than its own policy: REGISTRY_STALE; the registry's word fetched today shows the carrier was uninsured at commitment: REGISTRY_CONTRADICTS_COMMITMENT — no help from the venue needed. Part 3: a venue that reads the lapse and commits anyway — the attestation it could not forge indicts it. Part 4: the registry is unreachable — the venue refuses rather than attest from memory.",
  expect: { outcome: "REFUSED", reasonCode: "REGISTRY_STALE", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    const registryKey = await h.registry.key();
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (commitmentId: string) => JSON.parse(readFileSync(join(broker.dir, "commitments", `${commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const failing = (v: ReturnType<typeof verifyArtifact>) => v.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`);
    const findings: Finding[] = [];
    const policyMs = h.opts.venue?.registryMaxAgeMs ?? 1000;

    // ---- Control: an honest commitment carries the registry's fresh signed word on both parties.
    const c0 = await negotiate(h, broker, carrier, LOAD);
    const art0 = artifactOf(c0.task!.commitmentId!);
    const v0 = verifyArtifact(art0, { pinnedRootKey: root, registryKeys: [registryKey] });
    say(`control: ${c0.task!.status} ${art0.commitmentId.slice(0, 16)}… — artifact embeds registry ${art0.registry?.registryId} attestations for both parties (policy ${art0.registry?.policy.maxAgeMs}ms); verifier pinning the registry key → ${v0.ok ? "VERIFIED" : v0.reasonCode}: ${v0.checks.find((c) => c.name === "carrier.registry.fresh-at-commitment")?.detail}`);
    if (!v0.ok || !art0.registry) throw new Error("control: honest artifact did not verify with the registry key");

    // ---- The event nobody reports to the venue.
    const rec = await h.registry.record("2751903");
    await h.registry.update("2751903", { insurance: cancelBipd(rec.insurance, "2026-09-18") });
    say(`registry: Great Plains Mutual files BMC-91X cancellation for PRAIRIE WIND TRANSPORT, effective 2026-09-18. It tells the registry, as the law requires — and no one else. Venue status list: ${(await h.venue.statusList()).entries.length} entries.`);

    // ---- Part 1: honest venue. It asks on its own schedule; the registry's word says lapsed.
    await new Promise((r) => setTimeout(r, policyMs + 200));
    const p1 = await negotiate(h, broker, carrier, { ...LOAD, loadRef: "L-2026-263-0512", commodity: "Bagged fertilizer, palletized", weightLbs: 41_600 });
    const r1 = await resultFromTask(h, p1.task!);
    const ev1 = r1.evidence as { registry?: { registryId: string; asOf: string; kid: string } } | undefined;
    say(`part 1: honest venue tenders a new load → ${r1.outcome} ${r1.reasonCode} (${r1.refusedBy}); the refusal rests on registry ${ev1?.registry?.registryId}'s signature as of ${ev1?.registry?.asOf?.slice(11, 23)}Z — no notice was ever sent`);
    if (r1.reasonCode !== "INSURANCE_LAPSED") throw new Error("part 1: honest venue did not catch the lapse");
    findings.push({ label: "part 1: honest venue, no notice", reasonCode: "INSURANCE_LAPSED", by: "venue.identity", detail: "the venue's status list is clean and no source ever wrote to it; the refusal cites the registry's signed attestation, obtained at tender intake because the word it held had aged past its policy" });

    // ---- Part 2: a venue that read the registry once. Blue Mesa onboards insured; its insurer then cancels; the venue never asks again.
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 60 }));
    await h.venue.seedHistory("1984411", CARRIER_HISTORY);
    const mirrorAt = (await h.venue.registryMirror()).attestations.find((a) => a.usdot === "1984411")!;
    await h.venue.fault({ registryStale: true });
    const rec2 = await h.registry.record("1984411");
    await h.registry.update("1984411", { insurance: cancelBipd(rec2.insurance, "2026-09-19") });
    say(`part 2: ${carrier2.spec.agentId} onboarded; venue mirrored the registry's word as of ${mirrorAt.asOf.slice(11, 23)}Z. Then its insurer files a cancellation effective 2026-09-19. The venue stops asking (registryStale fault).`);
    await new Promise((r) => setTimeout(r, policyMs + 300));
    const p2 = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-263-0533", commodity: "Steel coil, tarped", weightLbs: 43_200 });
    if (p2.task!.status !== "COMMITTED") throw new Error(`part 2: expected the lazy venue to commit, got ${p2.task!.status} ${p2.task!.outcome?.reasonCode}`);
    const art2 = artifactOf(p2.task!.commitmentId!);
    const v2 = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: [registryKey] });
    const current = await h.registry.attest("1984411");
    const v2b = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: [registryKey], currentAttestations: [current] });
    say(`   venue COMMITS ${art2.commitmentId.slice(0, 16)}… with guarantee ${art2.underwriting.decision === "GUARANTEED" ? "ATTACHED" : "none"}; the artifact's registry word on the carrier is as of ${art2.registry?.attestations.carrier.asOf.slice(11, 23)}Z, commitment at ${art2.createdAt.slice(11, 23)}Z`);
    say(`   verifier pinning the registry key → ${v2.reasonCode ?? "VERIFIED"}: ${v2.checks.find((c) => c.name === "carrier.registry.fresh-at-commitment")?.detail}`);
    say(`   verifier who also fetches the registry's word TODAY (as of ${current.asOf.slice(11, 23)}Z) → ${v2b.reasonCode ?? "VERIFIED"}: ${v2b.checks.find((c) => c.name === "carrier.registry.standing-per-current-record")?.detail?.slice(0, 160)}`);
    if (v2.reasonCode !== "REGISTRY_STALE" || v2b.reasonCode !== "REGISTRY_CONTRADICTS_COMMITMENT" || art2.underwriting.decision !== "GUARANTEED") throw new Error("part 2: stale registry word not caught");
    await h.venue.fault(null);
    findings.push(
      { label: "part 2: read once, never again", reasonCode: "REGISTRY_STALE", by: "ledger/verify", detail: `the artifact must carry the registry's signed word the venue relied on; here it is ${Math.round((new Date(art2.createdAt).getTime() - new Date(art2.registry!.attestations.carrier.asOf).getTime()) / 100) / 10}s old at commitment against the ${art2.registry!.policy.maxAgeMs / 1000}s policy the venue itself declares in the artifact. The venue did not ask — and cannot say it did` },
      { label: "part 2: the registry's word today settles it", reasonCode: "REGISTRY_CONTRADICTS_COMMITMENT", by: "ledger/verify", detail: "cancellation dates are history: today's signed record shows the filing was already cancelled at the commitment time in the artifact. This needs nothing from the venue — only the registry key and the artifact" },
    );

    // ---- Part 3: a venue that reads the lapse and commits anyway (and tells the broker the coverage is fine).
    await h.venue.fault({ ignoreRegistry: true });
    const p3 = await negotiate(h, broker, carrier, { ...LOAD, loadRef: "L-2026-263-0561", commodity: "Lumber, bundled", weightLbs: 39_400 });
    if (p3.task!.status !== "COMMITTED") throw new Error(`part 3: expected the dishonest venue to commit, got ${p3.task!.status} ${p3.task!.outcome?.reasonCode}`);
    const art3 = artifactOf(p3.task!.commitmentId!);
    const v3 = verifyArtifact(art3, { pinnedRootKey: root, registryKeys: [registryKey] });
    say(`part 3: venue re-reads the registry (word as of ${art3.registry?.attestations.carrier.asOf.slice(11, 23)}Z says LAPSED), reports $1,000,000 BIPD to the broker, and COMMITS ${art3.commitmentId.slice(0, 16)}… with guarantee ${art3.underwriting.decision === "GUARANTEED" ? "ATTACHED" : "none"}`);
    say(`   verifier → ${v3.reasonCode ?? "VERIFIED"}: ${v3.checks.find((c) => c.name === "carrier.registry.standing-at-commitment")?.detail?.slice(0, 160)}`);
    if (v3.reasonCode !== "REGISTRY_CONTRADICTS_COMMITMENT") throw new Error("part 3: contradiction not caught");
    await h.venue.fault(null);
    findings.push({ label: "part 3: read it, ignored it", reasonCode: "REGISTRY_CONTRADICTS_COMMITMENT", by: "ledger/verify", detail: "the venue cannot forge the registry's signature and cannot omit it (a verifier pinning the registry treats absence as REGISTRY_ATTESTATION_MISSING); so the attestation it embeds is the registry's real record, and rerunning the standing check over it exposes the commitment as made against the registry's word" });

    // ---- Part 4: the registry goes dark. The venue refuses rather than attest from memory.
    await h.registry.fault({ unavailable: true });
    await new Promise((r) => setTimeout(r, policyMs + 200));
    const p4 = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-263-0578", commodity: "Canned goods, palletized", weightLbs: 42_800 });
    const r4 = await resultFromTask(h, p4.task!);
    say(`part 4: registry unreachable; venue's mirrored word is older than its policy → ${r4.outcome} ${r4.reasonCode} (${r4.refusedBy}): ${(r4.evidence as { error?: string } | undefined)?.error}`);
    if (r4.reasonCode !== "REGISTRY_UNAVAILABLE") throw new Error("part 4: venue did not fail closed");
    await h.registry.fault({ unavailable: false });
    findings.push(
      { label: "part 4: registry unreachable", reasonCode: "REGISTRY_UNAVAILABLE", by: "venue.identity", detail: "fail closed: a venue that cannot obtain the registry's word cannot attest anyone's standing. The cost is liveness — no commitments while the registry is down — which is the honest price of not guessing" },
      { label: "what this leaves", detail: "the registry itself: its clock and its honesty are trusted the way a witness's are, and the insurer→registry link is a legal obligation outside this protocol. A registry that signs a stale or false record is caught only by another source that contradicts it — which is what notices and promises are for" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "REGISTRY_STALE",
      refusedBy: "ledger/verify",
      evidence: { commitmentId: art2.commitmentId, createdAt: art2.createdAt, registryWordAsOf: art2.registry!.attestations.carrier.asOf, venuePolicyMaxAgeMs: art2.registry!.policy.maxAgeMs, failedChecks: failing(v2), withCurrentRegistryWord: failing(v2b).filter((c) => c.includes("per-current-record")) },
      guaranteeWouldHavePaid: "The guarantee was attached on the venue's say-so, and the artifact shows that say-so rested on registry word older than the venue's own policy. The venue's evidence indicts it; the broker's claim is against the venue, and an insurer backing the guarantee has the artifact to deny reinsurance on.",
      taskId: p2.task!.task.id,
      commitmentId: art2.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.taskId === p1.task!.task.id && e.outcome === "REFUSED"), ...pickAudit(audit, "venue", (e) => e.event === "registry-verdict-ignored").slice(0, 1), ...pickAudit(audit, "venue", (e) => e.event === "registry-refresh" && e.outcome === "REFUSED").slice(0, 1)],
    };
  },
};
