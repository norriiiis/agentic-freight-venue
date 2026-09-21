import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { LOAD, CARRIER_HISTORY, blueMesaCarrierSpec } from "../fixtures";
import { standardSetup, negotiate, resultFromTask } from "./common";
import { pickAudit } from "../scenario";
import { verifyArtifact, type CommitmentArtifact } from "../../ledger/artifact";
import type { OkpJwk } from "../../protocol/crypto";
import type { InsuranceFiling, RegistryRef } from "../../protocol/registry";

const cancelBipd = (insurance: InsuranceFiling[], on: string) => insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: on } : f));
type LapseEvidence = { registry?: RegistryRef; registriesShowingThis?: string[]; dissentingRegistries?: RegistryRef[]; rule?: string; registries?: Record<string, string>; error?: string };

export const registryQuorum: Scenario = {
  id: "registry-quorum",
  title: "One registry is one party to trust: independent mirrors, unanimity on standing, and a verifier that names the registries it insists on",
  summary: "Three vetting providers mirror the same upstream independently of each other and of the venue; the venue asks all three, needs two to have answered, and requires every answer to show the party in standing. Part 1: one mirror stops syncing yet claims a current sync (an honest one dates its last sync and drops out as stale) — the other two have the cancellation, so the venue refuses, and the stale mirror's signed word beside its peers' is the evidence it answers for. Part 1b: the reverse — only one mirror has the filing yet; it outranks the two that do not, because a cancellation is news that cannot be un-known. Part 2: the venue quietly drops the mirror that says no and commits on the two that say yes; a verifier who accepts any two is satisfied, a verifier who NAMES the dropped mirror is not, and the mirrors' word fetched today settles it. Part 3: fewer mirrors than the quorum answer — the venue refuses rather than judge on one.",
  expect: { outcome: "REFUSED", reasonCode: "REGISTRY_QUORUM_NOT_MET", refusedBy: "ledger/verify" },
  async run({ h, say }) {
    h.opts.venue = { registryQuorum: 2 };
    const [a, b, c] = await h.startRegistries(["li-mirror-a", "li-mirror-b", "li-mirror-c"]);
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 60 }, carrier: { thinkMs: 60 } });
    const keys = await Promise.all(h.registries.map((r) => r.key()));
    const root = JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk;
    const artifactOf = (commitmentId: string) => JSON.parse(readFileSync(join(broker.dir, "commitments", `${commitmentId}.json`), "utf8")) as CommitmentArtifact;
    const failing = (v: ReturnType<typeof verifyArtifact>) => v.checks.filter((x) => !x.ok).map((x) => `${x.name}: ${x.detail}`);
    const policyMs = h.opts.venue?.registryMaxAgeMs ?? 1000;
    const findings: Finding[] = [];

    // ---- Control: three signatures per party, unanimous.
    const c0 = await negotiate(h, broker, carrier, LOAD);
    const art0 = artifactOf(c0.task!.commitmentId!);
    const v0 = verifyArtifact(art0, { pinnedRootKey: root, registryKeys: keys });
    say(`control: ${c0.task!.status} — artifact carries ${art0.registry?.attestations.carrier.length} registry attestations per party (${art0.registry?.registries.map((r) => r.registryId).join(", ")}; policy ${art0.registry?.policy.maxAgeMs}ms, quorum ${art0.registry?.policy.quorum}); verifier pinning all three → ${v0.ok ? "VERIFIED" : v0.reasonCode}: ${v0.checks.find((x) => x.name === "carrier.registry.standing-at-commitment")?.detail}`);
    if (!v0.ok || art0.registry?.attestations.carrier.length !== 3) throw new Error("control: three-registry artifact did not verify");

    // ---- Part 1: a mirror that stopped syncing (or lies). The filing reaches the other two.
    await a!.fault({ freeze: true, claimsCurrent: true });
    const rec = await b!.record("2751903");
    await h.registryUpdate("2751903", { insurance: cancelBipd(rec.insurance, "2026-09-18") });
    say(`part 1: ${a!.registryId} stops syncing but claims a current sync (an honest one would date its last sync and drop out as stale). Great Plains Mutual files BMC-91X cancellation for PRAIRIE WIND, effective 2026-09-18: ${b!.registryId} and ${c!.registryId} have it; ${a!.registryId} still says insured.`);
    await new Promise((r) => setTimeout(r, policyMs + 200));
    const p1 = await negotiate(h, broker, carrier, { ...LOAD, loadRef: "L-2026-264-0601", commodity: "Bagged fertilizer, palletized", weightLbs: 41_600 });
    const r1 = await resultFromTask(h, p1.task!);
    const e1 = (r1.evidence ?? {}) as LapseEvidence;
    say(`   venue asks all three → ${r1.outcome} ${r1.reasonCode} (${r1.refusedBy}) on ${e1.registry?.registryId}'s word as of ${e1.registry?.asOf?.slice(11, 23)}Z; showing the lapse: ${e1.registriesShowingThis?.join(", ")}; dissenting: ${e1.dissentingRegistries?.map((d) => d.registryId).join(", ")} — ${e1.rule}`);
    if (r1.reasonCode !== "INSURANCE_LAPSED" || e1.dissentingRegistries?.[0]?.registryId !== a!.registryId) throw new Error("part 1: stale mirror not outvoted");
    findings.push({ label: "part 1: one stale mirror cannot cause a commitment", reasonCode: "INSURANCE_LAPSED", by: "venue.identity", detail: `${a!.registryId} signed "insured" with a current sync claim; ${b!.registryId} and ${c!.registryId} signed the cancellation. Unanimity refuses, and the refusal records the dissent: a signed statement ${a!.registryId} is accountable for, next to its peers' signed statements to the contrary. (An honestly stale mirror dates its last sync and is simply dropped as too old.)` });

    // ---- Part 1b: the reverse. Only one mirror has the filing yet — and it outranks the two that do not.
    await a!.fault({ freeze: false });
    const carrier2 = await h.startAgent(blueMesaCarrierSpec({ thinkMs: 60 }));
    await h.venue.seedHistory("1984411", CARRIER_HISTORY);
    await b!.fault({ freeze: true, claimsCurrent: true });
    await c!.fault({ freeze: true, claimsCurrent: true });
    const rec2 = await a!.record("1984411");
    await h.registryUpdate("1984411", { insurance: cancelBipd(rec2.insurance, "2026-09-19") });
    say(`part 1b: ${carrier2.spec.agentId} onboarded (all three vouch). Now ${b!.registryId} and ${c!.registryId} lag; Blue Mesa's insurer files a cancellation effective 2026-09-19 that only ${a!.registryId} has yet.`);
    await new Promise((r) => setTimeout(r, policyMs + 200));
    const p1b = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-264-0622", commodity: "Steel coil, tarped", weightLbs: 43_200 });
    const r1b = await resultFromTask(h, p1b.task!);
    const e1b = (r1b.evidence ?? {}) as LapseEvidence;
    say(`   → ${r1b.outcome} ${r1b.reasonCode} on ${e1b.registry?.registryId}'s word alone; dissenting: ${e1b.dissentingRegistries?.map((d) => d.registryId).join(", ")} — the one mirror that has the filing outranks the two that do not`);
    if (r1b.reasonCode !== "INSURANCE_LAPSED" || e1b.registry?.registryId !== a!.registryId || e1b.dissentingRegistries?.length !== 2) throw new Error("part 1b: fastest mirror did not block");
    findings.push({ label: "part 1b: unanimity, not majority", reasonCode: "INSURANCE_LAPSED", by: "venue.identity", detail: "two of three mirrors said insured and were outranked by the one that had the cancellation. A majority rule would have committed an uninsured carrier on the word of the slowest mirrors; a cancellation is news that cannot be un-known, so one signed lapse is enough" });

    // ---- Part 2: the venue does not like what mirror-a says, so it stops asking mirror-a.
    await h.venue.fault({ hideRegistries: [a!.registryId] });
    const p2 = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-264-0648", commodity: "Lumber, bundled", weightLbs: 39_400 });
    if (p2.task!.status !== "COMMITTED") throw new Error(`part 2: expected the venue to commit on two mirrors, got ${p2.task!.status} ${p2.task!.outcome?.reasonCode}`);
    const art2 = artifactOf(p2.task!.commitmentId!);
    const vAny = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys });
    const vNamed = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys, requiredRegistries: [a!.registryId] });
    const today = await Promise.all(h.registries.map((r) => r.attest("1984411")));
    const vToday = verifyArtifact(art2, { pinnedRootKey: root, registryKeys: keys, currentAttestations: today });
    say(`part 2: venue hides ${a!.registryId}, asks only ${b!.registryId} and ${c!.registryId} (both lagging, both say insured), quorum 2 met → COMMITS ${art2.commitmentId.slice(0, 16)}… with guarantee ${art2.underwriting.decision === "GUARANTEED" ? "ATTACHED" : "none"}; artifact carries ${art2.registry?.attestations.carrier.map((x) => x.registryId).join(", ")}`);
    say(`   verifier pinning all three, any two → ${vAny.ok ? "VERIFIED (!)" : vAny.reasonCode}: ${vAny.checks.find((x) => x.name === "carrier.registry.quorum")?.detail}`);
    say(`   verifier who names ${a!.registryId} → ${vNamed.reasonCode ?? "VERIFIED"}: ${vNamed.checks.find((x) => x.name === "carrier.registry.quorum")?.detail?.slice(0, 120)}`);
    say(`   verifier with all three mirrors' word TODAY → ${vToday.reasonCode ?? "VERIFIED"}: ${vToday.checks.find((x) => x.name === "carrier.registry.standing-per-current-record")?.detail?.slice(0, 160)}`);
    if (!vAny.ok || vNamed.reasonCode !== "REGISTRY_QUORUM_NOT_MET" || vToday.reasonCode !== "REGISTRY_CONTRADICTS_COMMITMENT" || art2.underwriting.decision !== "GUARANTEED") throw new Error("part 2: dropped mirror not caught");
    await h.venue.fault(null);
    findings.push(
      { label: "part 2: the venue's choice of registries is not the verifier's", reasonCode: "REGISTRY_QUORUM_NOT_MET", by: "ledger/verify", detail: `the artifact shows two genuine, fresh, unanimous attestations — and no ${a!.registryId}. "Any two" is satisfied by whichever two the venue liked; "${a!.registryId} must vouch" cannot be, because that signature exists only if the venue asked and embedded it. Same shape as named witnesses` },
      { label: "part 2: today's word settles it", reasonCode: "REGISTRY_CONTRADICTS_COMMITMENT", by: "ledger/verify", detail: `${a!.registryId}'s record today shows the filing cancelled before the commitment; the other two still say otherwise — a split the verifier reports and does not average` },
    );

    // ---- Part 3: below quorum. Two mirrors dark; one answer is not enough to judge anyone.
    await b!.fault({ freeze: false, unavailable: true });
    await c!.fault({ freeze: false, unavailable: true });
    await new Promise((r) => setTimeout(r, policyMs + 200));
    const p3 = await negotiate(h, broker, carrier2, { ...LOAD, loadRef: "L-2026-264-0671", commodity: "Canned goods, palletized", weightLbs: 42_800 });
    const r3 = await resultFromTask(h, p3.task!);
    const e3 = (r3.evidence ?? {}) as LapseEvidence;
    say(`part 3: ${b!.registryId} and ${c!.registryId} unreachable → ${r3.outcome} ${r3.reasonCode} (${r3.refusedBy}): ${e3.error}; per registry: ${Object.entries(e3.registries ?? {}).map(([k, v]) => `${k}=${v.split(" (")[0]}`).join(", ")}`);
    if (r3.reasonCode !== "REGISTRY_UNAVAILABLE") throw new Error("part 3: venue did not fail closed below quorum");
    await b!.fault({ unavailable: false });
    await c!.fault({ unavailable: false });
    findings.push(
      { label: "part 3: below quorum", reasonCode: "REGISTRY_UNAVAILABLE", by: "venue.identity", detail: "one mirror answered and it happens to be right; the venue still refuses, because 'right' is what a quorum is for. Liveness is the price, and the quorum is the operator's number to tune against how independent the mirrors really are" },
      { label: "what this leaves", detail: "the mirrors' independence is asserted by configuration, not proven: k colluding mirrors defeat any-k the way k colluding witnesses do, and the answer is the same — the verifier names the ones it trusts. Beneath every mirror sits the one upstream, FMCSA, which does not sign; and beneath that the insurer's legal duty to file" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "REGISTRY_QUORUM_NOT_MET",
      refusedBy: "ledger/verify",
      evidence: { commitmentId: art2.commitmentId, registriesInArtifact: art2.registry!.attestations.carrier.map((x) => x.registryId), required: [a!.registryId], failedChecks: failing(vNamed), withTodaysWord: failing(vToday).filter((x) => x.includes("per-current-record")) },
      guaranteeWouldHavePaid: "Attached on two mirrors' say-so after the venue stopped asking the third. The artifact cannot show a signature the venue chose not to collect — which is exactly what a verifier who named that registry sees. The claim is against the venue; the mirrors' word today is the evidence.",
      taskId: p2.task!.task.id,
      commitmentId: art2.commitmentId,
      findings,
      auditRefs: [...pickAudit(audit, "venue", (e) => e.taskId === p1.task!.task.id && e.outcome === "REFUSED"), ...pickAudit(audit, "venue", (e) => e.taskId === p1b.task!.task.id && e.outcome === "REFUSED"), ...pickAudit(audit, "venue", (e) => e.event === "fault-armed" && !!(e.evidence as { hideRegistries?: unknown }).hideRegistries), ...pickAudit(audit, "venue", (e) => e.event === "registry-refresh" && e.outcome === "REFUSED").slice(-1)],
    };
  },
};
