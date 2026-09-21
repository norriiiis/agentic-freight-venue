import type { Scenario } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, negotiate, resultFromTask } from "./common";

export const insuranceLapsed: Scenario = {
  id: "insurance-lapsed",
  title: "Carrier credential valid, but BIPD insurance lapsed between onboarding and tender",
  summary: "The carrier onboarded with a live BMC-91X filing and holds an unexpired, unrevoked credential. Before the tender, the insurer files a cancellation — with the registry, as the law requires; nobody notifies the venue. The venue obtains the registry's fresh signed word at tender intake and catches it; the credential alone would not have.",
  expect: { outcome: "REFUSED", reasonCode: "INSURANCE_LAPSED", refusedBy: "venue.identity" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h);
    const rec = await h.registry.record("2751903");
    const insurance = rec.insurance.map((f) => (f.type === "BIPD" ? { ...f, cancellationDate: "2026-09-18" } : f));
    await h.registry.update("2751903", { insurance });
    say("registry: Great Plains Mutual files BMC-91X cancellation for PRAIRIE WIND TRANSPORT, effective 2026-09-18 (after onboarding, before tender). No notice reaches the venue.");
    const { task } = await negotiate(h, broker, carrier, LOAD);
    const res = await resultFromTask(h, task!);
    const cred = (await h.venue.agents()).find((a) => a.agentId === carrier.spec.agentId)!;
    const reg = (res.evidence as { registry?: { registryId: string; asOf: string } } | undefined)?.registry;
    res.findings.push({ label: "credential itself still valid", detail: `${cred.credentialId.slice(0, 18)}… issuer signature ok, unexpired (90-day validity), not revoked — only the registry's word caught the lapse` });
    res.findings.push({ label: "refusal rests on the registry's signature, not the venue's memory", detail: `attestation by ${reg?.registryId} as of ${reg?.asOf}; the venue never received a notice and its status list is clean` });
    return res;
  },
};
