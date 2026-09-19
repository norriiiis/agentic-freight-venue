import type { Scenario } from "../scenario";
import { LOAD, carrierSpec } from "../fixtures";
import { standardSetup, resultFromTask } from "./common";
import { pickAudit } from "../scenario";
import { termsHash, type Terms } from "../../protocol/freight";

export const spoofedCarrier: Scenario = {
  id: "spoofed-carrier",
  title: "Spoofed carrier presents a real carrier's registry identifiers (and its real credential id)",
  summary: "An attacker runs a carrier agent claiming PRAIRIE WIND's USDOT/MC and even presents the genuine credential id, but signs with its own key. Three layers refuse it: onboarding (no proof of control), message presentation (key not bound to the credential), and the honest negotiation proceeds untouched.",
  expect: { outcome: "REFUSED", reasonCode: "IDENTITY_KEY_MISMATCH", refusedBy: "venue.identity" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { carrier: { thinkMs: 900 } });
    const realCred = (await h.venue.agents()).find((a) => a.agentId === carrier.spec.agentId)!.credentialId;

    // The spoofer: real identifiers, wrong proof-of-control token, own key, presents the real agentId + credential id.
    const spoofer = await h.startAgent(
      carrierSpec({
        agentId: "spoof-carrier-agent",
        proofOfControlToken: "guessed-token",
        principalName: "Fraud ring operator",
        registerEnvelope: false,
        rogue: { skipOnboarding: true, presentAgentId: carrier.spec.agentId, presentCredentialId: realCred },
      }),
    );
    say(`spoofer up, claiming ${spoofer.spec.entity.legalName} ${spoofer.spec.entity.mc} with credential ${realCred.slice(0, 18)}… but its own key`);

    // Layer 1: try to onboard with the real identifiers.
    const onboard = await spoofer.onboard();
    say(`spoofer onboarding attempt → ${onboard.ok ? "ACCEPTED (!)" : `REFUSED ${onboard.reasonCode}`}`);

    // Layer 2: race the honest carrier to ACCEPT the broker's tender.
    const r = await broker.tender(LOAD, { agentId: carrier.spec.agentId });
    const tender = (await h.venue.tasks()).find((t) => t.task.id === r.taskId)!;
    const terms: Terms = {
      loadRef: LOAD.loadRef, load: LOAD, rateUsd: tender.onTable!.offer.rateUsd, pickup: tender.onTable!.offer.pickup, delivery: tender.onTable!.offer.delivery, paymentTermsDays: tender.onTable!.offer.paymentTermsDays,
      brokerAgentId: broker.spec.agentId, carrierAgentId: carrier.spec.agentId,
      brokerEntity: { usdot: broker.spec.entity.usdot, mc: broker.spec.entity.mc }, carrierEntity: { usdot: carrier.spec.entity.usdot, mc: carrier.spec.entity.mc },
    };
    const spoofSend = await spoofer.send({ type: "ACCEPT", loadRef: LOAD.loadRef, round: 1, terms, termsHash: termsHash(terms), from: { agentId: carrier.spec.agentId, usdot: carrier.spec.entity.usdot, mc: carrier.spec.entity.mc } }, r.taskId, tender.task.contextId);
    say(`spoofer sends ACCEPT on the live task as ${carrier.spec.agentId} → ${spoofSend.refusal ? `REFUSED ${spoofSend.refusal.reasonCode}` : "ACCEPTED (!)"}`);

    // Layer 3: the honest negotiation is unaffected.
    const t = await h.venue.waitTerminal(r.taskId!);
    await Promise.all([broker.waitStatus(r.taskId!, ["COMMITTED", "REFUSED", "REJECTED"]), carrier.waitStatus(r.taskId!, ["COMMITTED", "REFUSED", "REJECTED"])]);
    const audit = await h.venue.audit();
    const spoofAudit = audit.filter((e) => e.outcome === "REFUSED" && (e.reasonCode === "IDENTITY_KEY_MISMATCH" || e.reasonCode === "ONBOARDING_PROOF_OF_CONTROL_FAILED"));
    const key = spoofAudit.find((e) => e.reasonCode === "IDENTITY_KEY_MISMATCH")!;
    const honest = await resultFromTask(h, t);
    return {
      outcome: "REFUSED",
      reasonCode: "IDENTITY_KEY_MISMATCH",
      refusedBy: "venue.identity",
      evidence: key.evidence,
      guaranteeWouldHavePaid: (spoofSend.refusal as { guaranteeWouldHavePaid?: string } | undefined)?.guaranteeWouldHavePaid,
      taskId: r.taskId,
      findings: [
        { label: "onboarding with real identifiers", reasonCode: onboard.reasonCode, by: "venue.identity", detail: "proof of control against the FMCSA-registered contact failed (stub); a live credential already binds this entity to another key anyway" },
        { label: "honest negotiation outcome", reasonCode: honest.outcome, by: "venue.commitment", detail: honest.commitmentId ? `commitment ${honest.commitmentId} between the real parties` : honest.reasonCode },
      ],
      auditRefs: pickAudit(audit, "venue", (e) => spoofAudit.includes(e)),
    };
  },
};
