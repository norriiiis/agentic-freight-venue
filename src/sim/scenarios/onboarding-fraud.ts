import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario, Finding } from "../scenario";
import { brokerSpec, carrierSpec, CARRIER_HISTORY, LOAD } from "../fixtures";
import { generateKeyPair } from "../../protocol/crypto";
import { signControlAttestation } from "../../protocol/control";
import { pickAudit } from "../scenario";

/** The contact point the public record carries for Prairie Wind — the mailbox a challenge goes to. */
const PRAIRIE_CONTACT = "dispatch@prairiewindtransport.example";

export const onboardingFraud: Scenario = {
  id: "onboarding-fraud",
  title: "A fraudster binds its own key to somebody else's operating authority — the one failure nothing downstream repairs",
  summary:
    "Every other check in this system asks whether an entity is in good standing. This one asks whether it is the entity at all, and if it is wrong the credential is a forgery the venue signed itself: the registries vouch for it, the mandate engine enforces its limits, the artifact verifies, and a broker pays an impostor. So the proof is bound to the key being registered, is good exactly once, and is either run by the venue or signed by a verifier the venue pins. Part 1: the fraudster asks for a challenge against Prairie Wind's number — and the code goes to Prairie Wind, not to them. Part 2: they present the real carrier's own satisfied challenge, and it is refused because it is about a different key. Part 3: they sign their own attestation, and it is refused because nobody pinned them. Part 4: the real carrier answers the code the venue sent it, onboards, and the credential records which proof it rests on.",
  expect: { outcome: "REFUSED", reasonCode: "CONTROL_PROOF_NOT_BOUND_TO_KEY", refusedBy: "venue.identity" },
  async run({ h, say }) {
    // A venue configured as a deployed one is: no readable stub token, and one pinned verifier that is NOT the fraudster.
    const honestVerifier = generateKeyPair();
    h.opts.venue = {
      controlMethods: ["REGISTRY_CONTACT_CHALLENGE", "OPERATOR_ATTESTED"],
      controlVerifiers: [{ verifierId: "northstar-vetting", publicKey: honestVerifier.publicJwk, methods: ["OPERATOR_ATTESTED"] }],
    };
    await h.startVenue();
    await h.venue.seedHistory("2751903", CARRIER_HISTORY);
    const findings: Finding[] = [];

    // ---- Part 1: the fraudster asks the venue to challenge an entity it does not control.
    const thief = generateKeyPair();
    const c1 = await h.venue.controlChallenge({ usdot: "2751903", publicKey: thief.publicJwk });
    const sentTo = c1.result?.sentTo;
    const code = h.venue.challengeCodeFor(PRAIRIE_CONTACT);
    say(`part 1: a stranger asks to register key ${thief.kid.slice(0, 12)}… against USDOT 2751903 (PRAIRIE WIND TRANSPORT). The venue sends a code to ${sentTo} — the contact point on the public record — and tells the asker only that much. The code itself (${code ? `${code.slice(0, 2)}****` : "—"}) went to the carrier's mailbox; the asker never sees it.`);
    if (!c1.result || !code) throw new Error("part 1: no challenge was sent");
    const guess = await h.venue.controlVerify({ challengeId: c1.result.challengeId, code: "000000" });
    say(`   guessing: ${guess.error?.message} — ${JSON.stringify((guess.error?.data as { evidence?: { attemptsLeft?: number } })?.evidence?.attemptsLeft)} tries left of 5, and the challenge dies after that`);
    findings.push({ label: "part 1: the code goes to the record, not to the asker", detail: `the venue reads the contact point off the registry's signed record and sends there itself. Whoever asked learns the address only masked (${sentTo}) and never the code. The old stub served that token to any caller that could reach the registry, which proved reachability and nothing else` });

    // ---- Part 2: the fraudster waits for the real carrier to answer, then presents that challenge for its own key.
    await h.venue.controlVerify({ challengeId: c1.result.challengeId, code });  // the carrier answers its own mail
    const real = await h.startAgent(carrierSpec({ thinkMs: 60, proofMethod: "REGISTRY_CONTACT_CHALLENGE" }));
    void real;
    const stolen = await h.venue.controlChallenge({ usdot: "2751903", publicKey: generateKeyPair().publicJwk });
    const theirCode = h.venue.challengeCodeFor(PRAIRIE_CONTACT)!;
    await h.venue.controlVerify({ challengeId: stolen.result!.challengeId, code: theirCode });
    const replay = await h.venue.onboardRaw({ usdot: "2751903", publicKey: thief.publicJwk, agentId: "thief-agent", kp: thief, proof: { method: "REGISTRY_CONTACT_CHALLENGE", challengeId: stolen.result!.challengeId } });
    const e2 = (replay.error?.data as { evidence?: Record<string, unknown> })?.evidence ?? {};
    say(`part 2: the stranger takes a challenge that WAS answered — the code really did reach the carrier — and presents it for its own key → ${(replay.error?.data as { reasonCode?: string })?.reasonCode}`);
    say(`   bound to ${String(e2.boundTo).slice(0, 12)}…, presented ${String(e2.presented).slice(0, 12)}… — "${String(e2.why)}"`);
    if ((replay.error?.data as { reasonCode?: string })?.reasonCode !== "CONTROL_PROOF_NOT_BOUND_TO_KEY") throw new Error("part 2: a proof about another key was accepted");
    findings.push({ label: "part 2: a proof is about one key", reasonCode: "CONTROL_PROOF_NOT_BOUND_TO_KEY", by: "venue.identity", detail: "the challenge named the key it was issued for, so intercepting an answered one buys nothing without that key. This is the property the old token lacked entirely: it was bound to nothing, so anyone holding it could bind anything" });

    // ---- Part 3: the fraudster signs its own attestation.
    const forged = signControlAttestation(thief, "northstar-vetting", {
      usdot: "2751903", subjectKid: thief.kid, method: "OPERATOR_ATTESTED",
      evidence: { note: "verified by me, honestly", operator: "definitely a real person" },
      verifiedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), jti: "cta_forged",
    });
    const r3 = await h.venue.onboardRaw({ usdot: "2751903", publicKey: thief.publicJwk, agentId: "thief-agent-2", kp: thief, proof: { method: "OPERATOR_ATTESTED", attestation: forged } });
    const code3 = (r3.error?.data as { reasonCode?: string })?.reasonCode;
    say(`part 3: the stranger signs its own attestation under the pinned verifier's NAME → ${code3}: ${String(((r3.error?.data as { evidence?: Record<string, unknown> })?.evidence ?? {}).why)}`);
    if (code3 !== "CONTROL_VERIFIER_UNTRUSTED") throw new Error("part 3: a self-signed attestation was accepted");
    findings.push({ label: "part 3: a name is not a key", reasonCode: "CONTROL_VERIFIER_UNTRUSTED", by: "venue.identity", detail: "the venue pins a KEY for each verifier it listens to, so claiming a verifier's name signs nothing. A venue that pinned nobody accepts no attestations at all, which is the safe default" });

    // ---- Part 4: the real carrier, doing it properly, and what the credential then records.
    const broker = await h.startAgent(brokerSpec({ thinkMs: 60, proofMethod: "REGISTRY_CONTACT_CHALLENGE" }));
    const cred = JSON.parse(readFileSync(join(broker.dir, "credential.json"), "utf8")) as { evidence: { proofOfControl: string; proofOfControlDetail?: { method: string; verifierId?: string; boundToKid: string } } };
    say(`part 4: the broker onboards by answering the code the venue sent to its own contact point. Its credential records how: ${cred.evidence.proofOfControl}, bound to ${cred.evidence.proofOfControlDetail?.boundToKid.slice(0, 12)}…`);
    if (cred.evidence.proofOfControl !== "REGISTRY_CONTACT_CHALLENGE") throw new Error(`part 4: the credential records ${cred.evidence.proofOfControl}`);
    findings.push(
      { label: "part 4: the credential says what it rests on", detail: "a counterparty reading this credential can tell a challenge to the public record from an operator's say-so, and refuse the weaker one. A proof of control that is not written down is a claim nobody can weigh later" },
      { label: "what this still does not fix", detail: "the contact point on FMCSA's record is often a filing agent's address and is sometimes years stale, so a challenge to it proves control of THAT MAILBOX — much better than nothing, worse than identity. That is why a pinned vetting provider's assertion is the second method, and why the next thing to buy is a provider that will sign one" },
    );

    const audit = await h.venue.audit();
    return {
      outcome: "REFUSED",
      reasonCode: "CONTROL_PROOF_NOT_BOUND_TO_KEY",
      refusedBy: "venue.identity",
      evidence: { usdot: "2751903", thiefKid: thief.kid, ...e2 },
      guaranteeWouldHavePaid: "Not applicable — nothing was committed. Had the binding succeeded, impersonation is the covered peril, and the venue's own control failing is exactly the loss the guarantee exists for; which is why this gate is the one that cannot be allowed to fail.",
      findings,
      auditRefs: pickAudit(audit, "venue", (e) => e.event === "control-challenge" || e.event === "control-verify" || e.event === "onboard").slice(0, 4),
    };
  },
};
