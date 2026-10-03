/**
 * Getting a client from "we are a broker with USDOT 3312874" to "our agent is
 * on the venue and may commit", in steps that each leave a record.
 *
 *   1  CLAIM     the entity: the registry's signed word says who that USDOT is
 *   2  PROVE     control of it — the gate that keeps a fraudster from binding
 *                a key to someone else's authority
 *   3  KEY       a principal key in custody, which the agent will never hold
 *   4  MANDATE   limits the principal signs with that key, plus the coarser
 *                envelope the venue is given
 *   5  AGENT     a process with that mandate on disk, onboarded to the venue,
 *                holding a credential bound to the entity
 *
 * On proof of control, plainly: the gate that matters in this pilot is step 2,
 * performed by this service — a challenge to the contact point on the public
 * record, or an operator who did the check by hand and said what they did. The
 * venue runs its own check too, against the registry's out-of-band channel,
 * and that one is a stub: anything that can reach the registry can read the
 * token. Two weak checks are not one strong one, and the stronger of the two
 * is the human one. This is the single most important thing to replace before
 * the pilot stops being closed.
 */
import { randomBytes } from "node:crypto";
import { validateLimits } from "../mandate/validate";
import { issueEnvelopeWith, issueMandateWith } from "../mandate/sign";
import type { Mandate, MandateLimits } from "../mandate/types";
import type { MandateEnvelope } from "../protocol/types";
import { newId } from "./auth";
import type { AppDb, OrgRole, OrgStatus } from "./db";
import type { PrincipalKeyStore } from "./keys";
import type { Mailer } from "./mail";
import type { RegistryClient } from "./venue";
import { Supervisor, freePort } from "./supervisor";

/**
 * Starting limits. Deliberately conservative, and with `requireGuarantee`
 * false because this venue is not offering one: a mandate that requires a
 * guarantee would refuse every load it was given.
 */
export const STARTING_LIMITS: Record<OrgRole, MandateLimits> = {
  broker: {
    maxRatePerLoadUsd: 3000, minRatePerLoadUsd: 500, maxRatePerMileUsd: 4.5,
    allowedLaneRegions: ["TX", "OK", "KS", "MO", "AR", "LA"], allowedEquipment: ["VAN", "REEFER"], hazmatPermitted: false,
    requiredCounterpartyInsuranceUsd: 1_000_000, requireInsurerAttestation: false,
    maxPerCounterpartyExposureUsd: 10_000, maxDailyExposureUsd: 25_000,
    requireGuarantee: false, mayTender: true, maxNegotiationRounds: 10, paymentTermsDays: { min: 15, max: 45 },
  },
  carrier: {
    minRatePerLoadUsd: 500, minRatePerMileUsd: 1.6,
    allowedLaneRegions: ["TX", "OK", "KS", "MO", "AR", "LA", "NE", "IA", "CO"], allowedEquipment: ["VAN"], hazmatPermitted: false,
    requiredCounterpartyInsuranceUsd: 75_000,
    maxPerCounterpartyExposureUsd: 15_000, maxDailyExposureUsd: 25_000,
    requireGuarantee: false, mayTender: false, maxNegotiationRounds: 10, paymentTermsDays: { min: 0, max: 45 },
  },
};

export const STARTING_CONTEXT: Record<OrgRole, Record<string, unknown>> = {
  broker: { canary: "", customerRateUsd: 0, targetMarginPct: 0.15, minMarginPct: 0.08, openingDiscountPct: 0.1, concessionPct: 0.35, acceptGapPct: 0.03, pickupFlexHours: 12, paymentTermsDays: 30 },
  carrier: { canary: "", costPerMileUsd: 1.85, deadheadMiles: 80, fixedCostPerLoadUsd: 150, minMarginPct: 0.08, targetMarginPct: 0.2, openingMarkupPct: 0.12, concessionPct: 0.3, acceptGapPct: 0.03, paymentTermsDays: 30 },
};

export type Step = "claim" | "prove" | "key" | "mandate" | "agent";
export const STEPS: { id: Step; title: string; blurb: string }[] = [
  { id: "claim", title: "Claim your entity", blurb: "We look your USDOT up in the registry and show you what it says. If that is not you, stop here." },
  { id: "prove", title: "Prove you control it", blurb: "A code to the contact point on the public record, or a check one of our people does by hand and signs their name to." },
  { id: "key", title: "Create your signing key", blurb: "The key that signs your limits. Your agent never holds it." },
  { id: "mandate", title: "Set and sign your limits", blurb: "What your agent may do. Read it as a sentence before you sign it." },
  { id: "agent", title: "Start your agent", blurb: "Your agent goes to the venue, proves who it is, and gets a credential bound to your USDOT." },
];

export function stepOf(status: OrgStatus): Step {
  switch (status) {
    case "NEW": return "claim";
    case "ENTITY_CLAIMED": return "prove";
    case "CONTROL_PROVEN": return "key";
    case "MANDATE_SIGNED": return "agent";
    default: return "agent";
  }
}

export interface OnboardingDeps {
  db: AppDb;
  keys: PrincipalKeyStore;
  mail: Mailer;
  registry: RegistryClient;
  supervisor: Supervisor;
  appUrl: string;
}

export class Onboarding {
  constructor(private readonly d: OnboardingDeps) {}

  // ---------------------------------------------------------------- 1. claim
  /** What the registry says about a USDOT, before anyone commits to anything. */
  async lookup(usdot: string) {
    const a = await this.d.registry.attest(usdot.trim());
    return { found: !!a.record, record: a.record, registryId: a.registryId, asOf: a.asOf, upstreamAsOf: a.upstreamAsOf };
  }

  async claimEntity(orgId: string, usdot: string, actorUserId: string): Promise<{ ok: true } | { ok: false; error: string }> {
    const org = this.d.db.org(orgId);
    if (!org) return { ok: false, error: "unknown organisation" };
    const taken = this.d.db.entityByUsdot(usdot);
    if (taken && taken.orgId !== orgId) return { ok: false, error: `USDOT ${usdot} is already claimed on this venue. If that is your number, tell us and we will sort it out by hand.` };
    const look = await this.lookup(usdot);
    if (!look.found || !look.record) return { ok: false, error: `The registry has no record for USDOT ${usdot}.` };
    const r = look.record;
    const wantsBroker = org.role === "broker";
    const hasBroker = r.authorities.some((a) => a.type === "BROKER" && a.status === "ACTIVE");
    const hasCarrier = r.authorities.some((a) => a.type !== "BROKER" && a.status === "ACTIVE");
    if (wantsBroker && !hasBroker) return { ok: false, error: `${r.legalName} has no active brokerage authority on the public record, so it cannot tender loads here.` };
    if (!wantsBroker && !hasCarrier) return { ok: false, error: `${r.legalName} has no active operating authority on the public record.` };
    this.d.db.tx(() => {
      this.d.db.run("INSERT INTO entities (org_id, usdot, mc, legal_name, entity_type, registry_as_of, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(org_id) DO UPDATE SET usdot = excluded.usdot, mc = excluded.mc, legal_name = excluded.legal_name, entity_type = excluded.entity_type, registry_as_of = excluded.registry_as_of, snapshot = excluded.snapshot",
        orgId, r.usdot, r.mc ?? null, r.legalName, r.entityType, look.asOf, JSON.stringify(r));
      this.d.db.run("UPDATE orgs SET status = ? WHERE id = ? AND status = 'NEW'", "ENTITY_CLAIMED", orgId);
    });
    this.d.db.audit({ actorUserId, orgId, event: "onboarding.claim", outcome: "ALLOWED", detail: { usdot: r.usdot, legalName: r.legalName, registryId: look.registryId, asOf: look.asOf } });
    return { ok: true };
  }

  // ---------------------------------------------------------------- 2. prove
  /** Send a one-time code to the contact point the public record carries. */
  async startEmailChallenge(orgId: string, actorUserId: string): Promise<{ ok: true; sentTo: string; detail?: string } | { ok: false; error: string }> {
    const e = this.d.db.entity(orgId);
    if (!e || !e.snapshot) return { ok: false, error: "claim your entity first" };
    const snap = JSON.parse(e.snapshot) as { email?: string; phone?: string };
    const to = (snap.email ?? "").trim();
    if (!to) return { ok: false, error: "The public record carries no email address for this entity, so we cannot challenge it. Ask us to verify you by hand instead." };
    const code = randomBytes(4).toString("hex").toUpperCase();
    const id = newId("proof");
    this.d.db.run("INSERT INTO proofs (id, org_id, method, status, challenge, sent_to, created_at) VALUES (?, ?, ?, 'PENDING', ?, ?, ?)",
      id, orgId, "registry-contact-challenge", code, to, new Date().toISOString());
    const sent = await this.d.mail.send({
      to,
      subject: `Confirm control of USDOT ${e.usdot}`,
      text: `Someone is setting up an automated freight agent for ${e.legalName} (USDOT ${e.usdot}).\n\nIf that is you, your confirmation code is:\n\n    ${code}\n\nEnter it at ${this.d.appUrl}/onboarding.\n\nIf it is not you, ignore this message and tell us at once — somebody is trying to transact as your company.\n`,
    });
    this.d.db.audit({ actorUserId, orgId, event: "onboarding.challenge-sent", outcome: sent.ok ? "ALLOWED" : "FAILED", detail: { to, proofId: id, transport: this.d.mail.kind, detail: sent.detail } });
    return { ok: true, sentTo: to, detail: sent.detail };
  }

  verifyChallenge(orgId: string, code: string, actorUserId: string): { ok: true } | { ok: false; error: string } {
    const p = this.d.db.one<{ id: string; challenge: string }>("SELECT id, challenge FROM proofs WHERE org_id = ? AND status = 'PENDING' AND method = 'registry-contact-challenge' ORDER BY created_at DESC", orgId);
    if (!p) return { ok: false, error: "no challenge is outstanding" };
    if ((p.challenge ?? "").toUpperCase() !== code.trim().toUpperCase()) {
      this.d.db.audit({ actorUserId, orgId, event: "onboarding.challenge-verify", outcome: "REFUSED", detail: { proofId: p.id } });
      return { ok: false, error: "That code does not match." };
    }
    this.d.db.tx(() => {
      this.d.db.run("UPDATE proofs SET status = 'VERIFIED', verified_at = ? WHERE id = ?", new Date().toISOString(), p.id);
      this.d.db.run("UPDATE orgs SET status = ? WHERE id = ? AND status = 'ENTITY_CLAIMED'", "CONTROL_PROVEN", orgId);
    });
    this.d.db.audit({ actorUserId, orgId, event: "onboarding.challenge-verify", outcome: "ALLOWED", detail: { proofId: p.id } });
    return { ok: true };
  }

  /** An operator did the check themselves. Their name and what they did go on the record, because that is the evidence. */
  operatorAttest(orgId: string, operatorUserId: string, evidence: string): { ok: true } | { ok: false; error: string } {
    if (evidence.trim().length < 20) return { ok: false, error: "Say what you actually did to verify this — a phone number you called, a document you saw. Twenty characters is not evidence." };
    const id = newId("proof");
    this.d.db.tx(() => {
      this.d.db.run("INSERT INTO proofs (id, org_id, method, status, created_at, verified_at, operator_user_id, evidence) VALUES (?, ?, ?, 'VERIFIED', ?, ?, ?, ?)",
        id, orgId, "operator-attested", new Date().toISOString(), new Date().toISOString(), operatorUserId, evidence.trim());
      this.d.db.run("UPDATE orgs SET status = ? WHERE id = ? AND status IN ('ENTITY_CLAIMED','NEW')", "CONTROL_PROVEN", orgId);
    });
    this.d.db.audit({ actorUserId: operatorUserId, orgId, event: "onboarding.operator-attested", outcome: "ALLOWED", detail: { proofId: id, evidence: evidence.trim() } });
    return { ok: true };
  }

  // ------------------------------------------------------------------ 3. key
  async createKey(orgId: string, actorUserId: string): Promise<{ ok: true; kid: string } | { ok: false; error: string }> {
    if (this.d.db.principalKey(orgId)) return { ok: false, error: "this organisation already has a signing key" };
    const org = this.d.db.org(orgId);
    if (!org || (org.status !== "CONTROL_PROVEN" && org.status !== "MANDATE_SIGNED")) return { ok: false, error: "prove control first" };
    const { kid } = await this.d.keys.create(orgId);
    this.d.db.audit({ actorUserId, orgId, event: "onboarding.key-created", outcome: "ALLOWED", detail: { kid, store: this.d.keys.kind } });
    return { ok: true, kid };
  }

  // -------------------------------------------------------------- 4. mandate
  async signMandate(orgId: string, limits: MandateLimits, actorUserId: string, validityDays = 30): Promise<{ ok: true; mandate: Mandate; envelope: MandateEnvelope } | { ok: false; errors: string[] }> {
    const org = this.d.db.org(orgId);
    const entity = this.d.db.entity(orgId);
    if (!org || !entity) return { ok: false, errors: ["claim your entity first"] };
    const problems = validateLimits(limits);
    if (limits.requireGuarantee) problems.push("This venue is not offering a guarantee, so a mandate that requires one would refuse every load. Turn it off.");
    if (problems.length) return { ok: false, errors: problems };
    const signer = await this.d.keys.signer(orgId);
    const agentId = agentIdFor(entity.legalName, entity.usdot);
    const mandate = await issueMandateWith(signer, org.name, agentId, limits, validityDays);
    const envelope = await issueEnvelopeWith(signer, mandate);
    this.d.db.tx(() => {
      this.d.db.run("UPDATE mandates SET superseded_at = ? WHERE org_id = ? AND superseded_at IS NULL", new Date().toISOString(), orgId);
      this.d.db.run("INSERT INTO mandates (id, org_id, agent_id, mandate_id, limits, signed_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        newId("mnd"), orgId, agentId, mandate.mandateId, JSON.stringify(limits), mandate.issuedAt, mandate.expiresAt);
      this.d.db.run("UPDATE orgs SET status = ? WHERE id = ? AND status = 'CONTROL_PROVEN'", "MANDATE_SIGNED", orgId);
    });
    this.d.db.audit({ actorUserId, orgId, event: "onboarding.mandate-signed", outcome: "ALLOWED", detail: { mandateId: mandate.mandateId, kid: signer.kid, expiresAt: mandate.expiresAt, limits } });
    return { ok: true, mandate, envelope };
  }

  // ---------------------------------------------------------------- 5. agent
  async provisionAndStart(orgId: string, actorUserId: string, privateContext?: Record<string, unknown>): Promise<{ ok: true; agentId: string; credentialId?: string } | { ok: false; error: string }> {
    const org = this.d.db.org(orgId);
    const entity = this.d.db.entity(orgId);
    const mandateRow = this.d.db.currentMandate(orgId);
    if (!org || !entity || !mandateRow) return { ok: false, error: "sign a mandate first" };
    const signer = await this.d.keys.signer(orgId).catch(() => undefined);
    if (!signer) return { ok: false, error: "no signing key in custody for this organisation" };

    // Re-issue from the stored limits so the files on disk and the database never drift apart.
    const limits = JSON.parse(mandateRow.limits) as MandateLimits;
    const mandate = await issueMandateWith(signer, org.name, mandateRow.agentId, limits, Math.max(1, Math.ceil((new Date(mandateRow.expiresAt).getTime() - Date.now()) / 86_400_000)));
    const envelope = await issueEnvelopeWith(signer, mandate);

    const existing = this.d.db.agentsOf(orgId)[0];
    const port = existing?.port ?? (await freePort());
    const controlToken = existing?.controlToken ?? randomBytes(24).toString("base64url");
    const ctx = { ...(STARTING_CONTEXT[org.role]), ...(existing ? JSON.parse(existing.privateContext) as Record<string, unknown> : {}), ...(privateContext ?? {}), canary: randomBytes(8).toString("hex") };

    // The venue runs its own proof-of-control check against the registry's out-of-band channel. See the note
    // at the top of this file: that check is a stub, and the gate that matters was step 2, above.
    const oob = await this.d.registry.outOfBand(entity.usdot);

    const { dir } = this.d.supervisor.provision({
      agentId: mandateRow.agentId, role: org.role, port, controlToken,
      entity: { usdot: entity.usdot, mc: entity.mc ?? undefined, legalName: entity.legalName },
      principalName: org.name, principalPublicKey: signer.publicJwk,
      proofOfControl: { method: "stub:registry-out-of-band", token: oob?._proofOfControlToken ?? "" },
      mandate, envelope, privateContext: ctx,
    });

    const id = existing?.id ?? newId("agt");
    if (existing) {
      this.d.db.run("UPDATE agents SET private_context = ?, data_dir = ? WHERE id = ?", JSON.stringify(ctx), dir, id);
    } else {
      this.d.db.run("INSERT INTO agents (id, org_id, agent_id, role, port, data_dir, status, control_token, private_context) VALUES (?, ?, ?, ?, ?, ?, 'PROVISIONED', ?, ?)",
        id, orgId, mandateRow.agentId, org.role, port, dir, controlToken, JSON.stringify(ctx));
    }
    const row = this.d.db.one<import("./db").AgentRow>("SELECT * FROM agents WHERE id = ?", id)!;
    const started = await this.d.supervisor.start(row);
    if (!started.ok) return { ok: false, error: started.error ?? "the agent did not come up" };

    const onboarded = await this.d.supervisor.onboard(row);
    if (!onboarded.ok) {
      this.d.db.audit({ actorUserId, orgId, event: "onboarding.agent-onboard", outcome: "REFUSED", detail: onboarded });
      return { ok: false, error: `The venue refused the agent: ${onboarded.reasonCode ?? "unknown"}. ${JSON.stringify(onboarded.evidence ?? {})}` };
    }
    const credentialId = onboarded.credential?.credentialId;
    this.d.db.tx(() => {
      this.d.db.run("UPDATE agents SET credential_id = ?, status = 'LIVE' WHERE id = ?", credentialId ?? null, id);
      this.d.db.run("UPDATE mandates SET registered_at = ? WHERE id = ?", new Date().toISOString(), mandateRow.id);
      this.d.db.run("UPDATE orgs SET status = 'LIVE' WHERE id = ?", orgId);
    });
    this.d.db.audit({ actorUserId, orgId, event: "onboarding.agent-live", outcome: "ALLOWED", detail: { agentId: mandateRow.agentId, credentialId, port } });
    return { ok: true, agentId: mandateRow.agentId, credentialId };
  }
}

/** A stable, readable agent id from the entity itself — not a random string, because people read these in logs. */
export function agentIdFor(legalName: string, usdot: string): string {
  const slug = legalName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").split("-").slice(0, 3).join("-");
  return `${slug || "agent"}-${usdot}`;
}
