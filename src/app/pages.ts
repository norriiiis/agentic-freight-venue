/** Page bodies. Each takes plain data and returns HTML; nothing here talks to a database or a network. */
import { STEPS, type Step } from "./onboarding";
import { chip, esc, money, shortId, tile, when, type Tone } from "./views";
import type { MandateLimits } from "../mandate/types";

const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${esc(csrf)}">`;

export function loginPage(csrf: string, email = ""): string {
  return `<h1 style="font-size:20px;font-weight:600;margin-bottom:6px">Sign in</h1>
<p class="hint" style="margin-bottom:22px">Accounts here are created by invitation. If you were sent one, use the link in it.</p>
<form method="post" action="/login">${csrfField(csrf)}
  <div class="field"><label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="username" value="${esc(email)}"></div>
  <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password"></div>
  <button class="btn" type="submit" style="width:100%">Sign in</button>
</form>`;
}

export function invitePage(csrf: string, invite: { code: string; email: string; orgName: string | null; orgRole: string | null }): string {
  return `<h1 style="font-size:20px;font-weight:600;margin-bottom:6px">Set up your account</h1>
<p class="hint" style="margin-bottom:22px">For <strong>${esc(invite.email)}</strong>${invite.orgName ? `, joining <strong>${esc(invite.orgName)}</strong> as a ${esc(invite.orgRole ?? "")}` : ""}.</p>
<form method="post" action="/invite/${esc(invite.code)}">${csrfField(csrf)}
  <div class="field"><label for="name">Your name</label><input id="name" name="name" type="text" required autocomplete="name"></div>
  <div class="field"><label for="password">Choose a password</label><input id="password" name="password" type="password" required minlength="12" autocomplete="new-password">
    <p class="hint">At least 12 characters. This signs you in; it does not sign anything on the venue.</p></div>
  <button class="btn" type="submit" style="width:100%">Create account</button>
</form>`;
}

// ---------------------------------------------------------------- onboarding

export interface OnboardingView {
  csrf: string;
  step: Step;
  orgName: string;
  orgRole: "broker" | "carrier";
  entity?: { usdot: string; mc: string | null; legalName: string; entityType: string; registryAsOf: string | null };
  snapshot?: Record<string, unknown>;
  proofs: { method: string; status: string; sentTo: string | null; verifiedAt: string | null; evidence: string | null }[];
  challengeOutstanding?: { sentTo: string | null };
  keyKid?: string;
  keyDisclosure: string;
  limits?: MandateLimits;
  mandate?: { mandateId: string; expiresAt: string; signedAt: string };
  agent?: { agentId: string; status: string; credentialId: string | null; lastError: string | null };
  canOperate: boolean;
  isStaff: boolean;
}

export function onboardingPage(v: OnboardingView): string {
  const order: Step[] = ["claim", "prove", "key", "mandate", "agent"];
  const at = order.indexOf(v.step);
  const body = STEPS.map((s, i) => {
    const state = i < at ? "step-done" : i === at ? "step-now" : "";
    return `<section class="step ${state}">
      <div class="step-n">${i < at ? "✓" : i + 1}</div>
      <div>
        <h3>${esc(s.title)}</h3>
        <p>${esc(s.blurb)}</p>
        ${i === at ? `<div class="step-body">${stepBody(v)}</div>` : i < at ? `<div class="step-body">${stepDone(v, s.id)}</div>` : ""}
      </div>
    </section>`;
  }).join("");
  return `<div class="card" style="max-width:860px">${body}</div>`;
}

function stepDone(v: OnboardingView, id: Step): string {
  if (id === "claim" && v.entity) return `<p class="small muted">${esc(v.entity.legalName)} · USDOT ${esc(v.entity.usdot)}${v.entity.mc ? ` · ${esc(v.entity.mc)}` : ""}</p>`;
  if (id === "prove") {
    const p = v.proofs.find((x) => x.status === "VERIFIED");
    return p ? `<p class="small muted">${p.method === "operator-attested" ? `Verified by hand: ${esc(p.evidence ?? "")}` : `Code confirmed from ${esc(p.sentTo ?? "the record's contact point")}`} · ${esc(when(p.verifiedAt))}</p>` : "";
  }
  if (id === "key" && v.keyKid) return `<p class="small muted mono">${esc(shortId(v.keyKid, 20))}</p>`;
  if (id === "mandate" && v.mandate) return `<p class="small muted mono">${esc(v.mandate.mandateId.slice(0, 20))}… · expires ${esc(v.mandate.expiresAt.slice(0, 10))}</p>`;
  return "";
}

function stepBody(v: OnboardingView): string {
  const f = csrfField(v.csrf);
  switch (v.step) {
    case "claim":
      return `<form method="post" action="/onboarding/claim">${f}
        <div class="row" style="max-width:520px">
          <div><label for="usdot">USDOT number</label><input id="usdot" name="usdot" type="text" inputmode="numeric" required value="${esc(v.entity?.usdot ?? "")}"></div>
          <div style="flex:0 0 auto"><button class="btn" type="submit">Look it up</button></div>
        </div>
        <p class="hint">We read this from the registry and show you its answer. Nothing is claimed until you confirm.</p>
      </form>
      ${v.snapshot ? entityCard(v.snapshot, v.csrf) : ""}`;

    case "prove": {
      const email = (v.snapshot?.email as string) ?? "";
      return `<div class="stack" style="gap:14px">
        ${v.challengeOutstanding
          ? `<form method="post" action="/onboarding/verify">${f}
               <p class="small">A code went to <strong>${esc(v.challengeOutstanding.sentTo ?? "")}</strong>.</p>
               <div class="row" style="max-width:420px;margin-top:8px">
                 <div><label for="code">Confirmation code</label><input id="code" name="code" type="text" required autocomplete="one-time-code"></div>
                 <div style="flex:0 0 auto"><button class="btn" type="submit">Confirm</button></div>
               </div>
             </form>`
          : email
            ? `<form method="post" action="/onboarding/challenge">${f}
                 <p class="small">The public record lists <strong class="mono">${esc(email)}</strong> for this entity. We will send a code there.</p>
                 <button class="btn" type="submit" style="margin-top:10px">Send the code</button>
               </form>`
            : `<p class="small muted">The public record carries no email address for this entity, so we cannot challenge it automatically. One of our people will verify you by hand.</p>`}
        ${v.isStaff ? `<form method="post" action="/onboarding/attest" class="card" style="background:#F6EDDD;border-color:#E8D9BC">${f}
            <h3 style="color:#7A4F14">Operator: verify by hand</h3>
            <p class="hint" style="color:#7A4F14">Your name goes on this. Say what you actually did.</p>
            <div class="field" style="margin-top:10px"><label for="evidence">What you did</label><textarea id="evidence" name="evidence" rows="3" required placeholder="Called (713) 555-0142, the number on the FMCSA record, and spoke to…"></textarea></div>
            <button class="btn" type="submit">Record this and pass the step</button>
          </form>` : ""}
      </div>`;
    }

    case "key":
      return `<form method="post" action="/onboarding/key">${f}
        <p class="small">${esc(v.keyDisclosure)}</p>
        <button class="btn" type="submit" style="margin-top:12px">Create the signing key</button>
      </form>`;

    case "mandate":
      return mandateForm(v.csrf, v.limits ?? ({} as MandateLimits), "/onboarding/mandate", "Sign these limits");

    case "agent":
      return v.agent?.status === "LIVE"
        ? `<p class="small">Your agent is live. <a href="/desk">Go to the desk</a>.</p>`
        : `<form method="post" action="/onboarding/agent">${f}
            ${v.agent?.lastError ? `<div class="flash flash-bad">${esc(v.agent.lastError)}</div>` : ""}
            <p class="small">This starts a process that holds your mandate, presents your credential, and negotiates inside your limits. It does not hold your signing key.</p>
            <button class="btn" type="submit" style="margin-top:12px">Start my agent</button>
          </form>`;
  }
}

function entityCard(snap: Record<string, unknown>, csrf: string): string {
  const auth = (snap.authorities as { type: string; status: string }[] | undefined) ?? [];
  const ins = (snap.insurance as { type: string; form: string; insurer: string; coverageToUsd: number; cancellationDate?: string }[] | undefined) ?? [];
  const addr = snap.physicalAddress as { city?: string; state?: string } | undefined;
  return `<div class="card" style="margin-top:16px;background:#FDFCF9">
    <h3>What the registry says</h3>
    <dl class="kv" style="margin-top:12px">
      <dt>Legal name</dt><dd>${esc(snap.legalName)}</dd>
      <dt>USDOT / MC</dt><dd class="mono">${esc(snap.usdot)}${snap.mc ? ` · ${esc(snap.mc)}` : ""}</dd>
      <dt>Based</dt><dd>${esc(addr?.city ?? "")}${addr?.state ? `, ${esc(addr.state)}` : ""}</dd>
      <dt>Operating status</dt><dd>${esc(snap.operatingStatus)}</dd>
      <dt>Authorities</dt><dd>${auth.map((a) => `${esc(a.type)} ${chip(a.status, a.status === "ACTIVE" ? "good" : "bad")}`).join(" ") || "—"}</dd>
      <dt>Insurance on file</dt><dd>${ins.length ? ins.map((i) => `${esc(i.form)} ${esc(i.insurer)} ${money(i.coverageToUsd)}${i.cancellationDate ? ` ${chip("CANCELS " + i.cancellationDate, "bad")}` : ""}`).join("<br>") : "none"}</dd>
      <dt>Safety rating</dt><dd>${esc(snap.safetyRating)}</dd>
      <dt>Fleet</dt><dd>${esc(snap.powerUnits)} power units · ${esc(snap.drivers)} drivers</dd>
    </dl>
    <form method="post" action="/onboarding/claim-confirm" style="margin-top:16px">${csrfField(csrf)}
      <input type="hidden" name="usdot" value="${esc(snap.usdot)}">
      <button class="btn" type="submit">Yes, this is us</button>
      <span class="hint" style="display:inline-block;margin-left:12px">If it is not, stop and tell us.</span>
    </form>
  </div>`;
}

// ------------------------------------------------------------------ mandate

export function mandateForm(csrf: string, l: MandateLimits, action: string, submitLabel: string, problems: string[] = []): string {
  const v = (x: unknown) => (x === undefined || x === null ? "" : String(x));
  return `<form method="post" action="${esc(action)}">${csrfField(csrf)}
    ${problems.length ? `<div class="flash flash-bad"><strong>This cannot be signed yet.</strong><ul style="margin:8px 0 0;padding-left:18px">${problems.map((p) => `<li>${esc(p)}</li>`).join("")}</ul></div>` : ""}
    <div class="row"><div class="field"><label for="minRatePerLoadUsd">Never pay or take less than</label><input id="minRatePerLoadUsd" name="minRatePerLoadUsd" type="number" min="0" step="1" value="${v(l.minRatePerLoadUsd)}"></div>
      <div class="field"><label for="maxRatePerLoadUsd">Never pay more than</label><input id="maxRatePerLoadUsd" name="maxRatePerLoadUsd" type="number" min="0" step="1" value="${v(l.maxRatePerLoadUsd)}"></div></div>
    <div class="row"><div class="field"><label for="minRatePerMileUsd">Floor per mile</label><input id="minRatePerMileUsd" name="minRatePerMileUsd" type="number" min="0" step="0.01" value="${v(l.minRatePerMileUsd)}"></div>
      <div class="field"><label for="maxRatePerMileUsd">Ceiling per mile</label><input id="maxRatePerMileUsd" name="maxRatePerMileUsd" type="number" min="0" step="0.01" value="${v(l.maxRatePerMileUsd)}"></div></div>
    <div class="field"><label for="allowedLaneRegions">Lanes — both ends must be in these states</label>
      <input id="allowedLaneRegions" name="allowedLaneRegions" type="text" value="${esc((l.allowedLaneRegions ?? []).join(" "))}" placeholder="TX OK KS MO">
      <p class="hint">Two-letter USPS codes, separated by spaces. Leave empty for anywhere.</p></div>
    <div class="row"><div class="field"><label for="allowedEquipment">Equipment</label>
      <input id="allowedEquipment" name="allowedEquipment" type="text" value="${esc((l.allowedEquipment ?? []).join(" "))}" placeholder="VAN REEFER">
      <p class="hint">VAN, REEFER, FLATBED, STEP_DECK, POWER_ONLY.</p></div>
      <div class="field"><label for="hazmatPermitted">Hazmat</label><select id="hazmatPermitted" name="hazmatPermitted"><option value="false"${l.hazmatPermitted ? "" : " selected"}>Not permitted</option><option value="true"${l.hazmatPermitted ? " selected" : ""}>Permitted</option></select></div></div>
    <div class="field"><label for="requiredCounterpartyInsuranceUsd">The other side must carry at least</label><input id="requiredCounterpartyInsuranceUsd" name="requiredCounterpartyInsuranceUsd" type="number" min="0" step="1000" value="${v(l.requiredCounterpartyInsuranceUsd)}">
      <p class="hint">A broker checks the carrier's BIPD; a carrier checks the broker's bond.</p></div>
    <div class="row"><div class="field"><label for="maxPerCounterpartyExposureUsd">Most open with any one counterparty</label><input id="maxPerCounterpartyExposureUsd" name="maxPerCounterpartyExposureUsd" type="number" min="0" step="500" value="${v(l.maxPerCounterpartyExposureUsd)}"></div>
      <div class="field"><label for="maxDailyExposureUsd">Most committed in a day</label><input id="maxDailyExposureUsd" name="maxDailyExposureUsd" type="number" min="0" step="500" value="${v(l.maxDailyExposureUsd)}"></div></div>
    <div class="row"><div class="field"><label for="maxNegotiationRounds">Rounds before walking away</label><input id="maxNegotiationRounds" name="maxNegotiationRounds" type="number" min="1" max="100" value="${v(l.maxNegotiationRounds)}"></div>
      <div class="field"><label for="paymentMin">Payment terms, min days</label><input id="paymentMin" name="paymentMin" type="number" min="0" max="365" value="${v(l.paymentTermsDays?.min)}"></div>
      <div class="field"><label for="paymentMax">max days</label><input id="paymentMax" name="paymentMax" type="number" min="0" max="365" value="${v(l.paymentTermsDays?.max)}"></div></div>
    <div class="field"><label for="requireInsurerAttestation">The other side's insurer must vouch for it</label>
      <select id="requireInsurerAttestation" name="requireInsurerAttestation">
        <option value="false"${l.requireInsurerAttestation ? "" : " selected"}>No — the registry's word is enough</option>
        <option value="true"${l.requireInsurerAttestation ? " selected" : ""}>Yes — require the insurer's own signed word</option>
      </select>
      <p class="hint">Few carriers can meet this today: it needs their insurer to issue a signed, machine-readable certificate. Turning it on will refuse most counterparties.</p></div>
    <input type="hidden" name="mayTender" value="${l.mayTender ? "true" : "false"}">
    <input type="hidden" name="requireGuarantee" value="false">
    <button class="btn" type="submit">${esc(submitLabel)}</button>
  </form>`;
}

// ------------------------------------------------------------------- tender

export function tenderPage(csrf: string, carriers: { agentId: string; label: string }[], today: string): string {
  if (!carriers.length) return `<div class="empty">No carriers are on this venue yet. A load needs somebody to tender it to.</div>`;
  return `<form method="post" action="/tender" class="card" style="max-width:880px">${csrfField(csrf)}
    <h2>Post a load</h2>
    <p class="lede">Your agent opens the negotiation and runs it inside your mandate. You will not be asked to approve each round.</p>
    <div class="row"><div class="field"><label for="loadRef">Your reference</label><input id="loadRef" name="loadRef" type="text" required value="L-${esc(today)}-0001"></div>
      <div class="field"><label for="to">Tender to</label><select id="to" name="to" required>${carriers.map((c) => `<option value="${esc(c.agentId)}">${esc(c.label)}</option>`).join("")}</select></div></div>
    <div class="row"><div class="field"><label for="oCity">Origin city</label><input id="oCity" name="oCity" required></div>
      <div class="field"><label for="oState">State</label><input id="oState" name="oState" required maxlength="2" style="text-transform:uppercase"></div>
      <div class="field"><label for="oZip">ZIP</label><input id="oZip" name="oZip" required></div></div>
    <div class="row"><div class="field"><label for="dCity">Destination city</label><input id="dCity" name="dCity" required></div>
      <div class="field"><label for="dState">State</label><input id="dState" name="dState" required maxlength="2" style="text-transform:uppercase"></div>
      <div class="field"><label for="dZip">ZIP</label><input id="dZip" name="dZip" required></div></div>
    <div class="row"><div class="field"><label for="pickupDate">Pickup</label><input id="pickupDate" name="pickupDate" type="date" required></div>
      <div class="field"><label for="deliveryDate">Delivery</label><input id="deliveryDate" name="deliveryDate" type="date" required></div>
      <div class="field"><label for="miles">Miles</label><input id="miles" name="miles" type="number" min="1" required></div></div>
    <div class="row"><div class="field"><label for="equipment">Equipment</label><select id="equipment" name="equipment"><option>VAN</option><option>REEFER</option><option>FLATBED</option><option>STEP_DECK</option><option>POWER_ONLY</option></select></div>
      <div class="field"><label for="weightLbs">Weight (lb)</label><input id="weightLbs" name="weightLbs" type="number" min="1" required></div>
      <div class="field"><label for="customerRateUsd">What your customer pays</label><input id="customerRateUsd" name="customerRateUsd" type="number" min="1" required>
        <p class="hint">Private. It never crosses the wire; it is what your agent prices against.</p></div></div>
    <div class="field"><label for="commodity">Commodity</label><input id="commodity" name="commodity" required></div>
    <button class="btn" type="submit">Tender it</button>
  </form>`;
}

// --------------------------------------------------------------------- desk

export interface DeskView {
  orgRole: "broker" | "carrier";
  agentLive: boolean;
  exposureToday: number;
  dailyCap: number;
  worst?: { name: string; amount: number; cap: number };
  openCount: number;
  committedCount: number;
  refusals: { seq: number; ts: string; reasonCode?: string; component: string; detail: string; taskId?: string }[];
  open: { taskId: string; loadRef: string; counterparty: string; round: number; theirs?: number; mine?: number; status: string }[];
  committed: { commitmentId: string; loadRef: string; counterparty: string; rate?: number; status: string }[];
  selfRefusals: { ts: string; reasonCode?: string; event: string; detail: string }[];
  registry: { registryId: string; ok: boolean; asOf?: string; upstreamAsOf?: string };
}

export function deskPage(v: DeskView): string {
  const pct = v.dailyCap > 0 ? v.exposureToday / v.dailyCap : 0;
  return `<div class="grid-4">
    ${tile({ label: "Committed today", value: money(v.exposureToday), sub: `of your ${money(v.dailyCap)} daily cap`, meter: pct, tone: pct > 0.8 ? "warn" : "neutral" })}
    ${v.worst ? tile({ label: "Most exposed counterparty", value: money(v.worst.amount), sub: `${v.worst.name}, of ${money(v.worst.cap)}`, meter: v.worst.cap ? v.worst.amount / v.worst.cap : 0, tone: v.worst.cap && v.worst.amount / v.worst.cap > 0.75 ? "warn" : "neutral" }) : tile({ label: "Most exposed counterparty", value: "—", sub: "nothing open" })}
    ${tile({ label: "In flight", value: String(v.openCount), sub: v.openCount ? "negotiating now" : "nothing on the table" })}
    ${tile({ label: "Commitments", value: String(v.committedCount), sub: "on the ledger" })}
  </div>
  <div class="cols">
    <div class="stack">
      ${v.refusals.length ? `<section>
        <h2 style="font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#3D382F;margin-bottom:10px">Needs you</h2>
        <div class="stack" style="gap:10px">${v.refusals.map((r) => `<article class="card">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            ${chip(r.reasonCode ?? "REFUSED", "bad")}
            <span class="mono" style="font-size:12px">${esc(r.component)}</span>
            <div class="spacer" style="flex-grow:1"></div>
            <span class="mono small muted">${esc(when(r.ts))}</span>
          </div>
          <p style="margin:9px 0 0;font-size:13px;line-height:1.5;color:#3D382F">${esc(r.detail)}</p>
          <div style="margin-top:10px"><a href="/refusals/${r.seq}" style="font-size:12px;font-weight:500">Read the refusal</a></div>
        </article>`).join("")}</div>
      </section>` : ""}

      <section>
        <h2 style="font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#3D382F;margin-bottom:10px">In flight</h2>
        ${v.open.length ? `<table><thead><tr><th>Load</th><th>Counterparty</th><th class="num">Round</th><th class="num">They ask</th><th class="num">You offer</th></tr></thead><tbody>
          ${v.open.map((o) => `<tr><td class="mono"><a href="/loads/${esc(o.taskId)}">${esc(o.loadRef)}</a></td><td>${esc(o.counterparty)}</td><td class="mono num">${o.round}</td><td class="mono num">${o.theirs ? money(o.theirs) : "—"}</td><td class="mono num">${o.mine ? money(o.mine) : "—"}</td></tr>`).join("")}
        </tbody></table>` : `<div class="empty">${v.agentLive ? "Nothing on the table right now." : "Your agent is not running yet."}</div>`}
      </section>

      <section>
        <h2 style="font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#3D382F;margin-bottom:10px">Commitments</h2>
        ${v.committed.length ? `<table><thead><tr><th>Load</th><th>Counterparty</th><th class="num">Rate</th><th>Status</th><th></th></tr></thead><tbody>
          ${v.committed.map((c) => `<tr><td class="mono">${esc(c.loadRef)}</td><td>${esc(c.counterparty)}</td><td class="mono num">${c.rate ? money(c.rate) : "—"}</td><td>${chip(c.status, c.status === "VOIDED" ? "bad" : c.status === "COMPLETED" ? "good" : "neutral")}</td><td class="num"><a href="/commitments/${esc(c.commitmentId)}" class="small">Record</a></td></tr>`).join("")}
        </tbody></table>` : `<div class="empty">No commitments yet.</div>`}
      </section>
    </div>

    <div class="stack">
      <section class="card">
        <h2>Held back by your own limits</h2>
        <p class="lede">Your agent refused itself before anything reached the wire.</p>
        ${v.selfRefusals.length ? v.selfRefusals.map((s) => `<div style="padding:11px 0;border-top:1px solid #EFEBE2">
          <div style="display:flex;gap:8px;align-items:baseline"><span class="mono small muted">${esc(when(s.ts))}</span><span class="mono small t-bad">${esc(s.reasonCode ?? s.event)}</span></div>
          <p style="margin:5px 0 0;font-size:12px;line-height:1.5;color:#3D382F">${esc(s.detail)}</p>
        </div>`).join("") : `<p class="small muted">Nothing yet.</p>`}
      </section>

      <section class="card">
        <h2>Registry</h2>
        <p class="lede">Standing is judged on signed words, re-read before every step.</p>
        <div style="display:flex;align-items:center;gap:9px">
          <span class="dot ${v.registry.ok ? "dot-good" : "dot-bad"}"></span>
          <span class="mono small" style="flex-grow:1">${esc(v.registry.registryId)}</span>
          <span class="mono small muted">${v.registry.upstreamAsOf ? esc(when(v.registry.upstreamAsOf)) : v.registry.ok ? "live" : "unreachable"}</span>
        </div>
      </section>
    </div>
  </div>`;
}

// ---------------------------------------------------------------- one load

export interface LoadView {
  loadRef: string; status: string; taskId: string;
  lane?: string; equipment?: string; miles?: number; weightLbs?: number; commodity?: string;
  pickup?: string; delivery?: string;
  wire: { round: number; from: string; to: string; type: string; rate?: number; noteCode?: string; ts: string; verified?: string }[];
  outcome?: { commitmentId?: string; termsHash?: string; ledgerSeq?: number; reasonCode?: string; refusedBy?: string; evidence?: Record<string, unknown> };
  guarantee?: { decision: string; reasonCode?: string };
}

export function loadPage(v: LoadView): string {
  return `<div class="card">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <span class="mono" style="font-size:15px;font-weight:600">${esc(v.loadRef)}</span>
      ${chip(v.status, v.status === "COMMITTED" ? "good" : v.status === "REFUSED" || v.status === "VOIDED" ? "bad" : "neutral")}
    </div>
    ${v.lane ? `<div style="margin-top:12px;font-size:14px;font-weight:500">${esc(v.lane)}</div>
    <div class="mono small muted" style="margin-top:4px">${v.miles ? `${v.miles} mi · ` : ""}${esc(v.equipment ?? "")}${v.weightLbs ? ` · ${v.weightLbs.toLocaleString()} lb` : ""}${v.commodity ? ` · ${esc(v.commodity)}` : ""}</div>` : ""}
    ${v.pickup || v.delivery ? `<div class="facts"><div class="fact"><div class="fact-k">Pickup</div><div class="fact-v">${esc(v.pickup ?? "—")}</div></div><div class="fact"><div class="fact-k">Delivery</div><div class="fact-v">${esc(v.delivery ?? "—")}</div></div></div>` : ""}
  </div>
  <div class="cols">
    <section class="card">
      <h2>The wire</h2>
      <p class="lede">${v.wire.length} message${v.wire.length === 1 ? "" : "s"}. Each one signed by the party that sent it, and checked by the venue before it was passed on.</p>
      ${v.wire.map((w) => `<div class="wire">
        <div class="mono small muted">${w.round}</div>
        <div>
          <div class="wire-head">
            <span style="font-size:12px;font-weight:600">${esc(w.from)}</span>
            <span class="small muted">&rarr; ${esc(w.to)}</span>
            ${chip(w.type, w.type === "ACCEPT" || w.type === "COMMITTED" ? "good" : w.type === "REFUSED" ? "bad" : "info")}
            ${w.noteCode ? `<span class="mono small muted">[${esc(w.noteCode)}]</span>` : ""}
            ${w.rate !== undefined ? `<span class="wire-rate">${money(w.rate)}</span>` : ""}
          </div>
          ${w.verified ? `<div class="wire-sub">${esc(w.verified)}</div>` : ""}
        </div>
      </div>`).join("") || `<div class="empty">No messages recorded.</div>`}
    </section>
    <div class="stack">
      ${v.outcome?.commitmentId ? `<section class="card">
        <h2>The record</h2>
        <dl class="kv" style="margin-top:12px">
          <dt>Commitment</dt><dd class="mono">${esc(shortId(v.outcome.commitmentId, 24))}</dd>
          <dt>Terms hash</dt><dd class="mono">${esc(shortId(v.outcome.termsHash, 20))}</dd>
          <dt>Ledger</dt><dd class="mono">seq ${esc(v.outcome.ledgerSeq ?? "—")}</dd>
        </dl>
        <div style="margin-top:14px;display:flex;gap:8px">
          <a class="btn btn-quiet btn-sm" href="/commitments/${esc(v.outcome.commitmentId)}/bundle">Download the record</a>
          <a class="btn btn-quiet btn-sm" href="/verify?commitment=${esc(v.outcome.commitmentId)}">Verify it</a>
        </div>
      </section>` : ""}
      ${v.outcome?.reasonCode ? `<section class="card">
        <h2>Why it stopped</h2>
        <div style="margin-top:10px">${chip(v.outcome.reasonCode, "bad")} <span class="mono small muted">${esc(v.outcome.refusedBy ?? "")}</span></div>
        ${v.outcome.evidence ? `<pre class="mono small" style="margin:12px 0 0;white-space:pre-wrap;word-break:break-word;color:#3D382F">${esc(JSON.stringify(v.outcome.evidence, null, 2))}</pre>` : ""}
      </section>` : ""}
      ${v.guarantee ? `<section class="card">
        <h2>Guarantee</h2>
        <p class="small" style="margin-top:8px;line-height:1.55">${v.guarantee.decision === "GUARANTEED" ? "A guarantee is attached to this commitment." : "This venue is not offering a guarantee. Identity, the mandate and the record stand on their own; there is nothing to claim against, and the record says so rather than implying cover that does not exist."}</p>
      </section>` : ""}
    </div>
  </div>`;
}

// ------------------------------------------------------------------ refusal

export function refusalPage(v: { seq: number; ts: string; reasonCode?: string; component: string; subject?: string; taskId?: string; headline: string; meaning: string; evidence: Record<string, unknown> }): string {
  return `<div class="card">
    <div class="mono" style="font-size:11px;font-weight:600;letter-spacing:.08em;color:#9E3B24">REFUSED</div>
    <h2 class="verdict">${esc(v.headline)}</h2>
    <div class="facts">
      <div class="fact"><div class="fact-k">Reason code</div><div class="fact-v t-bad">${esc(v.reasonCode ?? "—")}</div></div>
      <div class="fact"><div class="fact-k">Refused by</div><div class="fact-v">${esc(v.component)}</div></div>
      <div class="fact"><div class="fact-k">At</div><div class="fact-v">${esc(v.ts)}</div></div>
      <div class="fact"><div class="fact-k">Audit</div><div class="fact-v">#${v.seq}</div></div>
    </div>
  </div>
  <div class="cols">
    <section class="card">
      <h2>What this means</h2>
      <p style="margin:10px 0 0;font-size:13px;line-height:1.6;color:#3D382F">${esc(v.meaning)}</p>
    </section>
    <section class="card">
      <h2>The evidence it relied on</h2>
      <pre class="mono small" style="margin:12px 0 0;white-space:pre-wrap;word-break:break-word;color:#3D382F">${esc(JSON.stringify(v.evidence, null, 2))}</pre>
    </section>
  </div>`;
}

// -------------------------------------------------------------------- staff

export interface StaffView {
  csrf: string;
  orgs: { id: string; name: string; role: string; status: string; usdot?: string; agentStatus?: string; createdAt: string }[];
  invites: { code: string; email: string; orgName: string | null; expiresAt: string }[];
  venue: { ok: boolean; venueId?: string; commitments?: number; tasks?: number; outbox?: number; deadLetter?: number };
  registry: { registryId: string; ok: boolean };
  appUrl: string;
  audit: { ts: string; event: string; outcome: string; orgId: string | null; detail: string | null }[];
}

export function staffPage(v: StaffView): string {
  const tone = (s: string): Tone => (s === "LIVE" ? "good" : s === "SUSPENDED" ? "bad" : "warn");
  return `<div class="grid-4">
    ${tile({ label: "Venue", value: v.venue.ok ? "up" : "down", sub: v.venue.venueId ?? "", tone: v.venue.ok ? "good" : "bad" })}
    ${tile({ label: "Registry", value: v.registry.ok ? "up" : "down", sub: v.registry.registryId, tone: v.registry.ok ? "good" : "bad" })}
    ${tile({ label: "Commitments", value: String(v.venue.commitments ?? 0), sub: `${v.venue.tasks ?? 0} tasks` })}
    ${tile({ label: "Outbox", value: String(v.venue.outbox ?? 0), sub: `${v.venue.deadLetter ?? 0} dead-lettered`, tone: (v.venue.deadLetter ?? 0) > 0 ? "warn" : "neutral" })}
  </div>
  <div class="cols">
    <div class="stack">
      <section>
        <h2 style="font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#3D382F;margin-bottom:10px">Clients</h2>
        ${v.orgs.length ? `<table><thead><tr><th>Organisation</th><th>Role</th><th>USDOT</th><th>Onboarding</th><th>Agent</th></tr></thead><tbody>
        ${v.orgs.map((o) => `<tr><td><a href="/staff/org/${esc(o.id)}">${esc(o.name)}</a></td><td>${esc(o.role)}</td><td class="mono">${esc(o.usdot ?? "—")}</td><td>${chip(o.status, tone(o.status))}</td><td>${o.agentStatus ? chip(o.agentStatus, o.agentStatus === "LIVE" ? "good" : o.agentStatus === "FAILED" ? "bad" : "warn") : "—"}</td></tr>`).join("")}
        </tbody></table>` : `<div class="empty">No clients yet. Invite one.</div>`}
      </section>
      <section class="card">
        <h2>Recent activity</h2>
        <div style="margin-top:10px">${v.audit.map((a) => `<div style="padding:8px 0;border-top:1px solid #EFEBE2;display:flex;gap:10px;align-items:baseline">
          <span class="mono small muted" style="width:70px;flex-shrink:0">${esc(when(a.ts))}</span>
          <span class="mono small" style="flex-grow:1">${esc(a.event)}</span>
          ${chip(a.outcome, a.outcome === "ALLOWED" ? "good" : a.outcome === "REFUSED" || a.outcome === "FAILED" ? "bad" : "neutral")}
        </div>`).join("") || `<p class="small muted">Nothing yet.</p>`}</div>
      </section>
    </div>
    <div class="stack">
      <section class="card">
        <h2>Invite a client</h2>
        <form method="post" action="/staff/invite" style="margin-top:12px">${csrfField(v.csrf)}
          <div class="field"><label for="email">Their email</label><input id="email" name="email" type="email" required></div>
          <div class="field"><label for="orgName">Company name</label><input id="orgName" name="orgName" type="text" required></div>
          <div class="field"><label for="orgRole">They are a</label><select id="orgRole" name="orgRole"><option value="broker">Broker</option><option value="carrier">Carrier</option></select></div>
          <button class="btn" type="submit" style="width:100%">Create the invitation</button>
        </form>
        ${v.invites.length ? `<div style="margin-top:16px;border-top:1px solid #EFEBE2;padding-top:12px">
          <h3 style="margin-bottom:8px">Open invitations</h3>
          ${v.invites.map((i) => `<div style="padding:8px 0;border-top:1px solid #EFEBE2">
            <div class="small">${esc(i.email)}${i.orgName ? ` · ${esc(i.orgName)}` : ""}</div>
            <div class="mono small muted" style="margin-top:3px;word-break:break-all">${esc(v.appUrl)}/invite/${esc(i.code)}</div>
          </div>`).join("")}
        </div>` : ""}
      </section>
    </div>
  </div>`;
}
