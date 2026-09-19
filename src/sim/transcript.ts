/**
 * Renders what happened, from the venue's wire log and the components' audit
 * logs. Nothing here reads either agent's private context.
 */
import type { Message } from "../protocol/a2a";
import type { SignedMeta } from "../protocol/envelope";
import { REASONS, type ReasonCode } from "../protocol/reasons";
import type { Scenario, ScenarioResult } from "./scenario";

const usd = (n: number | undefined) => (n === undefined ? "" : `$${n.toLocaleString("en-US")}`);
const hhmm = (iso: string) => iso.slice(5, 16).replace("T", " ") + "Z";

export function renderWire(log: { ts: string; direction: "IN" | "OUT"; note?: string; message: Message }[], roles: Record<string, string>, taskId?: string): string[] {
  const out: string[] = [];
  let n = 0;
  for (const e of log) {
    const meta = e.message.metadata as SignedMeta;
    const att = meta.venue;
    const tid = att?.taskId ?? e.message.taskId;
    if (taskId && tid && tid !== taskId) continue;
    const d = e.message.parts[0]?.kind === "data" ? (e.message.parts[0].data as Record<string, unknown>) : {};
    const type = String(d.type);
    const offer = (d.offer ?? (d.terms ? { rateUsd: (d.terms as { rateUsd: number }).rateUsd, pickup: (d.terms as { pickup: { windowStart: string; windowEnd: string } }).pickup } : undefined)) as { rateUsd: number; pickup?: { windowStart: string; windowEnd: string } } | undefined;
    if (e.direction === "IN") {
      n++;
      const who = roles[meta.senderAgentId] ?? meta.senderAgentId;
      const detail = [offer ? usd(offer.rateUsd) : "", offer?.pickup ? `pickup ${hhmm(offer.pickup.windowStart)}–${offer.pickup.windowEnd.slice(11, 16)}` : "", d.note ? `"${d.note}"` : "", d.reason ? `"${d.reason}"` : "", d.termsHash ? `termsHash ${String(d.termsHash).slice(0, 12)}…` : ""].filter(Boolean).join("  ");
      out.push(`  ${String(n).padStart(2)}  ${who.padEnd(8)} → venue    ${type.padEnd(8)} ${detail}`);
    } else {
      const to = e.note?.replace("to ", "") ?? "";
      const toRole = roles[to] ?? to;
      if (type === "COMMITTED") {
        const g = d.guarantee as { guaranteeId: string; coveredAmountUsd: number; premiumUsd: number } | undefined;
        out.push(`      venue    → ${toRole.padEnd(8)} COMMITTED ${String(d.commitmentId).slice(0, 20)}…${g ? `  guarantee ${g.guaranteeId.slice(0, 13)}… covers ${usd(g.coveredAmountUsd)} premium ${usd(g.premiumUsd)}` : "  (unguaranteed)"}`);
      } else if (type === "REFUSED") {
        out.push(`      venue    → ${toRole.padEnd(8)} REFUSED  ${d.reasonCode} (by ${d.refusedBy})`);
      } else if (type === "VOIDED") {
        out.push(`      venue    → ${toRole.padEnd(8)} VOIDED   ${d.reasonCode}`);
      } else if (att) {
        const cp = att.counterparty;
        const ins = cp.entity.entityType === "BROKER" ? `bond ${usd(cp.insurance.bondUsd)}` : `BIPD ${usd(cp.insurance.bipdUsd)}`;
        out.push(`      venue    → ${toRole.padEnd(8)} fwd ${type.padEnd(7)} verified ${cp.credentialId.slice(0, 13)}… ${cp.entity.legalName} ${cp.entity.mc ?? cp.entity.usdot} · ${ins}${att.guaranteeAvailable !== undefined ? ` · guarantee ${att.guaranteeAvailable ? "quoted" : "DECLINED"}` : ""}`);
      }
    }
  }
  return out;
}

function fmtEvidence(ev: Record<string, unknown> | undefined, indent = "            "): string[] {
  if (!ev) return [];
  const lines: string[] = [];
  const skip = new Set(["details", "allViolations", "assessment", "registeredAgents", "authorities"]);
  for (const [k, v] of Object.entries(ev)) {
    if (skip.has(k) || v === undefined) continue;
    let s = typeof v === "string" ? v : JSON.stringify(v);
    if (s.length > 150) s = s.slice(0, 147) + "…";
    lines.push(`${indent}${k}: ${s}`);
  }
  return lines;
}

export function renderResult(sc: Scenario, res: ScenarioResult, pass: boolean): string[] {
  const out: string[] = [];
  const reason = res.reasonCode ? `${res.reasonCode} — ${REASONS[res.reasonCode as ReasonCode] ?? ""}` : "";
  out.push("");
  out.push(`  OUTCOME     ${res.outcome}${res.commitmentId ? `  ${res.commitmentId}` : ""}`);
  if (res.reasonCode) {
    out.push(`  refused     ${reason}`);
    out.push(`  by          ${res.refusedBy}`);
    out.push(`  evidence`);
    out.push(...fmtEvidence(res.evidence));
    if (res.guaranteeWouldHavePaid) out.push(`  guarantee   would it have paid? ${res.guaranteeWouldHavePaid}`);
  }
  if (res.findings.length) {
    out.push(`  also`);
    for (const f of res.findings) out.push(`    • ${f.label}${f.reasonCode ? `: ${f.reasonCode}` : ""}${f.by ? ` (${f.by})` : ""}${f.detail ? ` — ${f.detail}` : ""}`);
  }
  if (res.auditRefs.length) {
    out.push(`  audit`);
    for (const a of res.auditRefs.slice(0, 6)) out.push(`    ${a.source}/audit.jsonl #${a.entry.seq}  ${a.entry.component}  ${a.entry.event}  ${a.entry.outcome}${a.entry.reasonCode ? `  ${a.entry.reasonCode}` : ""}`);
  }
  const exp = sc.expect;
  out.push(`  expected    ${exp.outcome}${exp.reasonCode ? ` / ${exp.reasonCode}` : ""}${exp.refusedBy ? ` / ${exp.refusedBy}` : ""}   →   ${pass ? "PASS" : "FAIL"}`);
  return out;
}

export function checkExpectation(sc: Scenario, res: ScenarioResult): boolean {
  const e = sc.expect;
  if (res.outcome !== e.outcome) return false;
  if (e.reasonCode && res.reasonCode !== e.reasonCode) return false;
  if (e.refusedBy && res.refusedBy !== e.refusedBy) return false;
  return true;
}
