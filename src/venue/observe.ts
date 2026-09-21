/**
 * Observability: metrics derived from the audit stream (so a counter and the
 * record it counts can never disagree), rendered in Prometheus text format;
 * and alerts — a webhook POST for the handful of events an operator must see
 * within minutes, never a verdict-changing action.
 */
import type { AuditEntry } from "../protocol/audit";

export class Metrics {
  private counters = new Map<string, number>();
  private gauges = new Map<string, () => number>();
  inc(name: string, labels: Record<string, string> = {}, by = 1) {
    const key = `${name}${Object.keys(labels).length ? `{${Object.entries(labels).map(([k, v]) => `${k}="${String(v).replace(/"/g, "'")}"`).join(",")}}` : ""}`;
    this.counters.set(key, (this.counters.get(key) ?? 0) + by);
  }
  gauge(name: string, read: () => number) {
    this.gauges.set(name, read);
  }
  /** Count every audit entry by component/event/outcome, and refusals by reason: the audit is the source of truth for the numbers. */
  observe(e: AuditEntry) {
    this.inc("venue_audit_events_total", { component: e.component, event: e.event, outcome: e.outcome });
    if (e.reasonCode && (e.outcome === "REFUSED" || e.outcome === "VOIDED")) this.inc("venue_refusals_total", { reasonCode: e.reasonCode, component: e.component });
    if (e.event === "commit" && e.outcome === "ALLOWED") this.inc("venue_commitments_total");
    if (e.event === "guarantee-attached") this.inc("venue_guarantees_attached_total");
    if (e.outcome === "VOIDED") this.inc("venue_commitments_voided_total", { reasonCode: e.reasonCode ?? "" });
  }
  render(): string {
    const lines: string[] = [];
    for (const [k, v] of [...this.counters].sort()) lines.push(`${k} ${v}`);
    for (const [k, read] of this.gauges) { try { lines.push(`${k} ${read()}`); } catch { /* a gauge that throws is omitted */ } }
    return lines.join("\n") + "\n";
  }
}

/** Events an operator must see now. Everything else is in the audit log and the metrics. */
export const ALERT_EVENTS = new Set(["registry-false-attestation", "insurer-false-attestation", "insurer-key-conflict", "deliver-abandoned", "crash", "ledger-rollback", "witness-fork", "equivocation-proof", "registry-refresh", "recovery"]);

export class Alerts {
  private queue: Promise<void> = Promise.resolve();
  sent = 0;
  failed = 0;
  constructor(private readonly webhook: string | undefined, private readonly venueId: string, private readonly log: (l: string) => void = () => {}) {}
  observe(e: AuditEntry) {
    if (!this.webhook || !ALERT_EVENTS.has(e.event) || e.outcome === "ALLOWED") return;
    const url = this.webhook;
    this.queue = this.queue.then(async () => {
      try {
        const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ venueId: this.venueId, alert: e.event, outcome: e.outcome, reasonCode: e.reasonCode, subject: e.subject, taskId: e.taskId, at: e.ts, seq: e.seq, evidence: e.evidence }) });
        if (res.ok) this.sent++; else { this.failed++; this.log(`[alerts] webhook ${res.status} for ${e.event}`); }
      } catch (err) {
        this.failed++;
        this.log(`[alerts] webhook failed for ${e.event}: ${String(err).slice(0, 80)}`);
      }
    });
  }
}
