/**
 * Exposure book: outstanding committed dollars by counterparty and by day.
 * Used by the agent-local engine (its own commitments) and by the venue
 * (per registered envelope). File-backed so a restart does not forget.
 */
import { existsSync, readFileSync } from "node:fs";
import { writeFileAtomic } from "../protocol/fsatomic";

export interface ExposureSnapshot {
  byCounterparty: Record<string, { outstandingUsd: number; count: number }>;
  byDay: Record<string, number>;
  /** Refs (commitment ids) whose add/release has been applied — makes re-application after a crash a no-op. */
  applied: string[];
}

export class ExposureBook {
  private state: ExposureSnapshot = { byCounterparty: {}, byDay: {}, applied: [] };
  constructor(private readonly path?: string) {
    if (path && existsSync(path)) this.state = { applied: [], ...JSON.parse(readFileSync(path, "utf8")) };
  }
  private persist() {
    if (!this.path) return;
    writeFileAtomic(this.path, JSON.stringify(this.state, null, 2));
  }
  /** True if an operation with this ref was already applied (and records it if not). */
  private once(ref: string | undefined): boolean {
    if (!ref) return true;
    if (this.state.applied.includes(ref)) return false;
    this.state.applied.push(ref);
    return true;
  }
  hasApplied(ref: string): boolean {
    return this.state.applied.includes(ref);
  }
  outstanding(counterparty: string): number {
    return this.state.byCounterparty[counterparty]?.outstandingUsd ?? 0;
  }
  daily(day: string): number {
    return this.state.byDay[day] ?? 0;
  }
  add(counterparty: string, amountUsd: number, day: string, ref?: string) {
    if (!this.once(ref && `add:${ref}`)) return;
    const c = (this.state.byCounterparty[counterparty] ??= { outstandingUsd: 0, count: 0 });
    c.outstandingUsd += amountUsd;
    c.count += 1;
    this.state.byDay[day] = (this.state.byDay[day] ?? 0) + amountUsd;
    this.persist();
  }
  release(counterparty: string, amountUsd: number, day: string, ref?: string) {
    if (!this.once(ref && `release:${ref}`)) return;
    const c = this.state.byCounterparty[counterparty];
    if (c) {
      c.outstandingUsd = Math.max(0, c.outstandingUsd - amountUsd);
      c.count = Math.max(0, c.count - 1);
    }
    this.state.byDay[day] = Math.max(0, (this.state.byDay[day] ?? 0) - amountUsd);
    this.persist();
  }
  snapshot(): ExposureSnapshot {
    return structuredClone(this.state);
  }
}
