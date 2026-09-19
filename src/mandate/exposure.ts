/**
 * Exposure book: outstanding committed dollars by counterparty and by day.
 * Used by the agent-local engine (its own commitments) and by the venue
 * (per registered envelope). File-backed so a restart does not forget.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface ExposureSnapshot {
  byCounterparty: Record<string, { outstandingUsd: number; count: number }>;
  byDay: Record<string, number>;
}

export class ExposureBook {
  private state: ExposureSnapshot = { byCounterparty: {}, byDay: {} };
  constructor(private readonly path?: string) {
    if (path && existsSync(path)) this.state = JSON.parse(readFileSync(path, "utf8"));
  }
  private persist() {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.state, null, 2));
  }
  outstanding(counterparty: string): number {
    return this.state.byCounterparty[counterparty]?.outstandingUsd ?? 0;
  }
  daily(day: string): number {
    return this.state.byDay[day] ?? 0;
  }
  add(counterparty: string, amountUsd: number, day: string) {
    const c = (this.state.byCounterparty[counterparty] ??= { outstandingUsd: 0, count: 0 });
    c.outstandingUsd += amountUsd;
    c.count += 1;
    this.state.byDay[day] = (this.state.byDay[day] ?? 0) + amountUsd;
    this.persist();
  }
  release(counterparty: string, amountUsd: number, day: string) {
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
