import type { Harness } from "./harness";
import type { AuditEntry } from "../protocol/audit";

export interface Finding {
  label: string;
  reasonCode?: string;
  by?: string;
  detail?: string;
  evidence?: Record<string, unknown>;
}

export interface ScenarioResult {
  outcome: "COMMITTED" | "REFUSED" | "VOIDED";
  reasonCode?: string;
  refusedBy?: string;
  evidence?: Record<string, unknown>;
  guaranteeWouldHavePaid?: string;
  taskId?: string;
  commitmentId?: string;
  findings: Finding[];
  /** The audit entries that constitute the refusal record. */
  auditRefs: { source: string; entry: AuditEntry }[];
}

export interface ScenarioContext {
  h: Harness;
  say: (line: string) => void;
}

export interface Scenario {
  id: string;
  title: string;
  summary: string;
  expect: { outcome: ScenarioResult["outcome"]; reasonCode?: string; refusedBy?: string };
  run(ctx: ScenarioContext): Promise<ScenarioResult>;
}

export function pickAudit(entries: AuditEntry[], source: string, pred: (e: AuditEntry) => boolean) {
  return entries.filter(pred).map((entry) => ({ source, entry }));
}
