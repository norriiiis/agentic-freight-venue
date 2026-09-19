/**
 * Acceptance: every scenario in sim/ produces the expected outcome, reason
 * code and refusing component. Each scenario spawns its own venue + agents.
 * Skip with FV_SKIP_SCENARIOS=1 for a fast unit-only run.
 */
import { describe, it, expect } from "vitest";
import { resolve, join } from "node:path";
import { Harness } from "../src/sim/harness";
import { SCENARIOS } from "../src/sim/scenarios/index";
import { checkExpectation } from "../src/sim/transcript";

const skip = process.env.FV_SKIP_SCENARIOS === "1";

describe.skipIf(skip)("simulator scenarios", () => {
  for (const sc of SCENARIOS) {
    it(`${sc.id}: ${sc.expect.outcome}${sc.expect.reasonCode ? ` / ${sc.expect.reasonCode}` : ""}${sc.expect.refusedBy ? ` / ${sc.expect.refusedBy}` : ""}`, async () => {
      const h = new Harness({ workspace: join(resolve(import.meta.dirname, "../.sim/test"), sc.id), quiet: true });
      try {
        const res = await sc.run({ h, say: () => {} });
        expect({ outcome: res.outcome, reasonCode: res.reasonCode, refusedBy: res.refusedBy }).toMatchObject(sc.expect);
        expect(checkExpectation(sc, res)).toBe(true);
        if (res.outcome !== "COMMITTED") {
          // every refusal names its component, carries evidence, states the guarantee position, and has an audit entry
          expect(res.refusedBy).toBeTruthy();
          expect(res.evidence && Object.keys(res.evidence).length).toBeGreaterThan(0);
          expect(res.guaranteeWouldHavePaid).toBeTruthy();
          expect(res.auditRefs.length).toBeGreaterThan(0);
        }
      } finally {
        await h.stop();
      }
    }, 90_000);
  }
});
