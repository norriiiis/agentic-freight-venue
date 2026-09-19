import type { Scenario } from "../scenario";
import { standardSetup, negotiate, resultFromTask } from "./common";

export const nonConvergence: Scenario = {
  id: "non-convergence",
  title: "Negotiation fails to converge within the venue's bounded rounds",
  summary: "The broker's customer rate only supports ~$1,950; the carrier's cost floor is ~$2,340. Each concedes toward its own limit and then holds. The venue enforces a hard round bound (8) and terminates the task with a machine-readable reason.",
  expect: { outcome: "REFUSED", reasonCode: "NEGOTIATION_MAX_ROUNDS", refusedBy: "venue.protocol" },
  async run({ h }) {
    const { broker, carrier } = await standardSetup(h, { brokerPrivate: { customerRateUsd: 2100 }, carrierPrivate: { costPerMileUsd: 2.3 } });
    const { task } = await negotiate(h, broker, carrier);
    const res = await resultFromTask(h, task!);
    res.findings.push({ label: "private limits (never on the wire)", detail: "broker max pay ≈ $1,953 (2100 × (1 − 7%)); carrier floor ≈ $2,339 (2.30/mi × 890 mi + 160, +6%)" });
    return res;
  },
};
