import type { Scenario } from "../scenario";
import { standardSetup, negotiate, resultFromTask } from "./common";

export const happyPath: Scenario = {
  id: "happy-path",
  title: "Happy path: tender → counter → converge → both sign → venue records → guarantee attaches",
  summary: "Broker agent tenders a 780-mile dry van load. Carrier agent evaluates against its own mandate and economics, counters (rate + a later pickup window), the two converge, both sign the same terms, the venue records the commitment and attaches a guarantee.",
  expect: { outcome: "COMMITTED" },
  async run({ h }) {
    const { broker, carrier } = await standardSetup(h);
    const { task } = await negotiate(h, broker, carrier);
    return resultFromTask(h, task!);
  },
};
