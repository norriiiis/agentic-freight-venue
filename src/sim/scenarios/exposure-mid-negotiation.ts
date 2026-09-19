import type { Scenario } from "../scenario";
import { PICKUP_DAY } from "../fixtures";
import { LOAD } from "../fixtures";
import { standardSetup, resultFromTask } from "./common";

export const exposureMidNegotiation: Scenario = {
  id: "exposure-mid-negotiation",
  title: "Counterparty accumulates exposure past the venue's per-counterparty limit mid-negotiation",
  summary: "The venue guarantees at most $40,000 outstanding against any one carrier. While this negotiation is in round 3, other brokers' guaranteed loads with the same carrier land and push its outstanding exposure to $38,500. When the carrier accepts, underwriting declines; the broker's mandate requires a guarantee, so the venue refuses the commitment.",
  expect: { outcome: "REFUSED", reasonCode: "VENUE_EXPOSURE_LIMIT_EXCEEDED", refusedBy: "underwriting" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h, { broker: { thinkMs: 250 }, carrier: { thinkMs: 250 } });
    const r = await broker.tender(LOAD, { agentId: carrier.spec.agentId });
    await h.venue.waitRound(r.taskId!, 3);
    const seeded = await h.venue.seedExposure("2751903", "1984411", 38_500, PICKUP_DAY, "other brokers' loads with PRAIRIE WIND, guaranteed today");
    say(`round 3 reached; other brokers' guaranteed loads land: outstanding vs PRAIRIE WIND now ${JSON.stringify(seeded.exposure)}`);
    const t = await h.venue.waitTerminal(r.taskId!);
    await Promise.all([broker.waitStatus(r.taskId!, ["REFUSED", "REJECTED", "COMMITTED"]), carrier.waitStatus(r.taskId!, ["REFUSED", "REJECTED", "COMMITTED"])]);
    const res = await resultFromTask(h, t);
    res.findings.push({ label: "why refused rather than committed unguaranteed", detail: "broker envelope requireGuarantee=true; carrier envelope requireGuarantee=false — the broker's principal chose to never take an unguaranteed carrier" });
    const bView = (await broker.tasks()).find((x) => x.taskId === r.taskId)?.outcome?.evidence ?? {};
    const cView = (await carrier.tasks()).find((x) => x.taskId === r.taskId)?.outcome?.evidence ?? {};
    res.findings.push({ label: "what each party was told", detail: `carrier (subject) sees ${Object.keys(cView).length} evidence fields incl. its other guaranteed loads; broker sees ${Object.keys(bView).length} fields: ${Object.keys(bView).join(", ")}` });
    return res;
  },
};
