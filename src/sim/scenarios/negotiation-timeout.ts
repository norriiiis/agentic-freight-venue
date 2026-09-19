import type { Scenario } from "../scenario";
import { LOAD } from "../fixtures";
import { standardSetup, resultFromTask } from "./common";

export const negotiationTimeout: Scenario = {
  id: "negotiation-timeout",
  title: "Carrier agent hangs mid-negotiation; the venue's reply timeout cancels the task",
  summary: "The carrier agent acknowledges the tender and then never replies (a crashed or hung runtime). The venue's sweeper cancels the negotiation after the reply window, names the silent party, and notifies the broker so it can re-tender. A late COUNTER from the carrier is refused against the terminal task.",
  expect: { outcome: "CANCELED", reasonCode: "NEGOTIATION_TIMEOUT", refusedBy: "venue.protocol" },
  async run({ h, say }) {
    h.opts.venue = { replyTimeoutMs: 1500, sweepMs: 200 };
    const { broker, carrier } = await standardSetup(h, { carrier: { rogue: { dropInbound: true } } });
    const r = await broker.tender(LOAD, { agentId: carrier.spec.agentId });
    say(`tendered; carrier acknowledges and goes silent (fault injection: dropInbound). Venue reply window 1.5s, sweeper every 200ms — no admin trigger.`);
    const t = await h.venue.waitTerminal(r.taskId!, 10_000);
    await broker.waitStatus(r.taskId!, ["CANCELED", "REFUSED"]);
    say(`venue canceled after ${t.outcome?.evidence.waitedMs}ms waiting on ${t.outcome?.evidence.awaiting}`);

    // The carrier "wakes up" and counters late.
    await carrier.setRogue(undefined);
    const late = await carrier.send({ type: "COUNTER", loadRef: LOAD.loadRef, round: 2, offer: { rateUsd: 2380, pickup: { windowStart: LOAD.origin.windowStart, windowEnd: LOAD.origin.windowEnd }, delivery: { windowStart: LOAD.destination.windowStart, windowEnd: LOAD.destination.windowEnd }, paymentTermsDays: 30 }, from: { agentId: carrier.spec.agentId, usdot: carrier.spec.entity.usdot, mc: carrier.spec.entity.mc } }, r.taskId, t.task.contextId);
    say(`late COUNTER from the carrier → ${late.refusal?.reasonCode} (task state ${(late.refusal?.evidence as { state?: string })?.state})`);

    const res = await resultFromTask(h, t);
    const brokerView = (await broker.tasks()).find((x) => x.taskId === r.taskId);
    res.findings.push(
      { label: "broker notified", detail: `local status ${brokerView?.status}; told concerning=${brokerView?.outcome?.evidence.concerning}, waited ${brokerView?.outcome?.evidence.waitedMs}ms — free to re-tender` },
      { label: "late reply after cancel", reasonCode: late.refusal?.reasonCode, by: late.refusal?.refusedBy, detail: "terminal tasks accept nothing" },
    );
    return res;
  },
};
