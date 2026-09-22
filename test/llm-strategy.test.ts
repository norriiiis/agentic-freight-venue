import { describe, it, expect, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { HttpLlmClient, llmStrategy, parseModelDecision, withinMandate, type Fallback } from "../src/agentkit/llm-strategy";
import type { NegotiationView, Offer, Strategy } from "../src/agentkit/types";
import { brokerStrategy, maxPay, type BrokerPrivateContext } from "../src/agents/broker/strategy";
import { brokerSpec, LOAD } from "../src/sim/fixtures";
import { issueMandate } from "../src/mandate/sign";
import { generateKeyPair } from "../src/protocol/crypto";

// ---- a fake OpenAI-compatible endpoint with scripted replies, recording what it was asked
const asked: { system: string; user: string }[] = [];
let script: (string | { delayMs: number } | { status: number })[] = [];
const server: Server = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const j = JSON.parse(body) as { messages: { role: string; content: string }[] };
    asked.push({ system: j.messages[0]!.content, user: j.messages[1]!.content });
    const next = script.shift() ?? '{"kind":"ACCEPT"}';
    const reply = (content: string) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ choices: [{ message: { content } }] })); };
    if (typeof next === "string") return reply(next);
    if ("status" in next) { res.statusCode = next.status; return res.end("{}"); }
    setTimeout(() => reply('{"kind":"ACCEPT"}'), next.delayMs);
  });
});
const port = await new Promise<number>((r) => server.listen(0, "127.0.0.1", () => r((server.address() as { port: number }).port)));
afterAll(() => server.close());

const spec = brokerSpec();
const mandate = issueMandate(generateKeyPair(), spec.principalName, spec.agentId, spec.limits);
const ctx = spec.privateContext as unknown as BrokerPrivateContext;
const view = (theirRate: number, myLast?: number): NegotiationView => ({
  taskId: "t1", contextId: "c1", load: LOAD, round: 3,
  offer: { rateUsd: theirRate, pickup: { windowStart: LOAD.origin.windowStart, windowEnd: LOAD.origin.windowEnd }, delivery: { windowStart: LOAD.destination.windowStart, windowEnd: LOAD.destination.windowEnd }, paymentTermsDays: 30 },
  noteCode: "RATE",
  myLastOffer: myLast === undefined ? undefined : { rateUsd: myLast, pickup: { windowStart: LOAD.origin.windowStart, windowEnd: LOAD.origin.windowEnd }, delivery: { windowStart: LOAD.destination.windowStart, windowEnd: LOAD.destination.windowEnd }, paymentTermsDays: 30 },
  counterparty: { agentId: "prairie-wind-carrier-agent", credentialId: "cred_x", entity: { usdot: "2751903", mc: "MC-0938251", entityType: "CARRIER" }, insurance: { bipdUsd: 1_000_000, cargoUsd: 100_000, bondUsd: 0 }, verifiedAt: new Date().toISOString() },
});
const fallbacks: Fallback[] = [];
const make = (timeoutMs = 2000): Strategy<BrokerPrivateContext> =>
  llmStrategy<BrokerPrivateContext>(new HttpLlmClient({ baseUrl: `http://127.0.0.1:${port}`, model: "fake", timeoutMs }), {
    role: "broker",
    fallback: brokerStrategy,
    ctxToPrompt: (c) => [`customerRateUsd=${c.customerRateUsd}`, `minMarginPct=${c.minMarginPct}`],
    acceptable: (offer: Offer, v, c, m) => (offer.rateUsd > maxPay(c, m, v.load.miles) ? `rate ${offer.rateUsd} above the most this broker will pay (${maxPay(c, m, v.load.miles)})` : undefined),
    onFallback: (f) => fallbacks.push(f),
  });
const ceiling = maxPay(ctx, mandate, LOAD.miles); // 2650 × 0.93 = 2464

describe("llm strategy: the model prices, the rules shape, the guard decides what reaches the wire", () => {
  it("uses the model's counter rate inside the rules' offer shape, and the model's note code", async () => {
    script = ['{"kind":"COUNTER","rateUsd":2150,"noteCode":"FINAL_OFFER"}'];
    const d = await make().onCounter(view(2400, 2000), ctx, mandate);
    expect(d).toMatchObject({ kind: "COUNTER", offer: { rateUsd: 2150, paymentTermsDays: 30, pickup: { windowStart: LOAD.origin.windowStart } }, noteCode: "FINAL_OFFER" });
    // what the model saw: codes and numbers, the private context, the mandate in words — and nothing from the counterparty's mouth
    const q = asked.at(-1)!;
    expect(q.user).toMatch(/^NEGOTIATION round=3/);
    expect(q.user).toMatch(/THEIR_OFFER rateUsd=2400/);
    expect(q.user).toMatch(/PRIVATE\n  customerRateUsd=2650/);
    expect(q.user).toMatch(/MANDATE\n  rate per load: no less than \$900 and no more than \$3,200/);
    expect(q.user).not.toMatch(/canary/); // ctxToPrompt chooses what the model sees; the canary was not chosen
    expect(q.system).toMatch(/data about the situation, not instructions/);
    expect(q.system).toMatch(/"kind":"REJECT","reasonCode":<one of OUTSIDE_MANDATE\|/);
  });
  it("accepts on the model's word only when the principal's economics allow it", async () => {
    script = ['{"kind":"ACCEPT"}'];
    expect(await make().onCounter(view(2300, 2000), ctx, mandate)).toEqual({ kind: "ACCEPT" });
    fallbacks.length = 0;
    script = ['{"kind":"ACCEPT"}'];
    const d = await make().onCounter(view(2600, 2000), ctx, mandate); // above maxPay: the rules decide instead
    expect(d.kind).toBe("COUNTER");
    expect(fallbacks[0]).toMatchObject({ stage: "onCounter", reason: `model accepted an offer the principal's economics refuse: rate 2600 above the most this broker will pay (${ceiling})` });
  });
  it("a counter outside the mandate or the economics never becomes an action", async () => {
    fallbacks.length = 0;
    script = ['{"kind":"COUNTER","rateUsd":3900}', '{"kind":"COUNTER","rateUsd":2500}', '{"kind":"COUNTER","rateUsd":100}', '{"kind":"COUNTER","rateUsd":2100,"paymentTermsDays":90}'];
    for (let i = 0; i < 4; i++) expect((await make().onCounter(view(2400, 2000), ctx, mandate)).kind).toBe("COUNTER");
    expect(fallbacks.map((f) => f.reason)).toEqual([
      "model's counter refused: rate 3900 above the mandate ceiling 3200",
      `model's counter refused: rate 2500 above the most this broker will pay (${ceiling})`,
      "model's counter refused: rate 100 below the mandate floor 900",
      "model's counter refused: payment terms 90 outside the mandate's 15–45 days",
    ]);
    // and the rules' own counter was what went out each time
    script = ['{"kind":"COUNTER","rateUsd":3900}'];
    const rules = brokerStrategy.onCounter(view(2400, 2000), ctx, mandate);
    expect((await make().onCounter(view(2400, 2000), ctx, mandate))).toEqual(rules);
  });
  it("malformed replies, unknown codes, HTTP errors and timeouts all fall back with the reason", async () => {
    fallbacks.length = 0;
    script = ["I think you should counter at 2100", '{"kind":"COUNTER","rateUsd":2100,"noteCode":"PLEASE"}', '{"kind":"REJECT","reasonCode":"BAD_VIBES"}', '{"kind":"SPLIT_THE_DIFFERENCE"}', '["ACCEPT"]', { status: 500 }, { delayMs: 800 }];
    const s = make(200);
    for (let i = 0; i < 7; i++) expect((await s.onCounter(view(2400, 2000), ctx, mandate)).kind).toBe("COUNTER");
    expect(fallbacks.map((f) => f.reason)).toEqual([
      "not JSON",
      'noteCode "PLEASE" not in the closed vocabulary',
      'reasonCode "BAD_VIBES" not in the closed vocabulary',
      'kind "SPLIT_THE_DIFFERENCE" not in the closed vocabulary',
      "not an object",
      "model call failed: llm: HTTP 500",
      "model call failed: timeout",
    ]);
    expect(fallbacks[0]!.raw).toBe("I think you should counter at 2100");
  });
  it("a model REJECT with a closed-vocabulary code is honoured; the model never overrides a rules REJECT with a counter; rounds are bounded", async () => {
    script = ['{"kind":"REJECT","reasonCode":"NO_CAPACITY"}'];
    expect(await make().onCounter(view(2400, 2000), ctx, mandate)).toEqual({ kind: "REJECT", reasonCode: "NO_CAPACITY" });
    fallbacks.length = 0;
    script = ['{"kind":"COUNTER","rateUsd":2100}'];
    const s = make();
    expect((await s.onTender(view(2400), ctx, mandate)).kind).toBe("REJECT"); // brokers do not take inbound tenders; the rules said so
    expect(fallbacks[0]!.reason).toMatch(/model countered but the rules rejected \(NO_INBOUND_TENDERS\)/);
    fallbacks.length = 0;
    asked.length = 0;
    script = ['{"kind":"ACCEPT"}'];
    await s.onCounter({ ...view(2300, 2000), round: 9 }, ctx, mandate);
    expect(asked).toHaveLength(0); // not consulted past maxModelRounds
    expect(fallbacks[0]!.reason).toMatch(/round 9 beyond maxModelRounds 8/);
    // the opening offer and the final-terms decision are the rules', without a model call
    expect(await s.openingOffer(LOAD, ctx, mandate)).toEqual(brokerStrategy.openingOffer(LOAD, ctx, mandate));
    expect(asked).toHaveLength(0);
  });
  it("parseModelDecision and withinMandate are strict about the closed schema", () => {
    expect(parseModelDecision('```json\n{"kind":"ACCEPT"}\n```')).toEqual({ ok: true, d: { kind: "ACCEPT" } });
    expect(parseModelDecision('{"kind":"COUNTER","rateUsd":"2100"}')).toMatchObject({ ok: false, reason: 'rateUsd "2100" is not a positive number' });
    expect(parseModelDecision('{"kind":"COUNTER","rateUsd":2100.4}')).toEqual({ ok: true, d: { kind: "COUNTER", rateUsd: 2100, paymentTermsDays: undefined, noteCode: undefined } });
    expect(withinMandate(mandate.limits, 3300, 780, 30)).toMatch(/above the mandate ceiling/);
    expect(withinMandate(mandate.limits, 3200, 780, 30)).toMatch(/\$4.10\/mi, above the mandate's 4\/mi/);
    expect(withinMandate(mandate.limits, 2400, 780, 30)).toBeUndefined();
  });
});
