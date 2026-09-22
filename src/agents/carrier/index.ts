/**
 * Carrier agent process. Own config, own data dir, own key, own mandate,
 * own private context. Knows the venue URL and nothing about any broker
 * beyond what the venue attests on forwarded messages.
 */
import { AgentRuntime, loadConfig } from "../../agentkit/runtime";
import { llmClientFromEnv, llmStrategy } from "../../agentkit/llm-strategy";
import { carrierStrategy, economics, type CarrierPrivateContext } from "./strategy";

const config = loadConfig();
if (config.role !== "carrier") throw new Error("carrier process started with non-carrier config");
// AGENT_LLM_URL set: a model negotiates price inside the rules' shape and the principal's economics; unset: the rules alone.
const llm = llmClientFromEnv();
const strategy = llm
  ? llmStrategy<CarrierPrivateContext>(llm, {
      role: "carrier",
      fallback: carrierStrategy,
      ctxToPrompt: (c) => [`costPerMileUsd=${c.costPerMileUsd} deadheadMiles=${c.deadheadMiles} fixedCostPerLoadUsd=${c.fixedCostPerLoadUsd}`, `targetMarginPct=${c.targetMarginPct} minMarginPct=${c.minMarginPct}`, `earliestPickup=${c.earliestPickup ?? "-"} paymentTermsDays=${c.paymentTermsDays}`],
      acceptable: (offer, view, c, m) => (offer.rateUsd < economics(view.load, c, m).floor ? `rate ${offer.rateUsd} below this carrier's floor (${economics(view.load, c, m).floor})` : undefined),
      onFallback: (f) => console.log(`[${config.agentId}] llm fallback at ${f.stage}: ${f.reason}`),
    })
  : carrierStrategy;
const rt = new AgentRuntime<CarrierPrivateContext>(config, strategy);
rt.listen().then(async () => {
  await rt.pinVenue();
  if (!config.rogue?.skipOnboarding && !rt.credential) {
    const r = await rt.onboard();
    console.log(`[${config.agentId}] onboard: ${r.ok ? `credential ${r.credential.credentialId}` : `REFUSED ${r.reasonCode}`}`);
  }
});
