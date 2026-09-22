/**
 * Broker agent process. Own config, own data dir, own key, own mandate,
 * own private context. Knows the venue URL and nothing about any carrier
 * beyond public registry identifiers.
 */
import { AgentRuntime, loadConfig } from "../../agentkit/runtime";
import { llmClientFromEnv, llmStrategy } from "../../agentkit/llm-strategy";
import { brokerStrategy, maxPay, type BrokerPrivateContext } from "./strategy";

const config = loadConfig();
if (config.role !== "broker") throw new Error("broker process started with non-broker config");
// AGENT_LLM_URL set: a model negotiates price inside the rules' shape and the principal's economics; unset: the rules alone.
const llm = llmClientFromEnv();
const strategy = llm
  ? llmStrategy<BrokerPrivateContext>(llm, {
      role: "broker",
      fallback: brokerStrategy,
      ctxToPrompt: (c) => [`customerRateUsd=${c.customerRateUsd} (what the shipper pays you)`, `targetMarginPct=${c.targetMarginPct} minMarginPct=${c.minMarginPct}`, `paymentTermsDays=${c.paymentTermsDays}`],
      acceptable: (offer, view, c, m) => (offer.rateUsd > maxPay(c, m, view.load.miles) ? `rate ${offer.rateUsd} above the most this broker will pay (${maxPay(c, m, view.load.miles)})` : undefined),
      onFallback: (f) => console.log(`[${config.agentId}] llm fallback at ${f.stage}: ${f.reason}`),
    })
  : brokerStrategy;
const rt = new AgentRuntime<BrokerPrivateContext>(config, strategy);
rt.listen().then(async () => {
  await rt.pinVenue();
  if (!config.rogue?.skipOnboarding && !rt.credential) {
    const r = await rt.onboard();
    console.log(`[${config.agentId}] onboard: ${r.ok ? `credential ${r.credential.credentialId}` : `REFUSED ${r.reasonCode}`}`);
  }
});
