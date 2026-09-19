/**
 * Broker agent process. Own config, own data dir, own key, own mandate,
 * own private context. Knows the venue URL and nothing about any carrier
 * beyond public registry identifiers.
 */
import { AgentRuntime, loadConfig } from "../../agentkit/runtime";
import { brokerStrategy, type BrokerPrivateContext } from "./strategy";

const config = loadConfig();
if (config.role !== "broker") throw new Error("broker process started with non-broker config");
const rt = new AgentRuntime<BrokerPrivateContext>(config, brokerStrategy);
rt.listen().then(async () => {
  await rt.pinVenue();
  if (!config.rogue?.skipOnboarding && !rt.credential) {
    const r = await rt.onboard();
    console.log(`[${config.agentId}] onboard: ${r.ok ? `credential ${r.credential.credentialId}` : `REFUSED ${r.reasonCode}`}`);
  }
});
