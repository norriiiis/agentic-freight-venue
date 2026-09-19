/**
 * Carrier agent process. Own config, own data dir, own key, own mandate,
 * own private context. Knows the venue URL and nothing about any broker
 * beyond what the venue attests on forwarded messages.
 */
import { AgentRuntime, loadConfig } from "../../agentkit/runtime";
import { carrierStrategy, type CarrierPrivateContext } from "./strategy";

const config = loadConfig();
if (config.role !== "carrier") throw new Error("carrier process started with non-carrier config");
const rt = new AgentRuntime<CarrierPrivateContext>(config, carrierStrategy);
rt.listen().then(async () => {
  await rt.pinVenue();
  if (!config.rogue?.skipOnboarding && !rt.credential) {
    const r = await rt.onboard();
    console.log(`[${config.agentId}] onboard: ${r.ok ? `credential ${r.credential.credentialId}` : `REFUSED ${r.reasonCode}`}`);
  }
});
