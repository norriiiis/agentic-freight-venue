import type { Scenario } from "../scenario";
import { happyPath } from "./happy-path";
import { insuranceLapsed } from "./insurance-lapsed";
import { spoofedCarrier } from "./spoofed-carrier";
import { doubleBrokering } from "./double-brokering";
import { brokerOverCeiling } from "./broker-over-ceiling";
import { exposureMidNegotiation } from "./exposure-mid-negotiation";
import { nonConvergence } from "./non-convergence";
import { revokedPrePickup } from "./revoked-pre-pickup";
import { replayAndTamper } from "./replay-and-tamper";
import { multiTender } from "./multi-tender";
import { negotiationTimeout } from "./negotiation-timeout";

export const SCENARIOS: Scenario[] = [happyPath, insuranceLapsed, spoofedCarrier, doubleBrokering, brokerOverCeiling, exposureMidNegotiation, nonConvergence, revokedPrePickup, replayAndTamper, multiTender, negotiationTimeout];
export const ADVERSARIAL = SCENARIOS.filter((s) => s.id !== "happy-path");
