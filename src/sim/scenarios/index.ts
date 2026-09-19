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

export const SCENARIOS: Scenario[] = [happyPath, insuranceLapsed, spoofedCarrier, doubleBrokering, brokerOverCeiling, exposureMidNegotiation, nonConvergence, revokedPrePickup, replayAndTamper];
export const ADVERSARIAL = SCENARIOS.filter((s) => s.id !== "happy-path");
