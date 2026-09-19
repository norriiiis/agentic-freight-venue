/**
 * A Mandate is the human-set policy an agent operates under. It is signed by
 * the PRINCIPAL's key — a key the agent does not hold — so the agent can
 * neither loosen it nor forge a new one. The engine in ./engine.ts is what
 * makes the mandate bite: it can and does refuse its own principal's agent.
 */
import type { OkpJwk } from "../protocol/crypto";
import type { Equipment } from "../protocol/freight";

export interface MandateLimits {
  /** Absolute per-load bounds (USD, all-in linehaul). */
  minRatePerLoadUsd?: number;
  maxRatePerLoadUsd?: number;
  /** Per-mile bounds — how dispatchers actually think. */
  minRatePerMileUsd?: number;
  maxRatePerMileUsd?: number;
  /** USPS state codes; a lane is approved iff both origin and destination states are listed. Empty/undefined = any. */
  allowedLaneRegions?: string[];
  allowedEquipment: Equipment[];
  hazmatPermitted: boolean;
  /** For brokers: the BIPD the counterparty carrier must carry. For carriers: the bond the broker must carry. */
  requiredCounterpartyInsuranceUsd: number;
  maxPerCounterpartyExposureUsd: number;
  maxDailyExposureUsd: number;
  /** If true, the agent may only commit when a venue guarantee attaches. */
  requireGuarantee: boolean;
  /** May this agent tender loads to others (i.e. act as a broker)? Carriers: false. */
  mayTender: boolean;
  /** Bound on negotiation rounds this agent will participate in. */
  maxNegotiationRounds: number;
  /** Payment terms the agent may agree to. */
  paymentTermsDays: { min: number; max: number };
}

export interface Mandate {
  schema: "freight-venue/mandate/v1";
  mandateId: string;
  agentId: string;
  principal: { name: string; kid: string; publicKey: OkpJwk };
  issuedAt: string;
  expiresAt: string;
  limits: MandateLimits;
  /** Detached JWS by the principal over the mandate sans this field. */
  principalSignature: string;
}

export type MandateAction =
  | {
      kind: "OFFER";
      /** True when this offer opens a negotiation (a TENDER) rather than countering one. */
      isTender?: boolean;
      rateUsd: number;
      miles: number;
      originState: string;
      destinationState: string;
      equipment: Equipment;
      hazmat: boolean;
      paymentTermsDays: number;
      round: number;
    }
  | {
      kind: "ACCEPT";
      rateUsd: number;
      miles: number;
      originState: string;
      destinationState: string;
      equipment: Equipment;
      hazmat: boolean;
      paymentTermsDays: number;
      round: number;
      counterpartyUsdot: string;
      counterpartyInsuranceUsd: number;
      guaranteeAvailable: boolean;
      day: string; // YYYY-MM-DD for the daily exposure bucket
    };
