/**
 * Vetting provider interface. Highway, Descartes MyCarrierPortal, Carrier
 * Assure and Carrier411 sell this today for human workflows; we treat their
 * output as an *input* and build above it.
 *
 * STUB: returns the flags recorded in the mock registry fixture.
 */
import type { RegistryView } from "../protocol/registry";
// The adapter imports only TYPES from this file, so this is not a runtime cycle.
import { CarrierOkVetting, type VettingPolicy } from "./vetting-carrierok";

export interface VettingAssessment {
  provider: string;
  checkedAt: string;
  flags: string[];
  /** Hard block from the provider (e.g. known fraud ring). */
  block: boolean;
  /**
   * What the provider knows about the entity's contact points. Not decoration: proof of control rests on
   * challenging a contact point, and one that several companies share — a filing agent's mailbox — makes that
   * challenge nearly worthless. The venue reads this before it sends a code anywhere.
   */
  contact?: {
    email?: string;
    /** Other FMCSA registrants using this same email. 0 means exclusive to this entity. */
    emailSharedWith: number;
    emailLastChanged?: string;
    emailChangeCount: number;
    phone?: string;
    phoneSharedWith: number;
    addressUndeliverable: boolean;
  };
  /** Signals the underwriting model can price, where the provider supplies them. */
  risk?: {
    score?: string;
    probability?: number;
    authorityAgeDays?: number;
    revocations?: number;
    insuranceCancellations?: number;
    vehicleOosRate?: number;
    issValue?: number;
  };
  /** Hash of the provider's response, so an assessment can be cited without republishing their data. */
  digest?: string;
  /** The provider's own "as of". */
  snapshotDate?: string;
}

export interface VettingProvider {
  assess(usdot: string): Promise<VettingAssessment>;
}

/**
 * VETTING_PROVIDER=carrierok | stub (default stub).
 *   carrierok  CARRIEROK_API_KEY (sk_test_… is their sandbox), CARRIEROK_BASE_URL,
 *              VETTING_ALLOW_ON_UNREACHABLE=1 to onboard when the provider is down (a decision, not a default),
 *              VETTING_MAX_CONTACT_SHARED (default 0: a contact point must be this entity's alone to be challenged),
 *              VETTING_BLOCK_RISK (comma-separated, default "Very High").
 */
export function vettingFromEnv(registry: RegistryView, env: NodeJS.ProcessEnv = process.env): VettingProvider {
  if (env.VETTING_PROVIDER !== "carrierok") return new StubVettingProvider(registry);
  if (!env.CARRIEROK_API_KEY) throw new Error("VETTING_PROVIDER=carrierok needs CARRIEROK_API_KEY");
  return new CarrierOkVetting({
    apiKey: env.CARRIEROK_API_KEY,
    baseUrl: env.CARRIEROK_BASE_URL,
    policy: {
      allowOnUnreachable: env.VETTING_ALLOW_ON_UNREACHABLE === "1",
      maxContactSharedWith: env.VETTING_MAX_CONTACT_SHARED ? Number(env.VETTING_MAX_CONTACT_SHARED) : undefined,
      blockRiskScores: env.VETTING_BLOCK_RISK ? env.VETTING_BLOCK_RISK.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
    } as Partial<VettingPolicy>,
  });
}

export class StubVettingProvider implements VettingProvider {
  constructor(private readonly registry: RegistryView, private readonly name = "stub:highway-like") {}
  async assess(usdot: string): Promise<VettingAssessment> {
    const rec = this.registry.get(usdot);
    const flags = rec?._vettingFlags ?? ["not-found"];
    return { provider: this.name, checkedAt: new Date().toISOString(), flags, block: flags.includes("BLOCK") };
  }
}

/**
 * A vetting provider over HTTP. Highway, Descartes MyCarrierPortal, Carrier
 * Assure and Carrier411 each have their own JSON; `map` turns a response
 * into flags and a block decision, so the venue's use of the result (a
 * credential's `vettingFlags`, the underwriting factors) is the same for all
 * of them. An unreachable provider is a `provider-unreachable` flag AND, by
 * default, a block: onboarding without vetting is a decision somebody makes,
 * not something that happens because a third party had an outage. Pass
 * `allowOnUnreachable` to decide the other way, deliberately.
 */
export class HttpVettingProvider implements VettingProvider {
  constructor(
    private readonly name: string,
    private readonly url: (usdot: string) => string,
    private readonly headers: Record<string, string>,
    private readonly map: (body: unknown) => { flags: string[]; block: boolean },
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly allowOnUnreachable = false,
  ) {}
  async assess(usdot: string): Promise<VettingAssessment> {
    try {
      const res = await this.fetchImpl(this.url(usdot), { headers: this.headers });
      if (!res.ok) return { provider: this.name, checkedAt: new Date().toISOString(), flags: [`provider-unreachable:${res.status}`], block: !this.allowOnUnreachable };
      const { flags, block } = this.map(await res.json());
      return { provider: this.name, checkedAt: new Date().toISOString(), flags, block };
    } catch (e) {
      return { provider: this.name, checkedAt: new Date().toISOString(), flags: [`provider-unreachable:${String(e).slice(0, 40)}`], block: !this.allowOnUnreachable };
    }
  }
}
