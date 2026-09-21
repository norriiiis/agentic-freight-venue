/**
 * Vetting provider interface. Highway, Descartes MyCarrierPortal, Carrier
 * Assure and Carrier411 sell this today for human workflows; we treat their
 * output as an *input* and build above it.
 *
 * STUB: returns the flags recorded in the mock registry fixture.
 */
import type { RegistryView } from "../protocol/registry";

export interface VettingAssessment {
  provider: string;
  checkedAt: string;
  flags: string[];
  /** Hard block from the provider (e.g. known fraud ring). */
  block: boolean;
}

export interface VettingProvider {
  assess(usdot: string): Promise<VettingAssessment>;
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
 * of them. Unreachable provider = a `provider-unreachable` flag, never a
 * silent pass: onboarding without vetting is a decision, not an accident.
 */
export class HttpVettingProvider implements VettingProvider {
  constructor(
    private readonly name: string,
    private readonly url: (usdot: string) => string,
    private readonly headers: Record<string, string>,
    private readonly map: (body: unknown) => { flags: string[]; block: boolean },
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}
  async assess(usdot: string): Promise<VettingAssessment> {
    try {
      const res = await this.fetchImpl(this.url(usdot), { headers: this.headers });
      if (!res.ok) return { provider: this.name, checkedAt: new Date().toISOString(), flags: [`provider-unreachable:${res.status}`], block: false };
      const { flags, block } = this.map(await res.json());
      return { provider: this.name, checkedAt: new Date().toISOString(), flags, block };
    } catch (e) {
      return { provider: this.name, checkedAt: new Date().toISOString(), flags: [`provider-unreachable:${String(e).slice(0, 40)}`], block: false };
    }
  }
}
