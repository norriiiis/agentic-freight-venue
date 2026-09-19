/**
 * Vetting provider interface. Highway, Descartes MyCarrierPortal, Carrier
 * Assure and Carrier411 sell this today for human workflows; we treat their
 * output as an *input* and build above it.
 *
 * STUB: returns the flags recorded in the mock registry fixture.
 */
import type { MockRegistry } from "./registry";

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
  constructor(private readonly registry: MockRegistry, private readonly name = "stub:highway-like") {}
  async assess(usdot: string): Promise<VettingAssessment> {
    const rec = this.registry.get(usdot);
    const flags = rec?._vettingFlags ?? ["not-found"];
    return { provider: this.name, checkedAt: new Date().toISOString(), flags, block: flags.includes("BLOCK") };
  }
}
