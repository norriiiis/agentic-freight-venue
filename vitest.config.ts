import { defineConfig } from "vitest/config";

/**
 * Every integration suite here spawns real OS processes — a registry, a venue,
 * agents, the hosted application — and several assert on timing (witness
 * freshness, reply timeouts, registry staleness). Running test FILES in
 * parallel puts a dozen processes on the same cores and those assertions start
 * failing for load rather than for a defect. One file at a time; the unit
 * suites are fast enough that this costs little.
 */
export default defineConfig({
  test: {
    fileParallelism: false,
    testTimeout: 200_000,
    hookTimeout: 120_000,
  },
});
