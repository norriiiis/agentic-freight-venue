import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Scenario } from "../scenario";
import { standardSetup, negotiate, resultFromTask } from "./common";
import { fetchBundle, verifyBundle, type Pins } from "../../ledger/bundle";
import type { OkpJwk } from "../../protocol/crypto";

export const happyPath: Scenario = {
  id: "happy-path",
  title: "Happy path: tender → counter → converge → both sign → venue records → guarantee attaches",
  summary: "Broker agent tenders a 780-mile dry van load. Carrier agent evaluates against its own mandate and economics, counters (rate + a later pickup window), the two converge, both sign the same terms, the venue records the commitment and attaches a guarantee. A verification bundle is then assembled from the venue's part and the registries' word today, and verified against the verifier's own pins.",
  expect: { outcome: "COMMITTED" },
  async run({ h, say }) {
    const { broker, carrier } = await standardSetup(h);
    const { task } = await negotiate(h, broker, carrier);
    const res = await resultFromTask(h, task!);
    // One document, one verdict: the venue's part plus the world's word, verified against pins the verifier chose.
    const bundle = await fetchBundle({ venueUrl: h.venue.url, commitmentId: task!.commitmentId!, registryUrls: h.registries.map((r) => r.url) });
    const pins: Pins = { venueRoot: JSON.parse(readFileSync(join(h.venue.dir, "venue-root-public.jwk.json"), "utf8")) as OkpJwk, registryKeys: await Promise.all(h.registries.map((r) => r.key())) };
    writeFileSync(join(h.opts.workspace, "bundle.json"), JSON.stringify(bundle, null, 2));
    writeFileSync(join(h.opts.workspace, "pins.json"), JSON.stringify(pins, null, 2));
    const v = verifyBundle(bundle, pins);
    say(`verification bundle: venue part (artifact, ${bundle.ledger?.length} ledger entries, status list, key history) + ${bundle.currentAttestations?.length} registry attestation(s) fetched from ${bundle.sources.registries?.length} registr${bundle.sources.registries?.length === 1 ? "y" : "ies"} → ${v.ok ? "VERIFIED" : v.reasonCode} (${v.checks.length} checks)`);
    res.findings.push({ label: "verification bundle", detail: `bundle.json + pins.json in the workspace: one document, one verdict — ${v.checks.length} checks, ${v.ok ? "all pass" : v.reasonCode}; re-run with npm run verify -- --bundle <workspace>/bundle.json --pins <workspace>/pins.json` });
    return res;
  },
};
