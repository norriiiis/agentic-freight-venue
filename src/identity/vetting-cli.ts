/**
 * Point the adapter at the real API and print what comes back.
 *
 *   CARRIEROK_API_KEY=sk_test_… npm run vetting:check -- 2751903
 *
 * This exists because the adapter was written against CarrierOk's OpenAPI
 * document, and a document is a promise rather than an observation. Run this
 * with a sandbox key before a client depends on it: it reports which fields
 * the live response actually carries, which the adapter needed and did not
 * find, and what the venue would decide. A field named here as MISSING is one
 * the mapping silently treats as absent — which is how an integration quietly
 * stops vetting anybody.
 */
import { CarrierOkVetting, type CarrierOkProfile } from "./vetting-carrierok";

const NEEDED: (keyof CarrierOkProfile)[] = [
  "dot_number", "docket", "legal_name", "usdot_status", "out_of_service_flag",
  "email_address", "email_change_count", "email_last_changed", "telephone_number",
  "authority_common", "authority_contract", "authority_broker",
  "authority_common_revocation", "authority_age_common_active", "total_revocations", "indicator_authority",
  "indicator_insurance", "insurance_bipd_on_file", "insurance_cancel_count",
  "risk_score", "iss_recommendation", "indicator_carrier_safety",
  "network_graph_count_ein", "network_graph_count_email_address", "network_graph_count_telephone_numbers",
  "snapshot_date",
];

async function main() {
  const usdot = process.argv[2];
  const key = process.env.CARRIEROK_API_KEY;
  if (!usdot || !key) {
    console.error("usage: CARRIEROK_API_KEY=sk_test_… npm run vetting:check -- <USDOT>");
    process.exit(2);
  }
  const v = new CarrierOkVetting({ apiKey: key, baseUrl: process.env.CARRIEROK_BASE_URL });
  console.log(`asking ${process.env.CARRIEROK_BASE_URL ?? "https://api.carrierok.com"} about USDOT ${usdot}${v.sandbox ? "  (SANDBOX KEY: fixtures, not the live record)" : ""}\n`);

  const r = await v.profile(usdot);
  if (!r.ok) {
    console.error(`no profile: ${r.why}${r.retryAfterMs ? ` (retry in ${r.retryAfterMs / 1000}s)` : ""}`);
    process.exit(1);
  }
  const p = r.profile;
  const missing = NEEDED.filter((k) => p[k] === undefined);
  const present = NEEDED.filter((k) => p[k] !== undefined);
  console.log(`fields this adapter reads: ${present.length}/${NEEDED.length} present`);
  if (missing.length) {
    console.log(`\n  MISSING — the mapping treats each of these as absent:\n${missing.map((k) => `    ${k}`).join("\n")}`);
    console.log(`\n  If a contact or network-graph field is missing, the control gate cannot tell whether a mailbox`);
    console.log(`  is shared, and will let a challenge go to it. Decide that deliberately before onboarding anyone.`);
  }

  const a = v.map(p, r.body);
  console.log(`\nassessment`);
  console.log(`  provider     ${a.provider}`);
  console.log(`  snapshot     ${a.snapshotDate ?? "—"}`);
  console.log(`  block        ${a.block}`);
  console.log(`  flags        ${a.flags.length ? a.flags.join(", ") : "(none)"}`);
  console.log(`  contact      ${a.contact?.email ?? "—"}  shared with ${a.contact?.emailSharedWith ?? "?"} other registrants, last changed ${a.contact?.emailLastChanged ?? "—"}`);
  console.log(`  risk         ${a.risk?.score ?? "—"} (p=${a.risk?.probability ?? "—"}) · authority ${a.risk?.authorityAgeDays ?? "—"}d · ${a.risk?.revocations ?? 0} revocations · ${a.risk?.insuranceCancellations ?? 0} insurance cancellations`);

  const shared = a.contact?.emailSharedWith;
  console.log(`\nwhat the venue would do`);
  console.log(`  onboarding   ${a.block ? "REFUSE — the provider blocks this carrier" : "allow, recording the flags on the credential"}`);
  console.log(`  challenge    ${shared === undefined ? "send, and record that exclusivity is unknown" : shared > 0 ? `REFUSE — CONTROL_CONTACT_NOT_EXCLUSIVE (${shared} other registrants read that mailbox)` : "send a code to that contact point"}`);
}

void main();
