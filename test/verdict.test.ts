import { describe, it, expect } from "vitest";
import { VERDICT_ORDER, verdictFor } from "../src/ledger/artifact";

const f = (...names: (string | [string, string])[]) => names.map((n) => (typeof n === "string" ? { name: n } : { name: n[0], detail: n[1] }));

describe("verdict precedence: one declared order, most damning first", () => {
  it("names the worst thing that failed", () => {
    expect(verdictFor([])).toBeUndefined();
    expect(verdictFor(f("venue.no-equivocation", "carrier.registry.quorum", "status.fresh-as-of"))).toBe("VENUE_EQUIVOCATION");
    expect(verdictFor(f("inclusion[n1]", "carrier.registry.standing-at-commitment"))).toBe("INCLUSION_PROMISE_BROKEN");
    expect(verdictFor(f("carrier.registry[mirror-a].true-when-signed", "carrier.insurer[gpm].true-when-signed"))).toBe("REGISTRY_FALSE_ATTESTATION");
    expect(verdictFor(f("carrier.insurer[gpm].true-when-signed", "carrier.insurer.standing-at-commitment"))).toBe("INSURER_FALSE_ATTESTATION");
    expect(verdictFor(f("carrier.insurer.standing-per-renewal", "carrier.registry.standing-at-commitment"))).toBe("INSURER_CONTRADICTS_COMMITMENT");
    expect(verdictFor(f("carrier.registry.standing-at-commitment", "carrier.registry.quorum"))).toBe("REGISTRY_CONTRADICTS_COMMITMENT");
  });

  it("explains a missed registry quorum by why the registries did not qualify", () => {
    expect(verdictFor(f("carrier.registry.quorum", ["carrier.registry[a]", "registry word was 9000ms old at commitment; policy allows 1000ms"]))).toBe("REGISTRY_STALE");
    expect(verdictFor(f("carrier.registry.quorum", ["carrier.registry[a]", "attestation does not verify under the pinned key"]))).toBe("REGISTRY_ATTESTATION_INVALID");
    expect(verdictFor(f(["carrier.registry.quorum", "required registry c absent"]))).toBe("REGISTRY_QUORUM_NOT_MET");
  });

  it("grades the pending verdicts: only when nothing worse failed", () => {
    expect(verdictFor(f("status.no-pending-notices", "status.fresh-as-of"))).toBe("NOTICE_PENDING");
    expect(verdictFor(f("status.no-pending-notices", "terms.hash"))).toBe("RECORD_TAMPERED");
    expect(verdictFor(f("carrier.insurer.renewal-due"))).toBe("INSURANCE_RENEWAL_PENDING");
    expect(verdictFor(f("carrier.insurer.renewal-due", "carrier.registry.consistent"))).toBe("REGISTRY_DISAGREEMENT");
    expect(verdictFor(f("carrier.insurer.renewal-not-presented", "carrier.insurer.renewal-due"))).toBe("INSURANCE_RENEWAL_NOT_PRESENTED");
  });

  it("witness freshness verdicts apply only when every failure is about witnessing", () => {
    expect(verdictFor(f("status.fresh-as-of"))).toBe("STATUS_STALE");
    expect(verdictFor(f("status.witnessed"))).toBe("STATUS_NOT_WITNESSED");
    expect(verdictFor(f("status.witness-quorum", "keys.fresh-as-of"))).toBe("WITNESS_QUORUM_NOT_MET");
    expect(verdictFor(f("status.fresh-as-of", "broker.accept.signature"))).toBe("RECORD_TAMPERED");
  });

  it("key problems: an agent key compromise is named only when the venue's keys are fine", () => {
    expect(verdictFor(f("carrier.credential.trusted-at-signing"))).toBe("COMMITMENT_UNDER_COMPROMISED_KEY");
    expect(verdictFor(f("carrier.credential.trusted-at-signing", "venue.attestation.any-trusted"))).toBe("VENUE_KEY_UNTRUSTED");
    expect(verdictFor(f("carrier.credential.issuer-signature"))).toBe("CREDENTIAL_ISSUER_INVALID"); // the fallback: a credential the venue did not sign
    expect(verdictFor(f("broker.credential.entity-matches-terms"))).toBe("CREDENTIAL_ISSUER_INVALID"); // "-match$" is the ACCEPT-vs-terms family; entity/agent mismatches fall to the credential fallback
  });

  it("the origin chain, in order: regulator, license, key of record, filing of record, presence, undertaking, window", () => {
    expect(verdictFor(f("carrier.regulator[naic].anchored", "carrier.filer[gpm].licensed"))).toBe("REGULATOR_KEY_UNTRUSTED");
    expect(verdictFor(f("carrier.filer[gpm].licensed", "carrier.insurer[gpm].key-of-record"))).toBe("FILER_UNLICENSED");
    expect(verdictFor(f("carrier.insurer[gpm].key-of-record", "carrier.insurer[gpm].of-record"))).toBe("INSURER_KEY_NOT_OF_RECORD");
    expect(verdictFor(f("carrier.insurer[gpm].of-record", "carrier.insurer.attestation-present"))).toBe("INSURER_NOT_OF_RECORD");
    expect(verdictFor(f("carrier.insurer.attestation-present", "carrier.insurer.undertaking"))).toBe("INSURER_ATTESTATION_MISSING");
    expect(verdictFor(f("carrier.insurer.undertaking", "carrier.insurer.assured-through-delivery"))).toBe("INSURER_UNDERTAKING_MISSING");
  });

  it("every entry in the table is reachable by a name it matches, and the table has no duplicates except the two INVALID slots", () => {
    const codes = VERDICT_ORDER.map((v) => v.code);
    const dupes = codes.filter((c, i) => codes.indexOf(c) !== i);
    expect(dupes).toEqual(["REGISTRY_ATTESTATION_INVALID"]);
  });
});
