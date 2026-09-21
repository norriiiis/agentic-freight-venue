import { describe, it, expect } from "vitest";
import type { Terms } from "../src/protocol/freight";
import { DEFAULT_PROFILE, interchange, parseX12, read204, response990, status214, tender204, STATUS_214 } from "../src/edi/x12";

const TERMS: Terms = {
  loadRef: "L-2026-262-0417",
  load: {
    loadRef: "L-2026-262-0417",
    origin: { city: "Pasadena", state: "TX", zip: "77507", windowStart: "2026-09-23T13:00:00.000Z", windowEnd: "2026-09-23T19:00:00.000Z" },
    destination: { city: "Kansas City", state: "MO", zip: "64120", windowStart: "2026-09-24T13:00:00.000Z", windowEnd: "2026-09-24T21:00:00.000Z" },
    equipment: "VAN", weightLbs: 38_500, commodity: "Consumer packaged goods, palletized", miles: 780, hazmat: false, subcontractPermitted: false,
  },
  rateUsd: 2215, pickup: { windowStart: "2026-09-23T15:00:00.000Z", windowEnd: "2026-09-23T19:00:00.000Z" }, delivery: { windowStart: "2026-09-24T13:00:00.000Z", windowEnd: "2026-09-24T21:00:00.000Z" },
  paymentTermsDays: 30, brokerAgentId: "northline-broker-agent", carrierAgentId: "prairie-wind-carrier-agent",
  brokerEntity: { usdot: "3312874", mc: "MC-1088412" }, carrierEntity: { usdot: "2751903", mc: "MC-0938251" },
};
const ENV = { senderId: "USDOT3312874", receiverId: "USDOT2751903", controlNumber: 42, now: new Date("2026-09-21T16:05:00Z") };

describe("x12: envelopes", () => {
  it("writes a well-formed ISA (106 fixed characters) and matching GS/GE, ST/SE, IEA counts", () => {
    const x = interchange(ENV, [{ id: "204", body: tender204(TERMS, { scac: "PWTI", commitmentId: "cmt_1" }) }]);
    const lines = x.split("\n");
    expect(lines[0]).toHaveLength(106);
    expect(lines[0]!.startsWith("ISA*00*          *00*          *ZZ*USDOT3312874   *ZZ*USDOT2751903   *260921*1605*U*00401*000000042*0*T*>~")).toBe(true);
    const p = parseX12(x);
    expect(p.problems).toEqual([]);
    expect(p.delimiters).toEqual({ element: "*", segment: "~", subElement: ">" });
    expect(p.sets.map((s) => s.id)).toEqual(["204"]);
    const se = p.sets[0]!.segments.at(-1)!;
    expect(se[0]).toBe("SE");
    expect(Number(se[1])).toBe(p.sets[0]!.segments.length);
    expect(p.segments.find((s) => s[0] === "GS")![1]).toBe("SM");
    expect(p.segments.at(-1)).toEqual(["IEA", "1", "000000042"]);
  });
  it("puts each functional identifier in its own group and refuses data that contains a delimiter", () => {
    const x = interchange(ENV, [
      { id: "204", body: tender204(TERMS) },
      { id: "990", body: response990(TERMS, "A", { at: ENV.now }) },
      { id: "214", body: status214(TERMS, { event: "PICKED_UP", at: "2026-09-23T15:30:00Z" })! },
      { id: "214", body: status214(TERMS, { event: "DELIVERED", at: "2026-09-24T14:10:00Z" })! },
    ]);
    const p = parseX12(x);
    expect(p.problems).toEqual([]);
    expect(p.segments.filter((s) => s[0] === "GS").map((s) => s[1])).toEqual(["SM", "GF", "QM"]);
    expect(p.segments.filter((s) => s[0] === "GE").map((s) => s[1])).toEqual(["1", "1", "2"]);
    expect(p.segments.at(-1)![1]).toBe("3");
    const bad = { ...TERMS, load: { ...TERMS.load, commodity: "Cans*bottles" } };
    expect(() => interchange(ENV, [{ id: "204", body: tender204(bad) }])).toThrow(/contains the delimiter/);
  });
  it("a partner profile changes delimiters and version without changing the layout", () => {
    const x = interchange({ ...ENV, profile: { elementSep: "|", segmentTerm: "'", subElementSep: ":", version: "005010", repetitionSep: "^", usage: "P" } }, [{ id: "990", body: response990(TERMS, "D", { reasonCode: "MANDATE_RATE_BELOW_FLOOR" }) }]);
    expect(x.startsWith("ISA|00|")).toBe(true);
    expect(x).toContain("|^|00501|");
    const p = parseX12(x);
    expect(p.problems).toEqual([]);
    expect(p.delimiters).toEqual({ element: "|", segment: "'", subElement: ":" });
    expect(p.segments.find((s) => s[0] === "GS")![8]).toBe("005010");
    expect(p.segments.find((s) => s[0] === "B1")![4]).toBe("D");
    expect(p.segments.find((s) => s[0] === "N9" && s[1] === "ZZ")![2]).toBe("MANDATE_RATE_BELOW_FLOOR");
  });
  it("reports structural problems in a foreign interchange instead of throwing", () => {
    const x = interchange(ENV, [{ id: "204", body: tender204(TERMS) }]).replace("IEA*1*000000042", "IEA*2*000000099").replace(/SE\*(\d+)\*/, "SE*99*");
    const p = parseX12(x);
    expect(p.problems).toEqual(expect.arrayContaining([expect.stringMatching(/SE count 99/), expect.stringMatching(/IEA control 000000099 != ISA control 000000042/), expect.stringMatching(/IEA group count 2 != 1/)]));
    expect(() => parseX12("hello")).toThrow(/no ISA/);
  });
});

describe("x12: 204 / 990 / 214 carry the venue's terms", () => {
  it("204: the load, both stops with their windows, the rate and references round-trip", () => {
    const body = tender204(TERMS, { scac: "PWTI", commitmentId: "cmt_abc" });
    expect(body[0]).toEqual(["B2", "", "PWTI", "", "L-2026-262-0417", "", "PP"]);
    expect(body.filter((s) => s[0] === "S5").map((s) => s[2])).toEqual(["CL", "CU"]); // complete load, complete unload
    const q = DEFAULT_PROFILE.qualifiers;
    expect(body.filter((s) => s[0] === "G62").map((s) => `${s[1]}:${s[2]}:${s[3]}:${s[4]}`)).toEqual([
      `${q.pickupNotBefore}:20260923:${q.earliestTime}:1500`, `${q.pickupNoLater}:20260923:${q.latestTime}:1900`,
      `${q.deliverNotBefore}:20260924:${q.earliestTime}:1300`, `${q.deliverNoLater}:20260924:${q.latestTime}:2100`,
    ]);
    const x = interchange(ENV, [{ id: "204", body }]);
    const back = read204(parseX12(x).sets[0]!.segments);
    expect(back.loadRef).toBe("L-2026-262-0417");
    expect(back.rateUsd).toBe(2215);
    expect(back.load?.miles).toBe(780);
    expect(back.load?.weightLbs).toBe(38_500);
    expect(back.load?.commodity).toBe("Consumer packaged goods, palletized");
    expect(back.references).toMatchObject({ BM: "L-2026-262-0417", CR: "cmt_abc", TN: "3312874", MC: "MC-1088412", PT: "30" });
    expect(back.stops).toEqual([
      { kind: "CL", city: "Pasadena", state: "TX", zip: "77507", notBefore: "2026-09-23T15:00:00.000Z", noLater: "2026-09-23T19:00:00.000Z" },
      { kind: "CU", city: "Kansas City", state: "MO", zip: "64120", notBefore: "2026-09-24T13:00:00.000Z", noLater: "2026-09-24T21:00:00.000Z" },
    ]);
  });
  it("204: hazmat and reefer are flagged; the tender states the subcontracting rule", () => {
    const hz = tender204({ ...TERMS, load: { ...TERMS.load, hazmat: true, equipment: "REEFER" } });
    expect(hz.find((s) => s[0] === "N7")!.at(-1)).toBe("RT");
    expect(hz.filter((s) => s[0] === "L5").every((s) => s[7] === "D")).toBe(true);
    expect(hz.find((s) => s[0] === "NTE")![2]).toMatch(/subcontracting not permitted/);
  });
  it("990: accept and decline, with the venue's reason code when declined", () => {
    expect(response990(TERMS, "A", { scac: "PWTI", at: ENV.now, commitmentId: "cmt_1" })).toEqual([["B1", "PWTI", "L-2026-262-0417", "20260921", "A"], ["N9", "BM", "L-2026-262-0417"], ["N9", "CR", "cmt_1"]]);
    expect(response990(TERMS, "D", { at: ENV.now, reasonCode: "MANDATE_RATE_BELOW_FLOOR" }).at(-1)).toEqual(["N9", "ZZ", "MANDATE_RATE_BELOW_FLOOR"]);
  });
  it("214: carrier statuses map to AT7 codes with UTC time; the POD hash rides as a reference; non-status events have no 214", () => {
    const pu = status214(TERMS, { event: "PICKED_UP", at: "2026-09-23T15:30:00Z" }, { scac: "PWTI", commitmentId: "cmt_1" })!;
    expect(pu.find((s) => s[0] === "AT7")).toEqual(["AT7", "AF", "NS", "", "", "20260923", "1530", "UT"]);
    expect(pu.find((s) => s[0] === "MS1")).toEqual(["MS1", "Pasadena", "TX", "US"]);
    const pod = status214(TERMS, { event: "POD", at: "2026-09-24T14:10:00Z", evidenceHash: "ab".repeat(32) })!;
    expect(pod.find((s) => s[0] === "AT7")![1]).toBe(STATUS_214.POD!.code);
    expect(pod.find((s) => s[0] === "L11" && s[2] === "POD")![1]).toBe("ab".repeat(32));
    expect(pod.find((s) => s[0] === "MS1")).toEqual(["MS1", "Kansas City", "MO", "US"]);
    for (const ev of ["DELIVERY_ACCEPTED", "PAID", "DISPUTE_OPENED", "DISPUTE_CLOSED"] as const) expect(status214(TERMS, { event: ev, at: "2026-09-25T00:00:00Z" })).toBeUndefined();
  });
});
