/**
 * X12 EDI for the transactions the rest of the industry speaks: 204 (Motor
 * Carrier Load Tender), 990 (Response to a Load Tender) and 214 (Shipment
 * Status). This is the bridge OUT of the venue: a commitment's terms
 * rendered as the 204 a TMS expects, the acceptance as its 990, and each
 * lifecycle event as a 214 status — so a shipper's existing systems see the
 * load the way they see every other load, while the ledger stays the record.
 *
 * What is deliberately NOT here: trading-partner implementation guides. Every
 * partner's 204 differs in which qualifiers, references and N1 loops it wants;
 * the `Profile` names the choices this serializer makes (segment terminators,
 * date/time qualifiers, timezone code, version) so a partner override is a
 * profile, not a fork. X12 has no escape mechanism — data that contains a
 * delimiter is rejected, not silently corrupted.
 *
 * Layouts follow ASC X12 004010 segment usage as commonly implemented for
 * truckload; a partner IG is the authority on the qualifiers.
 */
import type { LifecycleEventType, Terms } from "../protocol/freight";

export type Segment = string[];

export interface Profile {
  version: "004010" | "005010";
  elementSep: string;
  segmentTerm: string;
  subElementSep: string;
  repetitionSep: string;
  usage: "P" | "T";
  /** X12 times have no offset; we emit UTC and say so (AT7-07 = "UT"). */
  timeZoneCode: string;
  /** G62 date/time qualifiers for stop windows. Partner IGs vary; these are the 004010 codes for ship/deliver not-before/no-later. */
  qualifiers: { pickupNotBefore: string; pickupNoLater: string; deliverNotBefore: string; deliverNoLater: string; earliestTime: string; latestTime: string };
}

export const DEFAULT_PROFILE: Profile = {
  version: "004010",
  elementSep: "*",
  segmentTerm: "~",
  subElementSep: ">",
  repetitionSep: "U",
  usage: "T",
  timeZoneCode: "UT",
  qualifiers: { pickupNotBefore: "37", pickupNoLater: "38", deliverNotBefore: "53", deliverNoLater: "54", earliestTime: "G", latestTime: "L" },
};

export interface Envelope {
  senderId: string;
  receiverId: string;
  /** Interchange control number; the GS/ST numbers derive from it. */
  controlNumber: number;
  now?: Date;
  profile?: Partial<Profile>;
}

/** Lifecycle → 214 AT7 shipment status codes. Events the carrier does not report (acceptance, payment, disputes) are not shipment statuses and have no 214. */
export const STATUS_214: Partial<Record<LifecycleEventType, { code: string; desc: string }>> = {
  PICKED_UP: { code: "AF", desc: "Carrier departed pick-up location with shipment" },
  DELIVERED: { code: "D1", desc: "Completed unloading at delivery location" },
  POD: { code: "D1", desc: "Completed unloading at delivery location (proof of delivery attached)" },
};

const ccyymmdd = (iso: string) => iso.slice(0, 10).replace(/-/g, "");
const yymmdd = (iso: string) => iso.slice(2, 10).replace(/-/g, "");
const hhmm = (iso: string) => iso.slice(11, 16).replace(":", "");
const pad = (s: string, n: number) => s.padEnd(n).slice(0, n);
const num = (n: number, width: number) => String(Math.trunc(n)).padStart(width, "0").slice(-width);

function profileOf(e: Envelope): Profile {
  return { ...DEFAULT_PROFILE, ...e.profile, qualifiers: { ...DEFAULT_PROFILE.qualifiers, ...e.profile?.qualifiers } };
}

/** Elements that would break the interchange are refused: X12 has no escaping. */
function guard(p: Profile, seg: Segment): Segment {
  for (const el of seg) {
    for (const d of [p.elementSep, p.segmentTerm, p.subElementSep]) if (el.includes(d)) throw new Error(`X12: element "${el}" contains the delimiter "${d}"; substitute before serializing`);
  }
  return seg;
}

function render(p: Profile, segments: Segment[]): string {
  return segments.map((s) => {
    const trimmed = [...s];
    while (trimmed.length > 1 && trimmed[trimmed.length - 1] === "") trimmed.pop(); // trailing empties are omitted, except in the fixed-width ISA
    return (s[0] === "ISA" ? s : guard(p, trimmed)).join(p.elementSep) + p.segmentTerm;
  }).join("\n");
}

/** ISA/GS/ST … SE/GE/IEA around one or more transaction sets. */
export function interchange(env: Envelope, sets: { id: "204" | "990" | "214"; body: Segment[] }[]): string {
  const p = profileOf(env);
  const now = (env.now ?? new Date()).toISOString();
  const isaCtl = num(env.controlNumber, 9);
  const out: Segment[] = [[
    "ISA", "00", pad("", 10), "00", pad("", 10), "ZZ", pad(env.senderId, 15), "ZZ", pad(env.receiverId, 15), yymmdd(now), hhmm(now), p.repetitionSep, p.version === "004010" ? "00401" : "00501", isaCtl, "0", p.usage, p.subElementSep,
  ]];
  // one functional group per functional identifier, in order of first appearance
  const groups = new Map<string, { id: string; sets: Segment[][] }>();
  const functional = { "204": "SM", "990": "GF", "214": "QM" } as const;
  sets.forEach((s, i) => {
    const stCtl = num(env.controlNumber * 100 + i + 1, 4);
    const body = [["ST", s.id, stCtl], ...s.body];
    body.push(["SE", String(body.length + 1), stCtl]);
    const g = groups.get(functional[s.id]) ?? { id: functional[s.id], sets: [] };
    g.sets.push(body);
    groups.set(functional[s.id], g);
  });
  let gi = 0;
  for (const g of groups.values()) {
    gi += 1;
    const gsCtl = String(env.controlNumber * 10 + gi);
    out.push(["GS", g.id, env.senderId, env.receiverId, ccyymmdd(now), hhmm(now), gsCtl, "X", p.version]);
    for (const set of g.sets) out.push(...set);
    out.push(["GE", String(g.sets.length), gsCtl]);
  }
  out.push(["IEA", String(groups.size), isaCtl]);
  return render(p, out);
}

// ------------------------------------------------------------------- 204

export interface TenderOptions {
  /** Carrier SCAC, when known; the venue knows USDOT/MC, a TMS keys on SCAC. */
  scac?: string;
  /** B2A purpose: 00 original, 01 cancellation, 04 change. */
  purpose?: "00" | "01" | "04";
  /** Bill-to party for the N1*BT loop (defaults to the broker). */
  billTo?: { name: string; id?: string };
  commitmentId?: string;
}

/** A commitment's terms as a 204 load tender. */
export function tender204(t: Terms, opts: TenderOptions = {}): Segment[] {
  const seg: Segment[] = [];
  seg.push(["B2", "", opts.scac ?? "", "", t.loadRef, "", "PP"]); // PP: prepaid (the broker pays the carrier)
  seg.push(["B2A", opts.purpose ?? "00", "LT"]);
  seg.push(["L11", t.loadRef, "BM"]); // bill of lading number = the broker's load reference
  if (opts.commitmentId) seg.push(["L11", opts.commitmentId, "CR"]); // customer reference: the venue commitment
  seg.push(["L11", t.brokerEntity.usdot, "TN"]); // transaction reference: broker USDOT
  if (t.brokerEntity.mc) seg.push(["L11", t.brokerEntity.mc, "MC"]);
  seg.push(["L11", String(t.paymentTermsDays), "PT"]); // payment terms in days
  seg.push(["NTE", "OTH", `venue commitment; rate USD ${t.rateUsd.toFixed(2)}; subcontracting ${t.load.subcontractPermitted ? "permitted" : "not permitted"}`]);
  seg.push(["N1", "BT", opts.billTo?.name ?? `USDOT ${t.brokerEntity.usdot}`, "93", opts.billTo?.id ?? t.brokerEntity.usdot]);
  seg.push(["N7", "", "", String(t.load.weightLbs), "N", "", "", "", "", "", "", t.load.equipment === "REEFER" ? "RT" : t.load.equipment === "FLATBED" ? "FT" : "TV"]);
  const q = DEFAULT_PROFILE.qualifiers;
  const stop = (n: number, kind: "CL" | "CU", s: Terms["load"]["origin"], win: { windowStart: string; windowEnd: string }, notBefore: string, noLater: string) => {
    seg.push(["S5", String(n), kind, String(t.load.weightLbs), "L"]);
    seg.push(["G62", notBefore, ccyymmdd(win.windowStart), q.earliestTime, hhmm(win.windowStart)]);
    seg.push(["G62", noLater, ccyymmdd(win.windowEnd), q.latestTime, hhmm(win.windowEnd)]);
    seg.push(["N1", kind === "CL" ? "SH" : "CN", `${s.city}, ${s.state}`]);
    seg.push(["N4", s.city, s.state, s.zip, "US"]);
    seg.push(["OID", t.loadRef, "", "", "PL", "", "L", String(t.load.weightLbs)]);
    seg.push(["L5", "1", t.load.commodity, "", "", "", "", t.load.hazmat ? "D" : ""]);
  };
  stop(1, "CL", t.load.origin, t.pickup, q.pickupNotBefore, q.pickupNoLater);
  stop(2, "CU", t.load.destination, t.delivery, q.deliverNotBefore, q.deliverNoLater);
  seg.push(["L3", String(t.load.weightLbs), "G", "", "", String(Math.round(t.rateUsd * 100)), "", "", "", "", "", String(t.load.miles)]);
  return seg;
}

// ------------------------------------------------------------------- 990

/** The carrier's answer to the tender: A accepted, D declined. */
export function response990(t: Pick<Terms, "loadRef">, disposition: "A" | "D", opts: { scac?: string; at?: Date; commitmentId?: string; reasonCode?: string } = {}): Segment[] {
  const at = (opts.at ?? new Date()).toISOString();
  const seg: Segment[] = [["B1", opts.scac ?? "", t.loadRef, ccyymmdd(at), disposition]];
  seg.push(["N9", "BM", t.loadRef]);
  if (opts.commitmentId) seg.push(["N9", "CR", opts.commitmentId]);
  if (disposition === "D" && opts.reasonCode) seg.push(["N9", "ZZ", opts.reasonCode]);
  return seg;
}

// ------------------------------------------------------------------- 214

export interface StatusEvent {
  event: LifecycleEventType;
  at: string;
  evidenceHash?: string | null;
}

/** A lifecycle event as a 214 shipment status, or `undefined` for events that are not shipment statuses. */
export function status214(t: Terms, ev: StatusEvent, opts: { scac?: string; commitmentId?: string; profile?: Partial<Profile> } = {}): Segment[] | undefined {
  const st = STATUS_214[ev.event];
  if (!st) return undefined;
  const p = { ...DEFAULT_PROFILE, ...opts.profile };
  const where = ev.event === "PICKED_UP" ? t.load.origin : t.load.destination;
  const seg: Segment[] = [["B10", t.loadRef, t.loadRef, opts.scac ?? ""]];
  if (opts.commitmentId) seg.push(["L11", opts.commitmentId, "CR"]);
  if (ev.event === "POD" && ev.evidenceHash) seg.push(["L11", ev.evidenceHash, "POD"]); // hash of the proof-of-delivery document, as on the ledger
  seg.push(["N1", "SH", `${t.load.origin.city}, ${t.load.origin.state}`]);
  seg.push(["N1", "CN", `${t.load.destination.city}, ${t.load.destination.state}`]);
  seg.push(["LX", "1"]);
  seg.push(["AT7", st.code, "NS", "", "", ccyymmdd(ev.at), hhmm(ev.at), p.timeZoneCode]);
  seg.push(["MS1", where.city, where.state, "US"]);
  seg.push(["MS2", opts.scac ?? "", "", t.load.equipment === "REEFER" ? "RT" : "TV"]);
  return seg;
}

// ------------------------------------------------------------------ parse

export interface Parsed {
  delimiters: { element: string; segment: string; subElement: string };
  segments: Segment[];
  /** Transaction sets, by ST-02 control number. */
  sets: { id: string; control: string; segments: Segment[] }[];
  problems: string[];
}

/** Read an interchange back; delimiters come from the ISA itself. Structural problems are reported, not thrown. */
export function parseX12(text: string): Parsed {
  const t = text.replace(/\r?\n/g, "");
  if (!t.startsWith("ISA") || t.length < 106) throw new Error("X12: not an interchange (no ISA)");
  const element = t[3]!;
  const subElement = t[104]!;
  const segment = t[105]!;
  const segments = t.split(segment).filter((s) => s.length).map((s) => s.split(element));
  const problems: string[] = [];
  const sets: Parsed["sets"] = [];
  let cur: Parsed["sets"][number] | undefined;
  for (const s of segments) {
    if (s[0] === "ST") { cur = { id: s[1] ?? "", control: s[2] ?? "", segments: [s] }; sets.push(cur); continue; }
    if (cur) cur.segments.push(s);
    if (s[0] === "SE") {
      if (!cur) { problems.push("SE without ST"); continue; }
      if (Number(s[1]) !== cur.segments.length) problems.push(`SE count ${s[1]} != ${cur.segments.length} in set ${cur.control}`);
      if (s[2] !== cur.control) problems.push(`SE control ${s[2]} != ST control ${cur.control}`);
      cur = undefined;
    }
  }
  const isa = segments[0]!, iea = segments[segments.length - 1]!;
  if (iea[0] !== "IEA") problems.push("missing IEA");
  else if (isa[13] !== iea[2]) problems.push(`IEA control ${iea[2]} != ISA control ${isa[13]}`);
  const groups = segments.filter((s) => s[0] === "GS").length;
  if (iea[0] === "IEA" && Number(iea[1]) !== groups) problems.push(`IEA group count ${iea[1]} != ${groups}`);
  return { delimiters: { element, segment, subElement }, segments, sets, problems };
}

/** The load a 204 describes, as far as the venue's terms go. Reads this serializer's own layout and the common variants of it. */
export function read204(set: Segment[]): Partial<Terms> & { stops: { kind: string; city?: string; state?: string; zip?: string; notBefore?: string; noLater?: string }[]; references: Record<string, string> } {
  const references: Record<string, string> = {};
  const stops: ReturnType<typeof read204>["stops"] = [];
  let rateUsd: number | undefined;
  let miles: number | undefined;
  let weightLbs: number | undefined;
  let loadRef: string | undefined;
  let commodity: string | undefined;
  let cur: (typeof stops)[number] | undefined;
  const iso = (d: string | undefined, tm: string | undefined) => (d ? `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}T${(tm ?? "0000").slice(0, 2)}:${(tm ?? "0000").slice(2, 4)}:00.000Z` : undefined);
  for (const s of set) {
    switch (s[0]) {
      case "B2": loadRef = s[4]; break;
      case "L11": if (s[2]) references[s[2]] = s[1] ?? ""; break;
      case "S5": cur = { kind: s[2] ?? "" }; stops.push(cur); break;
      case "G62": if (cur) { if (s[1] === "37" || s[1] === "53" || s[1] === "10") cur.notBefore = iso(s[2], s[4]); else if (s[1] === "38" || s[1] === "54") cur.noLater = iso(s[2], s[4]); } break;
      case "N4": if (cur) { cur.city = s[1]; cur.state = s[2]; cur.zip = s[3]; } break;
      case "L5": commodity ??= s[2]; break;
      case "L3": weightLbs = Number(s[1]); rateUsd = s[5] ? Number(s[5]) / 100 : undefined; miles = s[11] ? Number(s[11]) : undefined; break;
    }
  }
  return { loadRef, rateUsd, stops, references, ...(weightLbs !== undefined || miles !== undefined || commodity ? { load: { weightLbs, miles, commodity } as unknown as Terms["load"] } : {}) };
}
