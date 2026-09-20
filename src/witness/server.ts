/**
 * Witness process entrypoint.
 *   WITNESS_ID, WITNESS_DATA_DIR, WITNESS_PORT, WITNESS_VENUE_URL, WITNESS_POLL_MS
 *   WITNESS_PEERS  JSON [{ witnessId, url, publicKey }] — other witnesses to gossip with (configured out of band)
 */
import { startServer } from "../protocol/rpc";
import { WitnessService, type WitnessPeer } from "./service";
import type { EquivocationProof, WitnessReceipt } from "../protocol/witness";

const peers = process.env.WITNESS_PEERS ? JSON.parse(process.env.WITNESS_PEERS) : [];
const w = new WitnessService(process.env.WITNESS_ID ?? "witness-1", process.env.WITNESS_DATA_DIR ?? ".data/witness", process.env.WITNESS_VENUE_URL ?? "http://127.0.0.1:4100", peers);
const port = Number(process.env.WITNESS_PORT ?? 4300);
const pollMs = Number(process.env.WITNESS_POLL_MS ?? 5000);
const ok = (body: unknown) => ({ status: 200, body });

startServer(port, {
  rpcPath: "/rpc",
  rpc: async () => { throw new Error("no rpc methods"); },
  routes: {
    "GET /health": async () => ok({ ok: true, ...w.status() }),
    "GET /receipts": async () => ok(w.receipts()),
    "GET /latest": async () => ok(w.latestReceipt() ?? null),
    /** A receipt for a position this witness verified, signed on demand — how a peer that is behind compares at a common seq. */
    "GET /receipt-for": async (req) => { const seq = Number(new URL(req.url ?? "/", "http://localhost").searchParams.get("seq")); return ok(Number.isInteger(seq) ? w.receiptFor(seq) ?? null : null); },
    "GET /forks": async () => ok(w.forks()),
    "GET /equivocations": async () => ok(w.equivocations()),
    "POST /poll": async () => ok(await w.poll()),
    "POST /gossip-now": async () => ok(await w.gossip()),
    "POST /peers": async (_r, b) => { w.addPeers((b as { peers: WitnessPeer[] }).peers); return ok({ peers: w.peers.map((p) => p.witnessId) }); },
    /** SIM fault: make this witness collude — it will sign any head it is handed. */
    "POST /fault": async (_r, b) => { w.signAnything = !!(b as { signAnything?: boolean }).signAnything; return ok({ colluding: w.signAnything }); },
    "POST /sign": async (_r, b) => { const { venueId, head } = b as { venueId: string; head: { seq: number; hash: string; ts: string } }; return ok({ receipt: w.signBlindly(venueId, head) ?? null }); },
    "POST /gossip": async (_r, b) => ok({ proof: w.receiveGossip((b as { receipt: WitnessReceipt }).receipt) ?? null }),
    "POST /equivocation": async (_r, b) => ok({ accepted: w.receiveProof((b as { proof: EquivocationProof }).proof) }),
  },
}).then(() => {
  console.log(`[${w.witnessId}] witnessing ${w.venueUrl} every ${pollMs}ms, gossiping with ${peers.length} peer(s) (kid ${w.kp.kid.slice(0, 12)}…) on http://127.0.0.1:${port}`);
  setInterval(() => { w.poll().then(() => w.gossip()).catch(() => {}); }, pollMs).unref();
});
