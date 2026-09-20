/**
 * Witness process entrypoint.
 *   WITNESS_ID, WITNESS_DATA_DIR, WITNESS_PORT, WITNESS_VENUE_URL, WITNESS_POLL_MS
 */
import { startServer } from "../protocol/rpc";
import { WitnessService } from "./service";

const w = new WitnessService(process.env.WITNESS_ID ?? "witness-1", process.env.WITNESS_DATA_DIR ?? ".data/witness", process.env.WITNESS_VENUE_URL ?? "http://127.0.0.1:4100");
const port = Number(process.env.WITNESS_PORT ?? 4300);
const pollMs = Number(process.env.WITNESS_POLL_MS ?? 5000);
const ok = (body: unknown) => ({ status: 200, body });

startServer(port, {
  rpcPath: "/rpc",
  rpc: async () => { throw new Error("no rpc methods"); },
  routes: {
    "GET /health": async () => ok({ ok: true, ...w.status() }),
    "GET /receipts": async () => ok(w.receipts()),
    "GET /forks": async () => ok(w.forks()),
    "POST /poll": async () => ok(await w.poll()),
  },
}).then(() => {
  console.log(`[${w.witnessId}] witnessing ${w.venueUrl} every ${pollMs}ms (kid ${w.kp.kid.slice(0, 12)}…) on http://127.0.0.1:${port}`);
  setInterval(() => { w.poll().catch(() => {}); }, pollMs).unref();
});
