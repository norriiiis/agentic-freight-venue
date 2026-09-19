import { describe, it, expect } from "vitest";
import { canonicalize, hashObject } from "../src/protocol/canonical";
import { generateKeyPair, signJws, verifyJws } from "../src/protocol/crypto";
import { signAgentCard, verifyAgentCard, type AgentCard, A2A_PROTOCOL_VERSION } from "../src/protocol/a2a";
import { buildMessage, signMessage, verifyMessageSignature, venueSignMessage, verifyVenueSignature } from "../src/protocol/envelope";

describe("canonical JSON", () => {
  it("is order-independent and drops undefined", () => {
    expect(canonicalize({ b: 1, a: [3, { z: 1, y: undefined }] })).toBe('{"a":[3,{"z":1}],"b":1}');
    expect(hashObject({ a: 1, b: 2 })).toBe(hashObject({ b: 2, a: 1 }));
  });
});

describe("JWS EdDSA", () => {
  it("round-trips attached and detached; rejects tamper and wrong key", () => {
    const kp = generateKeyPair();
    const p = { hello: "world", n: 1 };
    expect(verifyJws(signJws(p, kp), kp.publicKey).ok).toBe(true);
    expect(verifyJws(signJws(p, kp, {}, true), kp.publicKey, { n: 1, hello: "world" }).ok).toBe(true);
    expect(verifyJws(signJws(p, kp, {}, true), kp.publicKey, { n: 2, hello: "world" }).ok).toBe(false);
    expect(verifyJws(signJws(p, kp), generateKeyPair().publicKey).ok).toBe(false);
  });
});

describe("A2A agent card signatures", () => {
  it("signs with embedded JWK and rejects modification", () => {
    const kp = generateKeyPair();
    const card: AgentCard = { protocolVersion: A2A_PROTOCOL_VERSION, name: "x", description: "", url: "http://x/a2a", preferredTransport: "JSONRPC", version: "1", provider: { organization: "o" }, capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false }, defaultInputModes: [], defaultOutputModes: [], skills: [] };
    const signed = signAgentCard(card, kp);
    expect(verifyAgentCard(signed).ok).toBe(true);
    expect(verifyAgentCard({ ...signed, url: "http://evil/a2a" }).ok).toBe(false);
    expect(verifyAgentCard(signed, generateKeyPair().publicJwk).ok).toBe(false);
  });
});

describe("message envelopes", () => {
  it("agent signature survives venue enrichment; venue signature covers the enrichment", () => {
    const agent = generateKeyPair();
    const venue = generateKeyPair();
    const m = signMessage(buildMessage({ role: "user", data: { type: "COUNTER", round: 2 }, senderAgentId: "a", credentialId: "c" }), agent);
    const fwd = venueSignMessage(m, venue, { taskId: "t", contextId: "c", round: 2, forwardedAt: "now", counterparty: { agentId: "a", credentialId: "c", entity: { usdot: "1", legalName: "A", entityType: "CARRIER" }, publicKey: agent.publicJwk, insurance: { bipdUsd: 1, cargoUsd: 0, bondUsd: 0 }, verifiedAt: "now" } });
    expect(verifyMessageSignature(fwd, agent.publicJwk).ok).toBe(true);
    expect(verifyVenueSignature(fwd, venue.publicJwk).ok).toBe(true);
    // altering the venue attachment breaks the venue signature but not the agent's
    const altered = { ...fwd, metadata: { ...fwd.metadata, venue: { ...(fwd.metadata as { venue: object }).venue, round: 9 } } };
    expect(verifyMessageSignature(altered, agent.publicJwk).ok).toBe(true);
    expect(verifyVenueSignature(altered, venue.publicJwk).ok).toBe(false);
    // altering the payload breaks both
    const payload = { ...fwd, parts: [{ kind: "data" as const, data: { type: "COUNTER", round: 3 } }] };
    expect(verifyMessageSignature(payload, agent.publicJwk).ok).toBe(false);
    expect(verifyVenueSignature(payload, venue.publicJwk).ok).toBe(false);
  });
});
