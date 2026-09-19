# Agentic freight transaction venue — working skeleton

A runnable prototype of a third-party venue through which a broker's AI agent and a carrier's AI agent negotiate and commit to a load with no human approving each step. The venue verifies who each agent is (rooted in the public carrier registry), enforces the limits each principal set, records what was agreed in a tamper-evident ledger, and decides whether to stand behind the transaction with a guarantee.

The two agents are separate OS processes with separate data directories and separate configuration. They never learn each other's address. They talk only through the venue, over A2A-shaped JSON-RPC, and every message is signed with a real Ed25519 key.

**A convincing refusal is the product.** Fifteen adversarial scenarios each fail with a machine-readable reason, the component that refused, the evidence it relied on, and whether the guarantee would have paid.

## Run it

```bash
npm install
npm run demo            # happy path: full transcript, independent artifact verification, EDI mapping
npm run sim -- --all    # every adversarial scenario; exit code 1 if any misbehaves
npm test                # 88 tests incl. the no-shared-state proof and all scenarios (~70s)
```

Other entry points:

```bash
npm run sim -- --scenario double-brokering    # one scenario (see --list)
npm run sim -- --all --verbose                # with each process's stdout
npm run verify -- <artifact.json> --venue-root <venue-root-public.jwk.json> --ledger <ledger.jsonl> [--key-history …] [--status-list …]
npm run check:boundaries                      # static import-boundary check
FV_SKIP_SCENARIOS=1 npm test                  # unit tests only (<1s)
```

Every run writes its workspace under `.sim/<timestamp>/<scenario>/` with one directory per process: `venue/`, `northline-broker-agent/`, `prairie-wind-carrier-agent/`. Each contains that process's audit log, keys, state, and (for agents) its own copy of any commitment artifact.

Requires Node ≥ 20 (developed on 26). No cloud dependencies, no database, no network beyond `127.0.0.1`.

## What happens in the happy path

```
 1  BROKER   → venue    TENDER   $2,050  pickup 09-23 13:00Z–19:00
    venue    → CARRIER  fwd TENDER  verified cred_4379d3a5… NORTHLINE LOGISTICS LLC MC-1088412 · bond $75,000
 2  CARRIER  → venue    COUNTER  $2,380  pickup 09-23 15:00Z–19:00  "earliest available pickup"
    venue    → BROKER   fwd COUNTER verified cred_78dea827… PRAIRIE WIND TRANSPORT INC MC-0938251 · BIPD $1,000,000
 3  BROKER   → venue    COUNTER  $2,165
 4  CARRIER  → venue    COUNTER  $2,305
 5  BROKER   → venue    COUNTER  $2,215
 6  CARRIER  → venue    ACCEPT   $2,215  termsHash 696349cbf0b5…
    venue    → BROKER   fwd ACCEPT  … · guarantee quoted
 7  BROKER   → venue    ACCEPT   $2,215  termsHash 696349cbf0b5…
    venue    → BROKER   COMMITTED cmt_10c1712b…  guarantee gtee_a00a3ab7… covers $2,215 premium $35.21
    venue    → CARRIER  COMMITTED cmt_10c1712b…  guarantee gtee_a00a3ab7… covers $2,215 premium $35.21
```

The broker's private context (customer rate $2,650, target margin 14%, floor margin 7%) and the carrier's ($1.85/mi, 110 deadhead miles, $160 fixed, 22% target margin) never appear on the wire; the test suite asserts that. They converge at $2,215 — $2.84/mi — in five rounds, the carrier having moved the pickup window two hours later to match truck availability.

## Scenarios

| id | what happens | refused by | reason code | guarantee would have paid? |
|---|---|---|---|---|
| `happy-path` | converge, both sign, venue records, guarantee attaches | — | — | attached: $2,215 covered, $35.21 premium |
| `insurance-lapsed` | credential valid; insurer files BMC-91X cancellation after onboarding, before tender | `venue.identity` | `INSURANCE_LAPSED` | No — refused before commitment; an uninsured accident is excluded anyway |
| `spoofed-carrier` | attacker presents the real carrier's USDOT/MC *and* genuine credential id, signs with own key | `venue.identity` | `IDENTITY_KEY_MISMATCH` | Yes — impersonation is the covered peril; caught, so no loss |
| `double-brokering` | committed carrier re-tenders the same physical load (new reference) to an unverified party | `venue.routing` | `DOUBLE_BROKERING_ATTEMPT` (+ `NO_BROKERAGE_AUTHORITY`, `COUNTERPARTY_UNVERIFIED`) | Yes for the original broker, had the venue missed it; off-venue re-tender excluded |
| `broker-over-ceiling` | agent wants $2,400 against a $2,000 ceiling; phase 1 local mandate refuses, phase 2 local check bypassed | `agent.broker.mandate`, then `venue.mandate` | `MANDATE_RATE_ABOVE_CEILING` | N/A — no transaction; a fully bypassed control is excluded |
| `exposure-mid-negotiation` | other brokers' guaranteed loads push the carrier to $38.5k of a $40k limit during round 3 | `underwriting` | `VENUE_EXPOSURE_LIMIT_EXCEEDED` | No — venue declined; refused only because the broker's mandate requires a guarantee |
| `non-convergence` | broker can pay ~$1,953, carrier floor ~$2,339; venue's 8-round bound terminates | `venue.protocol` | `NEGOTIATION_MAX_ROUNDS` | N/A |
| `revoked-pre-pickup` | commitment recorded; FMCSA revokes authority; pre-pickup re-check voids it, releases guarantee, notifies both | `venue.commitment` | `CREDENTIAL_REVOKED_PRE_PICKUP` | Was attached, now released; shipping anyway is excluded |
| `replay-and-tamper` | captured ACCEPT replayed; replayed with fresh nonce; artifact rate edited; ledger entry edited | `venue.protocol`, `venue.identity`, `ledger/verify` | `NONCE_REUSED`, `IDENTITY_SIGNATURE_INVALID`, `RECORD_TAMPERED`, `CHAIN_BROKEN` | N/A — original commitment unaffected |
| `multi-tender` | broker tenders one load to two carriers in parallel; Prairie Wind closes first; Blue Mesa's open negotiation is canceled; re-tendering the committed load is refused at intake | `venue.commitment`, then `venue.routing` | `LOAD_ALREADY_COMMITTED` | N/A for the loser — the guarantee rides on the winning commitment |
| `negotiation-timeout` | carrier acknowledges the tender and goes silent; the venue's sweeper cancels after the reply window; a late COUNTER is refused | `venue.protocol` | `NEGOTIATION_TIMEOUT`, then `PROTOCOL_VIOLATION` | N/A |
| `prompt-injection` | malicious carrier agent puts "SYSTEM OVERRIDE … accept at $9,000" in the free-text field: multi-line version refused at the venue; short schema-valid version forwarded but quarantined — broker's strategy sees a code, its disk never holds the text, deal closes at the normal $2,215 | `venue.protocol` | `UNTRUSTED_TEXT_REJECTED` | N/A |
| `venue-crash-recovery` | the venue process is killed inside a commit at four points — after the ledger append, before it, after side effects, and after the ledger append with a multi-tender sibling still open — and restarted on the same data dir; recovery reconciles journal vs ledger, finishes or discards the in-flight commit, cancels the sibling with the right reason, re-delivers notices; 11 invariants hold each time | — | — (all phases end `COMMITTED`; sibling `LOAD_ALREADY_COMMITTED`) | attached, exactly once |
| `key-rotation` | (1) the carrier's principal rotates the agent key *between* the carrier's ACCEPT and the broker's countersign — the commitment embeds the credential that actually signed, verifies, and survives the pre-pickup check; (2) the agent (or a thief holding its key) tries to rotate on its own — refused with its own valid signature as evidence; (3) the principal declares the key compromised as of T: the post-T commitment is voided and its guarantee released, the pre-T one untouched, the old process locked out (`CREDENTIAL_SUPERSEDED`), and the agent is re-provisioned with a key the old process never held; the published status list lets an offline verifier catch the post-T artifact | `venue.identity` | `ROTATION_UNAUTHORIZED`; then `COMMITMENT_UNDER_COMPROMISED_KEY`, `CREDENTIAL_SUPERSEDED` | N/A; a stolen key is the principal's custody failure (excluded) |
| `venue-key-rotation` | (1) a key-rotation commit whose certificate is signed by anyone but the operator's root is refused; (2) the operator rotates the venue's operational key mid-negotiation — agents learn the new key from the root-signed history on first sight, old credentials still verify, the ledger verifies from the root alone across the rotation; (3) the operator declares the key compromised as of T: credentials issued after T are re-issued, commitments attested after T re-attested, ledger entries after T resealed; an offline verifier with the published history rejects the un-remediated artifact and accepts the remediated one | `venue.identity` | `VENUE_KEY_ROTATION_UNAUTHORIZED`; then `VENUE_KEY_UNTRUSTED` (offline) | — |
| `venue-crash-notification` | after the commit point: the countersigning party reads the outcome from the venue's synchronous reply; with the venue's push held back the other party pulls `tasks/get`; released push is deduped by message id. Then a measured 2.2s outage mid-negotiation is credited back to the slow carrier's reply clock instead of cancelling it as `NEGOTIATION_TIMEOUT` | — | — | attached |

Each scenario prints the wire log, the refusal with evidence, the audit entries by file and sequence number, and PASS/FAIL against its expectation. Refusals distinguish `FAILED` (a check failed) from `CANCELED` (nothing was wrong with this negotiation — it was overtaken or timed out).

## Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │                   venue/                     │
   broker process        │  ingest ─► identity ─► protocol ─► mandate    │       carrier process
  ┌──────────────┐       │     │        │   ▲        │           │       │      ┌──────────────┐
  │ agentkit     │──────►│     │   identity/  │   state machine   │       │◄─────│ agentkit     │
  │  runtime     │  A2A  │     │   (registry, │   (rounds, terms  │  A2A  │      │  runtime     │
  │ mandate/     │◄──────│     │   issuer,    │    hash, accept)  │       │─────►│ mandate/     │
  │  engine      │       │     │   verifier)  │        │          │       │      │  engine      │
  │ strategy.ts  │       │     ▼              │        ▼          │       │      │ strategy.ts  │
  │ private.json │       │  underwriting/ ◄───┘   ledger/         │       │      │ private.json │
  │ own key      │       │  (risk, price,        (hash chain,     │       │      │ own key      │
  │ own audit    │       │   exposure)            signed artifact)│       │      │ own audit    │
  └──────────────┘       └──────────────────────────────────────────────┘      └──────────────┘
        │                                                                              │
        └──── knows: venue URL, own principal's public key ── nothing about the other ─┘
```

| directory | role |
|---|---|
| `src/protocol/` | Wire layer, shared and stateless: canonical JSON, Ed25519/JWS, A2A shapes (Agent Card, Message, Task, JSON-RPC), the freight negotiation vocabulary, message envelopes, the venue key hierarchy (root-signed certificates, revocations, resolver), reason codes, audit entries. |
| `src/identity/` | Mock FMCSA registry (L&I schema: BMC-91X/34/84 filings, authority records, cancellation dates), credential issuer with expiry, revocation, and principal-authorized key rotation (lineage, grace window, compromise time), three-layer verifier (credential → presentation → live registry) plus historical signature trust, vetting-provider stub. |
| `src/mandate/` | Principal-signed mandates and envelopes, the policy engine (rate floor/ceiling per load and per mile, lanes, equipment, insurance minimums, per-counterparty and daily exposure, guarantee requirement, tender authority, round bound), exposure book. |
| `src/agentkit/` | The agent runtime — equivalent of an A2A SDK. Accepts inbound only from the venue, validates it against the closed schema, guards every outbound offer/accept with the mandate engine, quarantines counterparty free text from the strategy, keeps its own audit/exposure/task state. `prompting.ts` is the one sanctioned way to render a negotiation for an LLM. |
| `src/agents/broker/`, `src/agents/carrier/` | The two agents: process entry + private strategy. Import nothing from each other or from the venue side (enforced by `test/boundaries.ts`). |
| `src/venue/` | The service in the middle: onboarding, per-exchange verification, routing with attested enrichment, negotiation state machine, envelope enforcement, commitment assembly, pre-pickup re-verification, per-recipient redaction, agent and venue key rotation, crash recovery. `keyring.ts` holds the operational key and the root's certificates; never the root's private half. |
| `src/underwriting/` | Parameterized loss model (named factors), guarantee scope/exclusions/conditions, quote → attach → release lifecycle, per-counterparty / per-pair / portfolio exposure. |
| `src/ledger/` | Hash-chained, venue-signed, fsync'd append-only log — one entry is the commit point and carries the guarantee; `KEY_ROTATION`, `RESEAL` and `REATTESTATION` entries make the chain verifiable from the venue root alone across key changes; self-contained commitment artifact with additive attestations; independent verifier (library + CLI). |
| `src/edi/` | Commitment → rate confirmation and X12 850/855/856 segment outline. |
| `src/sim/` | Process harness (spawn, kill, restart, re-provision an agent with a new key; acts as each principal's key-management system and as the venue operator's root-key custody), fixtures, sixteen scenarios, transcript renderer, CLI. |
| `test/` | Identity and mandate refusal tests, ledger/protocol tests, the no-shared-state proof, scenario acceptance. |

### Wire protocol

A2A shapes are emulated, not reinvented: signed Agent Cards at `/.well-known/agent-card.json` (JWS with embedded JWK), `message/send` and `tasks/get` over JSON-RPC 2.0, Messages with DataParts, Tasks with the A2A state vocabulary (`submitted / working / completed / failed / rejected / canceled`). Freight content rides in a DataPart under a declared extension URI; signatures ride in `metadata`.

Two signatures can sit on a message:

- `metadata.sig` — the originating agent's detached JWS over the message *excluding* anything the venue adds.
- `metadata.venueSig` — the venue's detached JWS over the message *including* the agent's signature and the venue's attachment (`metadata.venue`: task/context ids, round, and the sender's verified identity, credential id, public key and current insurance).

The venue never mutates a signed message; it only adds. Agents accept inbound only with a valid `venueSig` against the venue key they pinned at startup, and additionally verify the counterparty's `sig` against the key the venue attested. A message sent from one agent directly to the other is refused as `ENVELOPE_NOT_FROM_VENUE`; the isolation test does exactly that.

**Closed wire schema.** Every agent-originated payload is validated (`protocol/freight.ts → validateNegotiationPayload`) by the venue on ingest and by agents on receipt: known keys only per message type; `noteCode` and `reasonCode` are enums; every string leaf — remark, commodity, city, reference — is single-line, bounded, and free of control, bidi and zero-width characters; identifiers match their formats. One optional free-text field (`text`, ≤140 chars) survives because real negotiations carry "dock closes 16:00"-type remarks, but it is **untrusted by construction**: the `NegotiationView` handed to a strategy has no text field at all, the runtime records only a hash, and `agentkit/prompting.ts → viewToPromptContext()` — the one sanctioned way to put a negotiation into an LLM prompt — renders codes and numbers only. The venue's wire log keeps the text verbatim for forensics. Violations are refused as `UNTRUSTED_TEXT_REJECTED`.

**Commit transaction.** A commit touches the ledger, the guarantee book, four exposure books, the commitment record, sibling negotiations, audit, and two notices. It runs as: prepare (pure) → write-ahead journal (atomic) → **one durable ledger append, which is the commit point and carries the guarantee** → apply side effects, each idempotent by commitment id (guarantee, exposure, commitment record, task state, multi-tender sibling cancellations, audit entries, notices into the outbox) → one atomic snapshot write → delete journal → flush the outbox. On startup the venue recovers before it serves: journals with a ledger entry are re-applied, journals without one are discarded, tasks holding both acceptances are re-committed, siblings of every ACTIVE commitment are reconciled, and every open task's reply clock is shifted by the measured downtime (a heartbeat rides in the snapshot) so the venue's silence is never charged to the party it was waiting on. `venue/service.ts → commit()`, `applyCommit()`, `recover()`; `venue/state.ts`.

**After the commit point, how the parties find out.** The ledger is the source of truth; notification is not. Three paths, all idempotent and all exercised by `venue-crash-notification`: (1) **sync ack** — the A2A `Task` the venue returns to the party whose message completed the commit already carries the venue-signed COMMITTED notice in `status.message`, and the runtime processes it on the spot; (2) **pull** — an agent whose send was retried and answered `NONCE_REUSED` (the venue processed the original before the connection died) immediately pulls `tasks/get`, and a reconcile timer pulls every locally-OPEN task; (3) **push** — the persisted outbox delivers at-least-once with per-recipient ordering and backoff, abandons to a dead-letter queue after `VENUE_OUTBOX_MAX_ATTEMPTS`, and the wire log records a delivery only once it has happened; agents dedupe by message id. `agentkit/runtime.ts → send()`, `pullTask()`, `reconcile()`.

**Key rotation.** A credential binds an agent key to a registry entity; the key will need to change — routinely, at renewal, or because it leaked. `venue/rotate` issues a successor credential (same agent id, entity, envelope; `supersedes` records lineage) and marks the old one `SUPERSEDED`. **Authority to rotate is never the agent's own key**: it is the principal key registered in the mandate envelope, or proof of control against the registry — so a thief holding the agent key cannot rebind it to themselves. A routine rotation leaves a grace window in which in-flight messages signed by the old key are still accepted; a `COMPROMISE` rotation records `compromisedAt`, accepts nothing further from the old key, and voids every ACTIVE commitment the old key signed at or after that time (`COMMITMENT_UNDER_COMPROMISED_KEY`, guarantee released). Commitment artifacts embed the credential that *signed* each acceptance, and the pre-pickup check judges standing by the party's *current* credential and signatures by whether they predate any declared compromise — so rotation never voids a deal by itself. The venue publishes its credential status list at `/.well-known/credential-status.json`; `npm run verify -- … --status-list` uses it to catch a signature made under a key later declared compromised, which is invisible offline otherwise. `identity/issuer.ts → rotate()`, `identity/verifier.ts → signatureTrustedAt()`, `agentkit/runtime.ts → rotatePrepare()/rotateSubmit()`.

**Venue key hierarchy.** The venue's *operational* key signs credentials, every forwarded message, every ledger entry and every attestation. It is certified by an offline **root** held by the venue operator — the venue process writes the root's private half once at first start for the operator to take custody of and never reads it back (`venue/keyring.ts`). Agents and verifiers **pin the root** (trust-on-first-use from the venue's agent card, which carries `metadata.venueKeys`), and accept any operational key that has a root-signed certificate: agents refresh from `/.well-known/venue-keys.json` when they meet an unfamiliar kid; the ledger carries certificates in `GENESIS`/`KEY_ROTATION` entries so `verifyChain` needs only the root; artifacts embed the certificates for every venue kid they reference. **The venue process cannot certify its own successor**: `venue/key-rotation/prepare` generates the next key, the operator's root signs its certificate, `venue/key-rotation/commit` installs it — the `KEY_ROTATION` entry is the successor's first signature and its authority is the certificate it carries. A compromise is a root-signed revocation with `compromisedAt`; the venue then re-issues credentials it signed after that time (same id, `signedAt` updated), re-attests commitments attested after it, and appends a `RESEAL` affirming the ledger entries the old key signed after it. Anything signed by a compromised key after its compromise time is untrusted until re-signed — `VENUE_KEY_UNTRUSTED` — and, as with agent keys, that is invisible to an offline verifier without the published history. `protocol/venue-keys.ts`, `venue/keyring.ts`, `venue/service.ts → keyRotationCommit()`, `applyKeyRotation()`.

**Negotiation lifecycle rules.** One A2A task per (load, counterparty). A broker may tender the same load to several carriers at once; the first commitment recorded wins and the venue cancels the rest (`LOAD_ALREADY_COMMITTED`), telling losing carriers only that the load went elsewhere. A load with an ACTIVE commitment cannot be tendered again until that commitment is voided. Every task tracks whom it is waiting on and since when; a sweeper cancels tasks whose awaited party has been silent longer than `VENUE_REPLY_TIMEOUT_MS` (default 120s), naming the silent party (`NEGOTIATION_TIMEOUT`). Terminal tasks accept nothing further.

### What the venue sees

Terms, on every message: rate, lane, windows, equipment, payment terms. Not private context. The wire vocabulary is closed (`protocol/freight.ts`) and tested. See `DECISIONS.md` Q5 for why terms rather than attest-only, and Q2 for what the venue tells each party about a refusal.

### Commitment artifact

A commitment is formed when the venue holds ACCEPT messages from both parties over the same `termsHash`. The artifact bundles both signed ACCEPTs, both credentials (each binding a key to a registry entity, signed by the venue's issuer key of the time), the root-signed certificates for every venue key it references, the underwriting decision, a ledger position, and one or more venue attestations over the content. `npm run verify` checks ~26 properties from the file alone — pin the venue root, and pass the ledger file, key history and credential status list to also check chain integrity, inclusion, and compromise-before-signing for both venue and agent keys. Either party keeps its own copy (`<agent-dir>/commitments/`).

## What is real, what is stubbed

**Real (works as it would in production, modulo scale):**

- Ed25519 signing, JWS (RFC 7515 compact, EdDSA), JWK thumbprints, canonical JSON. Nothing is faked; signatures verify with any standard library.
- Process isolation: three OS processes, three data directories, agents configured with only their own directory and the venue URL. Verified statically (import graph) and at runtime (canaries, wire vocabulary, direct-contact refusal, private keys never cross).
- Credential lifecycle: issuance against registry evidence, expiry, revocation, principal-authorized rotation with lineage / grace / compromise time, three-layer verification on every exchange, live re-check at tender / commit / pre-pickup, published (signed) status list for offline verifiers.
- Venue key hierarchy: operator-held root, root-certified operational key, operator-driven rotation and compromise remediation (re-issue, re-attest, reseal), chain and artifact verification from the root alone.
- Mandate engine and its two-layer enforcement (local + venue envelope), both principal-signed.
- Negotiation state machine, round bound, reply timeout with sweeper, first-commit-wins multi-tender, terms-hash consistency, nonce/timestamp replay protection, per-recipient redaction.
- Crash-safe commit: write-ahead journal, single durable commit point, idempotent apply (including sibling cancellation and audit), atomic snapshot with heartbeat, persisted outbox with dead-letter, startup recovery with downtime credit — demonstrated by killing the venue at four points inside a commit.
- Outcome delivery that does not depend on push: sync ack in the A2A reply, pull via `tasks/get` after a retried send, reconcile timer, push dedupe by message id.
- Closed wire schema with free text bounded on the wire and quarantined from the decision path; enforced at both the venue and the agent.
- Hash-chained ledger and self-contained artifact verification without the venue.
- Underwriting *interfaces*: pure quote → idempotent attach → idempotent release, exposure per counterparty / pair / portfolio, guarantee scope embedded in the artifact.
- Agent negotiation logic with genuine private economics that converge or stalemate for real reasons.

**Stubbed (interface is real, implementation is a placeholder — each is marked `STUB` in source):**

- **FMCSA registry** — a JSON file with a faithful L&I schema. Production reads FMCSA's L&I / QCMobile feeds or a vetting provider's normalized feed. `identity/registry.ts`
- **Proof of control at onboarding** — a token in the fixture standing in for a challenge to the FMCSA-registered email/phone, or a vetting provider's verified-identity assertion. `identity/issuer.ts`
- **Vetting provider** — returns flags from the fixture. Highway / MyCarrierPortal / Carrier Assure / Carrier411 plug in here. `identity/vetting.ts`
- **Loss model coefficients** — illustrative, not fitted. The factor structure is the deliverable. `underwriting/model.ts`
- **Guarantee backstop** — there is no insurer or capital behind the guarantee record. `underwriting/engine.ts`
- **Revocation feed** — revocations are injected by the simulator; production subscribes to FMCSA authority/insurance changes. `venue/server.ts` admin routes
- **Scheduler** — pre-pickup re-verification is triggered by the simulator rather than a job. `venue/service.ts → prePickupChecks()`
- **EDI** — segment-level outline of 850/855/856 and a rate-confirmation object, not an X12 serializer. Motor-carrier sets (204/990/214) map the same way. `edi/mapping.ts`
- **Payments** — none. AP2 would attach at the COMMITTED event.
- **Agent reasoning** — deterministic strategies, not LLMs. The `Strategy` interface is where an LLM-backed agent would sit; the mandate guard wraps it either way.

**Simulation-only surfaces** — never present in a deployed system: `/admin/*` on the venue and `/control/*` on agents (gated by `SIM_MODE=1`), and the `rogue` fault-injection block in agent config.

## What breaks first at scale

In the order it would hurt:

1. **JSON-file state under concurrency.** Every task, nonce and commitment lives in one snapshot that is rewritten atomically on every change — crash-safe, but a throughput ceiling: writes are serialized and the whole snapshot is rewritten per message. The commit protocol (journal → ledger → idempotent apply) is the right shape and survives the move; the storage does not. First move: a database with row-level locking on the exposure book and task rows, keeping the ledger append as the commit point; nonces to a TTL store.
2. **Synchronous delivery.** The venue delivers by HTTP POST to the agent's endpoint and awaits the ack. An unreachable agent stalls the handler. Needs a durable outbox with retries and A2A push notifications (`capabilities.pushNotifications`).
3. **Nonce set growth and clock skew.** The seen-nonce map grows forever and the ±5-minute timestamp window assumes synced clocks. Needs a TTL and a skew policy.
4. **Key custody.** Every private key is a JWK file on disk. The *protocols* exist — agent keys rotate under the principal's authority, the venue's operational key under the operator's root, both with compromise semantics — but the authorizing keys (each principal's, the venue root) are generated and held by the simulator. In production the principal key lives in the principal's KMS/SSO-backed signing flow, the venue root in an HSM behind a ceremony, and the operational key in a KMS. The root itself has no rotation path (a root rotation is a re-pinning event for every agent and verifier, and belongs to an out-of-band ceremony).
5. **Status propagation.** The credential status list (signed by the venue) and the venue key history (every entry root-signed) are published at well-known URLs and the artifact verifier consumes both, which is what lets a verifier months later judge a signature *at signing time*. Neither is timestamped by a third party, so an offline verifier cannot tell a stale copy from a current one (OCSP-style freshness is missing).
6. **The ledger file.** A JSONL hash chain is verifiable but not queryable, not replicated, and not publicly auditable. Production needs replication, a public transparency log (or periodic root publication) so inclusion proofs work without trusting the venue's copy, and a query layer.
7. **Underwriting.** Exposure accounting is single-threaded and idempotent, which is a feature until it isn't; the model needs fitting on real losses; the guarantee needs a capital reserve and a dispute/claims process that does not exist here.
8. **Registry freshness.** Live checks read a local snapshot. Real L&I data lags insurer filings by days; the venue must decide what "as of now" means and price the gap.
9. **Onboarding fraud.** Proof of control is the gate that keeps a fraudster from binding a key to a real carrier's MC. The stub token is the weakest link in the prototype and the hardest problem in the real system.

## Reason codes

All refusals use codes from `src/protocol/reasons.ts`, grouped: identity (`IDENTITY_*`, `CREDENTIAL_*`, `AUTHORITY_*`, `INSURANCE_*`, `ONBOARDING_*`), mandate (`MANDATE_*`), protocol and routing (`PROTOCOL_VIOLATION`, `UNTRUSTED_TEXT_REJECTED`, `NONCE_REUSED`, `MESSAGE_STALE`, `ENVELOPE_NOT_FROM_VENUE`, `TERMS_HASH_MISMATCH`, `NEGOTIATION_*` (max rounds, walkaway, timeout), `LOAD_ALREADY_COMMITTED`, `DOUBLE_BROKERING_ATTEMPT`, `NO_BROKERAGE_AUTHORITY`, `COUNTERPARTY_UNVERIFIED`, `REPLAY_DETECTED`, `RECORD_TAMPERED`, `CHAIN_BROKEN`), underwriting (`UNDERWRITING_DECLINED_RISK`, `VENUE_EXPOSURE_LIMIT_EXCEEDED`, `VENUE_PORTFOLIO_LIMIT_EXCEEDED`), post-commitment (`CREDENTIAL_REVOKED_PRE_PICKUP`). Every audit entry names its component, its reason code, and its evidence.

## Decisions

The five open questions — who pays, neutrality, guarantee trigger, federated vs. centralized, and whether the venue sees negotiation content — are argued both ways in [`DECISIONS.md`](DECISIONS.md), each with a choice, the strongest case against it, and the evidence that would change it.
