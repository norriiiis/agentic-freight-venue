# Decisions

Five open questions, each argued both ways, with a choice, the strongest argument against it, and what evidence would change the choice. Where the prototype embodies a decision, the code location is named so the decision can be checked against what was built rather than what was claimed.

---

## 1. Who pays, and on what basis?

**Choice: the broker pays, per transaction, a risk-priced percentage of guaranteed value (the guarantee premium) plus a small flat venue fee. Carriers pay nothing per transaction; a credentialed carrier account is free.**

In the prototype: `underwriting/model.ts` prices the premium as expected loss × load factor + flat fee. On the demo load ($2,215, a nine-year carrier with venue history) that is $35.21 — 1.6% of guaranteed value. A four-month-old carrier with virtual-office and phone-change flags prices at roughly 5× that. The beneficiary of every guarantee is the broker (`venue/service.ts` → `quoteFor()` passes the broker's USDOT as beneficiary).

**Why.**

- The loss lands on the broker. In carrier impersonation the broker pays the impersonator and still owes the real carrier; in double-brokering the broker faces the shipper's cargo claim and often pays twice. The ~$800M cited at the 2026 Freight Fraud Symposium is overwhelmingly broker- and shipper-side loss. Willingness to pay follows the loss.
- Percentage-of-guaranteed-value pricing ties revenue to the exposure the venue actually takes. A flat per-transaction fee would underprice the risky loads and overprice the safe ones, which is exactly backwards for a party that is standing behind the transaction.
- Free carrier side is an adoption requirement, not a preference. Carriers are fragmented (most run fewer than five trucks), price-sensitive, and already resent the vetting portals brokers make them fill out. The credential does have value to a carrier — no repeated onboarding packets, faster tenders — but charging for it at launch would starve the supply side.
- Precedent: PaymentWorks charges the paying enterprise; vendors join free. Highway, MyCarrierPortal and Carrier Assure are broker-paid. SAP Business Network's supplier tiers exist, but on top of a buyer subscription.

**Strongest argument against.**

- A one-sided fee makes this the broker's tool in fact regardless of what the architecture says (see Q2). Free supply also attracts low-quality supply: fraud rings onboard for free too. Proof of control and the registry root limit this, but do not eliminate it.
- Percentage-of-value pricing invites adverse selection. A broker will route only the loads it is nervous about through the guaranteed path and keep the safe loads off-venue. The guaranteed book then skews toward risk, and the pooled loss data (Q4) becomes unrepresentative. A subscription that covers all of a broker's loads fixes this and is what SAP Ariba's model looks like.
- Carriers do pay for one thing: getting paid. They give up 1–3% to factoring and quick-pay programs. A carrier-side payment guarantee ("the broker will pay, or the venue will") is a product carriers would buy, and it would make the venue two-sided in a way the current design is not.

**Evidence that would change the choice.**

- Adverse selection: if after six months the guaranteed book's loss ratio is more than twice the loss ratio of the same brokers' unguaranteed volume, move to subscription with all-loads coverage.
- Carrier willingness to pay: if a carrier-side payment-guarantee pilot converts more than ~10% of credentialed carriers at ≥0.5% of load value, add the carrier side and price the venue as a two-sided market.
- Broker friction: if enterprise brokers refuse per-transaction fees in procurement, offer a subscription tier (with the same risk-priced premium inside it).

---

## 2. Is the venue neutral, or the broker's tool?

**Choice: neutral by architecture, broker-paid by economics — and because the economics pull one way, the architecture has to carry the weight.** A claim of neutrality is worthless; only enforced symmetry is credible.

**What the architecture enforces.**

1. **Symmetric protocol.** Either party may initiate. `agentkit/runtime.ts → tender()` is role-agnostic; the venue checks *brokerage authority in the registry* (`liveCheck → brokerAuthority`), not which side you are. Blue Mesa Carriers in the fixture holds both carrier and broker authority and could tender as either.
2. **Same engine, same code path, both sides.** The venue evaluates the accepting party's registered mandate envelope with the same `evaluateMandate(envelopeToLimits(env))` regardless of side (`venue/service.ts → advance()`). There is no broker-only or carrier-only check.
3. **The venue cannot alter terms.** A commitment requires both parties' Ed25519 signatures over the same `termsHash`. The venue's attestation is a third signature on top. `ledger/artifact.ts → verifyArtifact()` verifies both party signatures against credential-bound keys without the venue; the carrier can prove what it agreed to even if the venue is gone or hostile. The `replay-and-tamper` scenario shows the venue's own ledger failing verification when edited.
4. **Attested facts flow both ways.** Every forwarded message carries a venue attachment with the *sender's* verified identity and insurance (`protocol/envelope.ts → VenueAttachment`). The carrier sees the broker's BMC-84 bond status on every message, exactly as the broker sees the carrier's BMC-91X.
5. **Refusals are redacted per recipient.** The party a refusal is *about* gets the full evidence; the counterparty gets the reason code and a `concerning:` pointer (`venue/service.ts → fail()`, `redactForCounterparty()`). A broker's mandate ceiling cannot leak to a carrier through a refusal notice, nor a carrier's other guaranteed loads to a broker. Writing this document is what surfaced that bug; the `exposure-mid-negotiation` scenario now reports what each party was told.
6. **Closed wire vocabulary.** `test/isolation.test.ts` asserts that every message on the wire contains only the negotiation vocabulary — no private-context field names, no canary secrets — so neither side can be harvested by the venue or the counterparty.
7. **Public rules.** Reason codes are an enumerated, published set (`protocol/reasons.ts`). The venue key is published; artifacts verify without the venue.

**Strongest argument against.**

Whoever pays sets the roadmap. The guarantee protects the broker (beneficiary) and not the carrier; the mandate envelope asks carriers to disclose a coarse floor to a broker-funded entity; carriers have no leverage over the venue's rules. The honest position is that until a carrier-side product exists (payment guarantee, Q1), the venue is neutral in mechanics and asymmetric in who it protects. Highway and MyCarrierPortal are openly broker tools and do fine.

**Evidence that would change the choice.**

- If carrier-initiated tenders (capacity postings) stay under ~5% of volume a year after launch, the venue is a broker tool in fact and should be positioned as one — simpler, and more honest.
- If carriers ask for and will pay for a payment guarantee, neutrality becomes real and the venue should be governed as two-sided (e.g., a carrier seat on the rules committee).

---

## 3. What does the guarantee trigger on?

**Choice: identity failure only — impersonation, double-brokering through the venue, and credential misbinding — and only where the venue's own controls functioned as designed. Non-performance is excluded.** It is contractual indemnification, not insurance: a promise backed by venue capital and an insurance partner, not a regulated policy. (PaymentWorks' scoping is the precedent, and its narrowness is the point.)

In the prototype: `underwriting/types.ts` → `GUARANTEE_SCOPE`, `GUARANTEE_EXCLUSIONS`, `GUARANTEE_CONDITIONS` ride inside every commitment artifact. `venue/guarantee-outcome.ts` states, for every refusal code, whether the guarantee would have paid, and the simulator prints it for each scenario.

**Underwritable (by this venue):**

- **Identity fraud.** Binary, evidence-rich (the artifact and audit trail decide the claim), and the venue *controls the probability* — better verification means fewer losses. The venue underwrites its own process, which is the only thing it can actually price.
- **Double-brokering through the venue.** Same reasoning: the load fingerprint match in `startNegotiation()` is the control; if it fails, that is the venue's failure.
- **Credential misbinding.** If the venue bound a key to the wrong registry entity, that is entirely the venue's error.

Loss severity is bounded by load value, claims are adversarial only against fraudsters (never against the honest counterparty), and the venue's per-counterparty and portfolio exposure limits (`underwriting/engine.ts`) cap the tail.

**Not underwritable (by this venue):**

- **Service failure** (late, no-show). High frequency, messy adjudication, and the venue has no control over it. Pricing it means pricing carrier operations, which the venue cannot observe.
- **Cargo loss or damage.** Already covered by the carrier's BMC-34 cargo filing and Carmack liability. Duplicating it adds cost and subrogation fights.
- **Off-venue arrangements.** Unobservable; the `double-brokering` scenario is explicit that a re-tender *off* the venue is excluded, and the artifact is the broker's evidence for a claim against the carrier.
- **Broker payment default.** Underwritable in principle (bond + venue history make it priceable), but it is a credit product with different capital, and it belongs to a carrier-side offering (Q1), not this guarantee.

**Strongest argument against.**

Brokers want one promise: "this load will be fine." Identity-only coverage sounds thin next to a competitor who says "coverage" loosely. The boundary cases are ugly: a double-brokered load that is also late — which peril? A carrier whose insurance lapsed the day of pickup — the `insurance-lapsed` scenario says the guarantee would not have paid even if the venue had missed it, and a broker will find that unsatisfying. Narrow scope protects the venue's loss ratio at the cost of the sales conversation.

**Evidence that would change the choice.**

- Loss composition: if identity-type losses (impersonation, double-brokering) are under ~30% of broker fraud losses by dollar, identity-only coverage will not sell and the product needs a non-performance rider priced separately.
- Observability: if telematics/ELD integration lets the venue adjudicate no-shows cheaply and objectively, non-performance becomes underwritable and the scope should widen.
- Claims data: if more than a small fraction of claims fall into the "controls functioned as designed" gray zone, the condition is doing too much work and should be replaced by explicit per-control warranties.

---

## 4. Federated (no pooled data) or centralized (pooled)?

**Choice: centralized identity, commitment ledger and outcome history; federated negotiation context.** The venue pools *who committed with whom, when, at what rate, and what happened*. It never pools private context (costs, margins, strategy), and the registered mandate envelope is a compliance ceiling, not the reservation price.

In the prototype: the venue's state (`venue/state.ts`, `underwriting/engine.ts`) holds commitments, exposure and history across all parties; each agent's `private.json` and strategy never leave its process (`test/isolation.test.ts`).

**What is actually lost by staying fully federated.**

1. **Velocity signals.** The same carrier committing to six loads in four hours from six brokers is *the* double-brokering tell, and only pooled commitments can see it. The per-counterparty exposure book that drives the `exposure-mid-negotiation` scenario is exactly this signal; a federated venue could not have refused that commitment.
2. **History-based risk scoring.** Without pooled outcomes, underwriting collapses to public registry features (authority age, insurance, safety rating) — which is what Carrier Assure already sells. The `history` factor in `underwriting/model.ts` is the only feature the incumbents cannot replicate.
3. **Fraud-ring linkage.** Shared phone numbers, addresses, agent keys and bank accounts across entities are visible only in pooled identity data.
4. **Benchmarking.** Lane rate benchmarks fall out of pooled terms. This is listed as a loss but should be treated as a product to *avoid*: rate benchmarking among competing brokers through a shared venue is information-sharing that invites antitrust scrutiny.

**Strongest argument against.**

Pooled rate data is a honeypot — a breach exposes every broker's book at once. Pooling turns the venue into the kind of data moat (Highway, MyCarrierPortal) that brokers already distrust and that large brokers with their own data science will refuse to feed. A federated design — each broker keeps its own history, the venue only verifies identity and attests commitments — is easier to sell to exactly the customers with the most volume, and it removes the venue from the information-sharing question entirely.

**Evidence that would change the choice.**

- If, in a twelve-month backtest, pooled features (velocity, cross-broker history) do not improve loss prediction over registry-only features by a meaningful margin (say AUC lift under 0.05), pooling is not worth the liability.
- If the two or three largest brokers refuse to onboard because of pooling, ship a federated tier: identity + attestation, no history-based pricing, and no guarantee — and see whether they miss the guarantee.

---

## 5. Does the venue need to see negotiation contents, or only attest to outcomes?

**Choice: the venue sees the *terms* on every message — rate, lane, dates, equipment, payment terms — not just the final outcome. It never sees private context. Attest-only is rejected for now.**

In the prototype: every message passes through `VenueService.ingest()`; the DataPart is a closed vocabulary (`protocol/freight.ts`), and the isolation test asserts nothing else is on the wire.

**Why it needs terms mid-negotiation, not just at commitment.**

1. **Mandate enforcement on offers.** The `broker-over-ceiling` scenario's second phase — a compromised agent runtime bypasses its local mandate — is caught by the venue at the *tender*, before a carrier has spent rounds on it. An attest-only venue would catch it only at commitment, after the carrier had already committed capacity.
2. **Guarantee quote before countersign.** The countersigning party's mandate may require a guarantee (the broker's does). The venue quotes at the first ACCEPT and carries `guaranteeAvailable` in the attachment so the countersigner's mandate engine can decide. That requires the terms at first-accept time.
3. **Exposure accounting.** Refusing the `exposure-mid-negotiation` commitment requires the rate at accept time and the exposure book at that moment.
4. **Protocol enforcement.** Round bound, state machine, and `termsHash` consistency between the two ACCEPTs all require seeing message types and terms.
5. **Attested counterparty facts.** The venue's real-time value — "the party you are talking to is insured *right now*" — is delivered as an enrichment on each forwarded message. Attest-only has nowhere to put it.

**What it deliberately does not see.** Private context, strategy, and the agents' reasoning. The mandate envelope a principal registers is a coarse compliance ceiling chosen by the principal, not the agent's target; it is signed by the principal's key, which the agent does not hold, so a compromised agent cannot loosen it.

**Strongest argument against.**

Seeing terms makes the venue a rate-data honeypot and a neutrality risk (Q2 and Q4). A compromised venue leaks every broker's ceiling and every carrier's floor. An attest-only design — agents negotiate over encrypted A2A, and the venue receives only the both-signed `termsHash` plus the terms at commitment — is strictly more private and still delivers identity, commitment recording and a guarantee. What attest-only gives up: fail-fast, offer-level mandate enforcement, mid-negotiation exposure checks, and the venue attachment. It also has a structural cost: if agents negotiate directly, they must reach each other, which reintroduces exactly the agent-to-agent channel this design forbids, or requires a blind relay that sees ciphertext only.

**Evidence that would change the choice.**

- If principals decline to register mandate envelopes — i.e., they do not want the venue as a second line of defense — the main justification for term visibility disappears and attest-only wins.
- If large brokers or regulators treat term visibility as data sharing that blocks adoption.
- If the compromised-agent threat (which justifies venue-side mandate checks) turns out to be rare relative to compromised credentials — then identity, not mandate, is where the venue earns its keep, and a blind relay suffices.

---

## Two smaller decisions made along the way

**Identity root.** The venue does not mint identity. A credential binds an agent key to a USDOT/MC that already exists on public record with mandated insurance filings; the credential records the registry snapshot hash it was issued against, and the venue re-checks the live registry at tender and at commitment. The `insurance-lapsed` scenario exists to show why a credential alone is insufficient.

**Two-layer mandate.** The full mandate is enforced locally by the agent's own engine (`agentkit/runtime.ts → guard()`), which can and does refuse its own principal's agent. A coarser, separately-signed envelope is enforced by the venue. Both are signed by the principal's key, never the agent's. The local layer protects the principal from its agent; the venue layer protects the principal from a compromised runtime. The `broker-over-ceiling` scenario runs both phases.

**Multi-tender: first commitment wins.** Brokers blast one load to several carriers; that is how the market works and the protocol should not pretend otherwise. When one carrier's commitment is recorded, the venue cancels every other open negotiation for that load and refuses re-tenders while the commitment is ACTIVE (`venue/service.ts → cancelSiblings()`, `activeCommitmentForLoad()`). Losing carriers are told only that the load went elsewhere. The cost is wasted carrier effort — a carrier can negotiate five rounds for nothing — which is exactly today's experience on load boards, but a venue could do better. The alternative is exclusive tendering with a hold window (one carrier at a time, first refusal), which is fairer to carriers and slower for brokers, and it is what a carrier-side product would push toward. Evidence to switch: if losing-carrier churn is measurable, or if carriers with alternatives decline tenders that are not exclusive.

**Reply timeout: the venue decides when a negotiation is dead.** An agent that acknowledges a message and never replies would otherwise leave a task open forever and the counterparty's capacity or load in limbo. The venue cancels after a configurable silence window and names the silent party, so the other side can move on and the silence is on the record. The alternative — leaving liveness to the agents — means each principal writes its own timeout policy and the two can disagree; a venue-level rule is symmetric and auditable. The window is a real trade-off: too short penalizes agents that consult a human or a slow TMS; too long wastes the counterparty's time. 120 seconds is a guess to be replaced by observed reply-time distributions.

**Free text on the wire: bounded and quarantined, not removed.** Any prose a counterparty can send is a prompt-injection surface for an LLM-backed agent, and the first version of this skeleton carried two such fields (`note`, `reason`). Removing free text entirely is the simplest fix, and it is nearly what was done: both fields became closed enums, and the venue rejects unknown keys, unknown codes, and any string leaf anywhere in a payload that is multi-line, over-long, or carries control/bidi/zero-width characters (`protocol/freight.ts → validateNegotiationPayload`). One optional, 140-character, single-line `text` field survives, because real negotiations do carry "dock closes at 16:00" and a protocol that cannot say so will be worked around out-of-band. The safety property does not rest on the bound alone: the agent runtime never passes text to a strategy (the `NegotiationView` type has no such field), records only a hash, and `agentkit/prompting.ts` is the one sanctioned rendering of a negotiation for a model — codes and numbers only. The venue's wire log keeps the text verbatim for forensics. The strongest argument for removing the field outright is that an LLM strategy author can still reach past the SDK to the raw message; the answer is that the SDK is the only surface that receives venue-signed messages, and reaching past it is a deliberate act that the audit hash makes visible. Closing the vocabulary also fixed a leak nobody was looking for: the broker's free-text note carried its private pickup-flex hours onto the wire.

**Commit atomicity: the ledger append is the commit point; everything else is a replayable side effect.** A commitment used to be nine writes across seven files with no journal; a crash between the ledger append and the guarantee attach left a record that said "committed" without saying whether it was guaranteed, and nothing on restart could tell. The alternatives were (a) a single database transaction — the right answer at scale, but it hides the design question inside the database, and this skeleton has no database; (b) two-phase commit across the files; (c) event sourcing: make the ledger the write-ahead log and every other file a materialized view rebuilt from it. The choice is (c) in spirit with (b)'s journal: the COMMITMENT entry now carries the guarantee, so the ledger alone answers both questions; a journal written before the append lets recovery re-apply the side effects after it, and every side effect is idempotent by commitment id so re-application is harmless. The cost is that the venue's state is now rewritten as one snapshot per message, which is the first thing the README says will break. What would change the choice: a database. The protocol shape — prepare, journal, one durable commit point, idempotent apply, recover before serving — is what should survive that move, and the crash-recovery scenario is the test that should keep passing after it.

**After the commit point, notification is not the source of truth — the ledger is.** Between the ledger append and the moment both parties hold the COMMITTED notice there is always a window, and no amount of outbox engineering closes it: the venue can die, the agent can be down, the network can drop the reply. The first version of the transaction treated push (the outbox) as the only way out of that window, which meant a party's knowledge of a commitment depended on the venue's health after the commit. The choice now is that push is one of three paths, and the cheapest two do not need the venue to do anything after the commit point: the party whose message completed the commit gets the outcome in the synchronous A2A reply (the Task's status message *is* the notice), and any party can pull `tasks/get` — which the runtime does automatically whenever a retried send is answered `NONCE_REUSED`, and on a timer for anything still open. Push remains for the common case and is deduplicated by message id. The alternative — make push reliable enough to be the only path — is the classic mistake of pretending exactly-once delivery exists; the honest design is at-least-once push plus idempotent pull, with the ledger deciding. Two smaller consequences followed: sibling cancellations and audit entries moved *inside* the commit transaction, because anything a crash can separate from the commit will eventually be separated from it; and the venue now measures its own downtime from a heartbeat and credits it back to open reply clocks, because a reply-timeout rule that the venue enforces must not be triggered by the venue's own absence.
