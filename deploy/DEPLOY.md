# Deploying this, step by step

From nothing to a real load between two real companies. Six phases; the first
is the one with lead time, and the only one that cannot be hurried by working
harder. `RUNBOOK.md` beside this file is day-2: what to do once it is up.

Three things decided before any of this, and worth re-reading if they change:
no guarantee is offered, the venue operates the registry mirror and says so on
every page, and client principal keys are held by the console. Each is argued
in `../DECISIONS.md`.

---

## Phase 0 — Accounts and answers (start today; some take days)

Nothing below needs a server. Everything below blocks a later phase.

1. **FMCSA QCMobile webkey** — free, from `mobile.fmcsa.dot.gov/QCDevsite/`.
   Without it the registry serves the four fixture carriers and nothing else.
2. **The L&I insurance-history problem.** QCMobile gives insurance as
   *amounts on file*; the filings — insurer, policy number, filer, effective
   and cancellation dates — have no API, and every insurer-of-record check
   reads them. Decide now which it is:
   - buy an export from a vetting provider and feed `mapLiInsuranceRows`, or
   - launch with mandates that do **not** set `requireInsurerAttestation`
     (the default), and accept that insurance is checked at the amount level.
   Do not discover this at onboarding.
3. **CarrierOk key** — free sandbox at `developers.carrierok.com` (`sk_test_…`,
   ten fixture carriers), $50 for live. Needed for the contact-exclusivity
   check that makes proof of control sound.
4. **A transactional email provider** — Resend or Postmark, plus a domain you
   control with SPF/DKIM set. The venue sends proof-of-control codes to
   carriers; from a domain that fails SPF, a meaningful share will not arrive,
   and a challenge nobody receives looks identical to a fraudster being
   correctly refused.
5. **Two legal answers, in writing.**
   - Does your counsel agree that identity + mandates + a record, with **no
     indemnity**, is not insurance or surety in your state? The code offers
     none (`offerGuarantees:false`) and the record says `GUARANTEE_NOT_OFFERED`;
     the question is whether anything in your *marketing* re-introduces it.
   - Does arranging transportation through this venue require broker
     authority (MC) and a BMC-84 bond for **you**? You are not the broker on
     these loads, but you are in the middle of them.
6. **Pick the pilot.** Both sides, by name: at least one broker and one
   carrier who will take your call when something refuses. A broker with
   nobody to tender to is a demo.
7. **Write the disclosure you will say out loud.** The console shows it on
   every page; your sales conversation must not contradict it.

**Do not proceed until 1, 3, 4 and 6 exist.** 2 and 5 can run in parallel
with phases 1–4 but must land before phase 5.

---

## Phase 1 — A host and its secrets (about an hour)

8. One Linux host. 2 vCPU / 4 GB is comfortable for a closed pilot: three
   long-running services plus one agent process per onboarded client, each a
   small Node process. This is **not** serverless — the venue holds a ledger
   and the console supervises child processes.
9. Docker and the compose plugin. A DNS A record for the console
   (`console.yourcompany.com`).
10. TLS in front of the console. Caddy is two lines and renews itself; the
    compose file publishes the app on `127.0.0.1:4200`, so the proxy is the
    only thing the internet can reach. The venue and registry are not exposed.
11. Generate secrets and put them in `deploy/.env` (mode 600, never committed):

    ```
    VENUE_OPS_TOKEN=$(openssl rand -hex 32)
    APP_MASTER_KEY=$(openssl rand -base64 32)
    APP_BOOTSTRAP_EMAIL=you@yourcompany.com
    APP_BOOTSTRAP_PASSWORD=<20+ characters from a password manager>
    APP_URL=https://console.yourcompany.com
    APP_SECURE_COOKIES=1
    ```

    `APP_MASTER_KEY` wraps every client's principal key. If it leaks, every
    mandate those keys signed should be treated as forgeable. It belongs in a
    secret store; `.env` on the host is the minimum, and the floor, not the goal.

---

## Phase 2 — Up, on fixtures, reachable only by you (an hour)

12. `cd deploy && docker compose up -d --build`. Three services; wait for the
    registry and venue healthchecks to pass. On a host without Docker,
    `./deploy/bootstrap.sh up` runs the same three services with the same
    variables, generates `deploy/.env` on first run, and handles the ordering
    problem in step 14 for you.
13. `docker compose logs app | head -40`. It prints the bootstrap operator
    account and **the console's control-verifier key**, with the exact two
    lines to paste.
14. Paste them into `.env` and restart the venue:

    ```
    VENUE_CONTROL_METHODS=REGISTRY_CONTACT_CHALLENGE,OPERATOR_ATTESTED
    VENUE_CONTROL_VERIFIERS='[{"verifierId":"interchange-console","publicKey":{…},"methods":["OPERATOR_ATTESTED"]}]'
    ```

    Until this is done, hand-verification silently does not work — which is
    the correct failure, and an easy hour to lose if you do not expect it.
15. Sign in. Confirm the disclosure is on every page and says what you will
    say.
16. `curl -H "authorization: Bearer $VENUE_OPS_TOKEN" http://127.0.0.1:4100/ops/health`.

**Checkpoint:** you can sign in; the venue and registry are healthy; nothing
real is connected yet.

---

## Phase 3 — Real data (half a day, mostly waiting on keys)

17. Registry against FMCSA: `REGISTRY_UPSTREAM=qcmobile`, `FMCSA_WEBKEY=…`.
    Restart the registry and look up a carrier you know. Compare what it says
    to SAFER by eye. Mirrors that disagree with reality are the one failure
    the whole trust chain cannot catch, because it is the chain's root.
18. Vetting: `VETTING_PROVIDER=carrierok`, `CARRIEROK_API_KEY=sk_test_…`,
    then **before trusting it**:

    ```bash
    CARRIEROK_API_KEY=sk_test_… npm run vetting:check -- 2751903
    ```

    It reports which fields the live response actually carries and which the
    adapter needed and did not find. A missing `network_graph_count_*` means
    the venue cannot tell whether a mailbox is shared and will let challenges
    through: decide that deliberately or stop. Then swap to the live key.
19. Email: `VENUE_NOTIFY=http`, provider, token, from-address. **Send yourself
    a challenge end to end** before any carrier sees one.
20. Confirm `VENUE_CONTROL_METHODS` does **not** contain `SIM_STUB_TOKEN`,
    and that no service has `SIM_MODE=1`. The venue warns loudly at startup
    if it does; that warning is the last line of defence, not a reassurance.

**Checkpoint:** a real USDOT resolves, vetting answers, a code reaches a real
mailbox.

---

## Phase 4 — Prove it on entities you control (a day)

Do all of this with your own companies, before any client.

21. Onboard your own USDOT through the console, as a client would. You control
    that mailbox, so you can complete the challenge honestly.
22. Onboard a second entity you control, on the other side of the trade.
23. Post a load between them. Watch two agents negotiate it unattended and
    reach a commitment.
24. Download the bundle and verify it on a different machine. What the
    console hands you is the VENUE'S PART — its artifact, its ledger entries,
    its lists — because what the world says is not the venue's to supply:

    ```bash
    npm run verify -- --bundle record.json --pins pins.json          # the part, on its own
    npm run verify -- --from-venue https://… --commitment cmt_… \
                      --registry-url https://… --pins pins.json      # gathering the world's word yourself
    ```

    The second form is the one that matters, and it is a handful more checks:
    it asks the registries YOU name what they say today, rather than trusting
    a file the venue assembled. `pins.json` is `{venueRoot, registryKeys[],
    minRegistries, maxRegistryAgeMs}`; the venue root is in
    `venue-root-public.jwk.json` and the registry keys in
    `registries.pinned.json`, both in the venue's data directory.
    If it does not verify away from the venue, nothing else here is worth
    anything.
25. **Break things on purpose**, and check the refusal says something a client
    could act on:
    - answer a challenge wrongly six times (the challenge should die);
    - let a challenge expire;
    - try to onboard a USDOT already claimed;
    - revoke an authority in the registry and run the pre-pickup sweep;
    - stop the vetting container and try to onboard (it should refuse).
26. Restore a backup into a scratch host and sign in to it. A backup you have
    not restored is a hope.

**Checkpoint:** you have committed a load, verified its record off-venue, and
seen five refusals read correctly.

---

## Phase 5 — The first real client (a week, mostly theirs)

27. Invite them from **Operations**. Be on the phone while they do it.
28. Watch the five steps in their activity log. The step that fails is almost
    always proof of control, and almost always for one of two honest reasons:
    the FMCSA contact point is their filing agent's (refused as
    `CONTROL_CONTACT_NOT_EXCLUSIVE`), or it is a dead mailbox. Both are
    verified by hand, by you, with what you did typed into the record.
29. Have them set their own mandate. Do not set it for them: the whole claim
    is that the limits are theirs.
30. First load with a human watching both ends and a phone open.
31. Afterwards, send them their bundle and show them how to verify it without
    you. A client who has verified once will trust the next hundred.

---

## Phase 6 — Running it (ongoing, set up in phase 2)

32. Backups: `venue-data` and `app-data` on a schedule, off the host.
    Losing `venue-data` loses the ledger; losing `app-data` means every client
    re-onboards and re-signs.
33. `/metrics` into Prometheus; `VENUE_ALERT_WEBHOOK` into whatever you read
    at 2am. The alerts that matter are false attestations, abandoned
    deliveries and key conflicts.
34. Watch `vetting-watchlist` and `pre-pickup-and-renewal` in `/ops/jobs`. A
    job that has not run is a check that is not happening.
35. Re-read the five "things that must be true" in `RUNBOOK.md` monthly.

---

## Stop and reconsider if

- Anyone asks you to add `SIM_STUB_TOKEN` to a venue that real entities reach.
- You are tempted to describe the service as guaranteeing anything.
- `vetting:check` reports missing network-graph fields and you ship anyway.
- A client cannot complete proof of control and the fix on offer is to skip it.
- You cannot restore a backup.
