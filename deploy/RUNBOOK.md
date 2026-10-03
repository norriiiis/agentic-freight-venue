# Running a closed pilot

Three processes, one host, three volumes. Put a reverse proxy with TLS in
front of the app; the venue and the registry are not exposed to the internet
in this configuration.

## Before the first start

```bash
cd deploy
cat > .env <<'ENV'
VENUE_OPS_TOKEN=REPLACE
APP_MASTER_KEY=REPLACE
APP_BOOTSTRAP_EMAIL=you@yourcompany.com
APP_BOOTSTRAP_PASSWORD=REPLACE
APP_URL=https://console.yourcompany.com
ENV
# then, actually generate them:
#   openssl rand -hex 32      -> VENUE_OPS_TOKEN
#   openssl rand -base64 32   -> APP_MASTER_KEY
docker compose up -d --build
```

The first start creates the operator account from `APP_BOOTSTRAP_*` and prints
it. Sign in, then invite your first client from **Operations**.

## What is in each volume, and what losing it costs

| volume | holds | if you lose it |
|---|---|---|
| `venue-data` | the ledger, commitments, credentials, the venue's keys | everything. Back it up. The ledger is the record; artifacts your clients already downloaded still verify, but the venue cannot issue or check anything. |
| `app-data` | accounts, principal keys (wrapped), agents' data dirs | clients must re-onboard and re-sign mandates. Their commitments survive on the venue. |
| `registry-data` | the registry mirror's key | its signature changes, so pinned keys must be re-pinned. |

Back up `venue-data` and `app-data` on a schedule. `sqlite3 ... ".backup"` or a
volume snapshot while the containers are stopped; a plain file copy of a live
WAL database is not a backup.

## The things that must be true before a real client transacts

1. `APP_MASTER_KEY` is in a secret store, not in the compose file or a shell
   history. If it leaks, every principal key it wraps is compromised, and every
   mandate those keys signed should be treated as forgeable.
2. TLS terminates in front of the app, and `APP_SECURE_COOKIES=1`.
3. `APP_MAIL=http` with a real provider, or proof of control is operator-only.
4. Backups are running and you have restored one.
5. Your clients know the disclosure the console shows them: this venue and the
   registry it reads are the same company, and no guarantee is offered.

## Day-to-day

- **Invite a client**: Operations → Invite a client. They get a link, set a
  password, and walk the five onboarding steps themselves.
- **Verify a client by hand**: open their org from Operations and use the
  operator panel on their onboarding page. What you type is the evidence, and
  it is kept with your name against it.
- **An agent is down**: the supervisor restarts it every 15 seconds and the
  client's rail shows its state. Repeated failure is in `docker compose logs app`.
- **Check the venue**: `curl -H "authorization: Bearer $VENUE_OPS_TOKEN" http://127.0.0.1:4100/ops/health`
  and `/metrics` for Prometheus.

## Upgrading

`docker compose build && docker compose up -d`. Agents are restarted by the
supervisor on the new image. The venue recovers its journals on start; the
crash-recovery scenarios in the test suite are the proof that this is safe.
