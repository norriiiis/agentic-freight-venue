#!/usr/bin/env bash
# Bring the three services up on this machine, in the configuration a deployed
# venue runs in: no SIM_MODE, no SIM_STUB_TOKEN, real proof of control.
#
#   ./deploy/bootstrap.sh up      generate secrets if absent, start everything, pin the console's verifier key
#   ./deploy/bootstrap.sh down    stop everything
#   ./deploy/bootstrap.sh status  what is running, and where
#
# On a host with Docker, `docker compose up -d --build` in deploy/ does the same
# thing with the same variables; this exists for a host without it, and so the
# ordering problem below is handled rather than discovered.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
RUN="${FV_RUN_DIR:-$ROOT/.data/local}"
ENV_FILE="${FV_ENV_FILE:-$ROOT/deploy/.env}"
mkdir -p "$RUN/logs"

REGISTRY_PORT="${REGISTRY_PORT:-4400}"
VENUE_PORT="${VENUE_PORT:-4100}"
APP_PORT="${APP_PORT:-4200}"

gen_env() {
  [ -f "$ENV_FILE" ] && return 0
  echo "generating $ENV_FILE (mode 600) — these are secrets, and APP_MASTER_KEY wraps every client's signing key"
  umask 077
  cat > "$ENV_FILE" <<EOF
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Treat as secret; regenerate for production from a secret store.
VENUE_OPS_TOKEN=$(openssl rand -hex 32)
APP_MASTER_KEY=$(openssl rand -base64 32)
APP_BOOTSTRAP_EMAIL=${APP_BOOTSTRAP_EMAIL:-operator@localhost}
APP_BOOTSTRAP_PASSWORD=$(openssl rand -base64 18)
APP_URL=http://127.0.0.1:${APP_PORT}
APP_SECURE_COOKIES=0
REGISTRY_ID=fmcsa-li-mock
# Phase 3 of DEPLOY.md replaces these three with real credentials.
REGISTRY_UPSTREAM=file
VETTING_PROVIDER=stub
VENUE_NOTIFY=file
EOF
  chmod 600 "$ENV_FILE"
}

start() {
  local name="$1"; shift
  local port="$1"; shift
  local health="$1"; shift
  if [ -f "$RUN/$name.pid" ] && kill -0 "$(cat "$RUN/$name.pid")" 2>/dev/null; then
    echo "  $name already running (pid $(cat "$RUN/$name.pid"))"; return 0
  fi
  ( env "$@" nohup npx tsx "src/$name/server.ts" >>"$RUN/logs/$name.log" 2>&1 & echo $! > "$RUN/$name.pid" )
  for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$port$health" >/dev/null 2>&1 && { echo "  $name up on :$port (pid $(cat "$RUN/$name.pid"))"; return 0; }
    sleep 0.5
  done
  echo "  $name did NOT come up; last lines:"; tail -5 "$RUN/logs/$name.log"; return 1
}

case "${1:-up}" in
up)
  gen_env
  set -a; . "$ENV_FILE"; set +a

  echo "starting registry"
  start registry "$REGISTRY_PORT" /health \
    REGISTRY_ID="$REGISTRY_ID" REGISTRY_PORT="$REGISTRY_PORT" REGISTRY_DATA_DIR="$RUN/registry" \
    REGISTRY_UPSTREAM="${REGISTRY_UPSTREAM:-file}" FMCSA_WEBKEY="${FMCSA_WEBKEY:-}"

  # The console generates its control-verifier key on first start, and the venue must PIN it before
  # hand-verification works. So the console starts first and the venue is told about it, rather than the
  # operator discovering an hour later that the operator path silently does nothing.
  echo "starting console"
  start app "$APP_PORT" /healthz \
    APP_PORT="$APP_PORT" APP_HOST=127.0.0.1 APP_URL="$APP_URL" APP_DATA_DIR="$RUN/app" \
    APP_SECURE_COOKIES="${APP_SECURE_COOKIES:-0}" APP_MASTER_KEY="$APP_MASTER_KEY" \
    APP_VENUE_URL="http://127.0.0.1:$VENUE_PORT" APP_VENUE_OPS_TOKEN="$VENUE_OPS_TOKEN" \
    APP_REGISTRY_URL="http://127.0.0.1:$REGISTRY_PORT" APP_REGISTRY_ID="$REGISTRY_ID" \
    APP_BOOTSTRAP_EMAIL="$APP_BOOTSTRAP_EMAIL" APP_BOOTSTRAP_PASSWORD="$APP_BOOTSTRAP_PASSWORD" \
    APP_NOTIFY="${APP_NOTIFY:-file}" APP_NOTIFY_FILE="$RUN/app/sent-mail.jsonl"

  VERIFIERS="$(npx tsx -e '
    import { readFileSync } from "node:fs";
    import { importKeyPair } from "./src/protocol/crypto";
    const kp = importKeyPair(JSON.parse(readFileSync(process.argv[1], "utf8")));
    process.stdout.write(JSON.stringify([{ verifierId: process.env.APP_VERIFIER_ID ?? "interchange-console", publicKey: kp.publicJwk, methods: ["OPERATOR_ATTESTED"] }]));
  ' "$RUN/app/control-verifier.jwk.json")"

  echo "starting venue (pinning the console as a control verifier)"
  start venue "$VENUE_PORT" /health \
    VENUE_ID="${VENUE_ID:-interchange}" VENUE_PORT="$VENUE_PORT" VENUE_HOST=127.0.0.1 VENUE_DATA_DIR="$RUN/venue" \
    VENUE_REGISTRY_URL="http://127.0.0.1:$REGISTRY_PORT" VENUE_REGISTRY_ID="$REGISTRY_ID" \
    VENUE_OPS_TOKEN="$VENUE_OPS_TOKEN" \
    VENUE_UW_PARAMS='{"offerGuarantees":false}' \
    VENUE_CONTROL_METHODS="${VENUE_CONTROL_METHODS:-REGISTRY_CONTACT_CHALLENGE,OPERATOR_ATTESTED}" \
    VENUE_CONTROL_VERIFIERS="$VERIFIERS" \
    VENUE_NOTIFY="${VENUE_NOTIFY:-file}" VENUE_NOTIFY_FILE="$RUN/venue/control-challenges.jsonl" \
    VENUE_NOTIFY_PROVIDER="${VENUE_NOTIFY_PROVIDER:-resend}" VENUE_NOTIFY_TOKEN="${VENUE_NOTIFY_TOKEN:-}" VENUE_NOTIFY_FROM="${VENUE_NOTIFY_FROM:-}" \
    VETTING_PROVIDER="${VETTING_PROVIDER:-stub}" CARRIEROK_API_KEY="${CARRIEROK_API_KEY:-}" \
    VETTING_MAX_CONTACT_SHARED="${VETTING_MAX_CONTACT_SHARED:-0}"

  echo
  echo "console   $APP_URL"
  echo "sign in   $APP_BOOTSTRAP_EMAIL  (password is in $ENV_FILE)"
  echo "logs      $RUN/logs/"
  echo "stop      ./deploy/bootstrap.sh down"
  ;;
down)
  for n in app venue registry; do
    if [ -f "$RUN/$n.pid" ]; then
      pid="$(cat "$RUN/$n.pid")"
      pkill -P "$pid" 2>/dev/null || true
      kill "$pid" 2>/dev/null && echo "  stopped $n ($pid)" || echo "  $n was not running"
      rm -f "$RUN/$n.pid"
    fi
  done
  # agents are children of the console; make sure none survived it
  pkill -f "src/agents/(broker|carrier)/index.ts" 2>/dev/null || true
  ;;
status)
  for n in registry venue app; do
    if [ -f "$RUN/$n.pid" ] && kill -0 "$(cat "$RUN/$n.pid")" 2>/dev/null; then echo "  $n running (pid $(cat "$RUN/$n.pid"))"; else echo "  $n stopped"; fi
  done
  ;;
*) echo "usage: $0 up|down|status"; exit 2;;
esac
