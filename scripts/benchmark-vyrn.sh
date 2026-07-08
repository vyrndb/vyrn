#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENTS=${CLIENTS:-16}
OPERATIONS=${OPERATIONS:-1000}
VALUE_SIZE=${VALUE_SIZE:-128}
MODES=${MODES:-"write read mixed transaction index"}
TMP=$(mktemp -d)
PID=""
cleanup(){ [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; [[ -n "$PID" ]] && wait "$PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-comparison-build.log 2>&1
fi
printf '%s\n' benchmark-password > "$TMP/password"
"$ROOT/target/release/vyrn" --hash-password "$TMP/hash" --password-input "$TMP/password" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/hash" VYRN_ALLOW_PLAINTEXT=true VYRN_CHECKPOINT_WRITES=1000000 \
VYRN_WRITE_BATCH_SIZE=128 VYRN_WRITE_BATCH_DELAY_US=500 VYRN_DURABILITY="${VYRN_DURABILITY:-durable}" \
  "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/server.log" 2>&1 &
PID=$!
ready=0
for _ in $(seq 1 100); do
  if curl -fsS http://127.0.0.1:7433/health/ready >/dev/null 2>&1; then ready=1; break; fi
  sleep .05
done
if [[ "$ready" != 1 ]]; then
  cat "$TMP/server.log" >&2
  exit 1
fi
URL='vyrn://vyrn:benchmark-password@127.0.0.1:7432/default?tls=disable'
for mode in $MODES; do
  "$ROOT/target/release/vyrn-load" --url "$URL" --clients "$CLIENTS" --operations "$OPERATIONS" --mode "$mode" --value-size "$VALUE_SIZE"
done
