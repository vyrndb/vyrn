#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
PID=""
cleanup(){ if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT
cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-build.log 2>&1
printf '%s\n' 'load-test-password' > "$TMP/password.txt"
"$ROOT/target/release/vyrn" --hash-password "$TMP/password.phc" --password-input "$TMP/password.txt" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" \
VYRN_ALLOW_PLAINTEXT=true \
VYRN_CHECKPOINT_WRITES=1000000 \
VYRN_WRITE_BATCH_SIZE=128 \
VYRN_WRITE_BATCH_DELAY_US=500 \
VYRN_DURABILITY="${VYRN_DURABILITY:-durable}" \
VYRN_ASYNC_SYNC_MS="${VYRN_ASYNC_SYNC_MS:-5}" \
  "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/server.log" 2>&1 &
PID=$!
for _ in $(seq 1 100); do
  curl -fsS http://127.0.0.1:7433/health/ready >/dev/null 2>&1 && break
  sleep .05
done
kill -0 "$PID"
URL='vyrn://vyrn:load-test-password@127.0.0.1:7432/default?tls=disable'
"$ROOT/target/release/vyrn" --url "$URL" put load/hot hot >/dev/null
printf 'WRITE\n'
"$ROOT/target/release/vyrn-load" --url "$URL" --clients 16 --operations 1000 --mode write --value-size 128
printf 'READ\n'
"$ROOT/target/release/vyrn-load" --url "$URL" --clients 16 --operations 5000 --mode read --value-size 128
printf 'MIXED\n'
"$ROOT/target/release/vyrn-load" --url "$URL" --clients 16 --operations 2000 --mode mixed --value-size 128
printf 'METRICS\n'
curl -fsS http://127.0.0.1:7433/metrics
