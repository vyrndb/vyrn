#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

wait_ready() {
  local url=$1
  for _ in $(seq 1 100); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$PID" 2>/dev/null; then cat "$TMP/server.log" 2>/dev/null || true; return 1; fi
    sleep 0.05
  done
  printf 'readiness timed out: %s\n' "$url" >&2
  return 1
}

cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked
printf '%s\n' 'linux-smoke-password' > "$TMP/password.txt"
"$ROOT/target/release/vyrn" --hash-password "$TMP/password.phc" --password-input "$TMP/password.txt" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_ALLOW_PLAINTEXT=true VYRN_CHECKPOINT_WRITES=2 \
  "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/server.log" 2>&1 &
PID=$!
wait_ready http://127.0.0.1:7433/health/ready
URL='vyrn://vyrn:linux-smoke-password@127.0.0.1:7432/default?tls=disable'
"$ROOT/target/release/vyrn" --url "$URL" put smoke/key value >/dev/null
"$ROOT/target/release/vyrn" --url "$URL" put smoke/second durable >/dev/null
curl -fsS http://127.0.0.1:7433/metrics | grep -q 'vyrn_writes_total 2'
kill -9 "$PID"; wait "$PID" 2>/dev/null || true; PID=""
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_ALLOW_PLAINTEXT=true VYRN_CHECKPOINT_WRITES=2 \
  "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/server.log" 2>&1 &
PID=$!
wait_ready http://127.0.0.1:7433/health/ready
test "$("$ROOT/target/release/vyrn" --url "$URL" get smoke/key)" = value
kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""
"$ROOT/target/release/vyrn" backup --data "$TMP/data" --output "$TMP/backup.vyrn"
"$ROOT/target/release/vyrn" verify-backup "$TMP/backup.vyrn"
"$ROOT/target/release/vyrn" restore "$TMP/backup.vyrn" --target "$TMP/restored"
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_ALLOW_PLAINTEXT=true VYRN_BIND=127.0.0.1:7442 VYRN_ADMIN_BIND=127.0.0.1:7443 \
  "$ROOT/target/release/vyrnd" --data "$TMP/restored" >"$TMP/restored.log" 2>&1 &
PID=$!
wait_ready http://127.0.0.1:7443/health/ready
test "$("$ROOT/target/release/vyrn" --url 'vyrn://vyrn:linux-smoke-password@127.0.0.1:7442/default?tls=disable' get smoke/key)" = value
kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""

# PITR leg: archive sealed WAL segments continuously, take a base backup, then
# recover through the archive into a fresh directory and read the data back.
ARCHIVE="$TMP/archive"
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_ALLOW_PLAINTEXT=true VYRN_CHECKPOINT_WRITES=2 \
VYRN_WAL_ARCHIVE_DIR="$ARCHIVE" VYRN_WAL_ARCHIVE_INTERVAL_MS=200 VYRN_BIND=127.0.0.1:7452 VYRN_ADMIN_BIND=127.0.0.1:7453 \
  "$ROOT/target/release/vyrnd" --data "$TMP/pitr-data" >"$TMP/pitr.log" 2>&1 &
PID=$!
wait_ready http://127.0.0.1:7453/health/ready
PITR_URL='vyrn://vyrn:linux-smoke-password@127.0.0.1:7452/default?tls=disable'
"$ROOT/target/release/vyrn" --url "$PITR_URL" put pitr/key archived >/dev/null
"$ROOT/target/release/vyrn" --url "$PITR_URL" put pitr/second archived >/dev/null
for _ in $(seq 1 100); do
  if ls "$ARCHIVE"/*.vwal >/dev/null 2>&1; then break; fi
  sleep 0.05
done
ls "$ARCHIVE"/*.vwal >/dev/null
kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""
"$ROOT/target/release/vyrn" backup --data "$TMP/pitr-data" --output "$TMP/pitr-base.vyrn"
"$ROOT/target/release/vyrn" verify-archive "$ARCHIVE"
"$ROOT/target/release/vyrn" recover --base "$TMP/pitr-base.vyrn" --archive "$ARCHIVE" --target "$TMP/pitr-recovered"
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_ALLOW_PLAINTEXT=true VYRN_BIND=127.0.0.1:7452 VYRN_ADMIN_BIND=127.0.0.1:7453 \
  "$ROOT/target/release/vyrnd" --data "$TMP/pitr-recovered" >"$TMP/pitr-recovered.log" 2>&1 &
PID=$!
wait_ready http://127.0.0.1:7453/health/ready
test "$("$ROOT/target/release/vyrn" --url "$PITR_URL" get pitr/key)" = archived
test "$("$ROOT/target/release/vyrn" --url "$PITR_URL" get pitr/second)" = archived
printf 'linux smoke passed\n'
