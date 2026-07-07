#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d); PID=""; WATCH=""
cleanup(){ [[ -n "$WATCH" ]] && kill "$WATCH" 2>/dev/null || true; [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-realtime-build.log 2>&1
printf '%s\n' realtime-password > "$TMP/password.txt"
"$ROOT/target/release/vyrn" --hash-password "$TMP/password.phc" --password-input "$TMP/password.txt" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_ALLOW_PLAINTEXT=true "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/server.log" 2>&1 & PID=$!
for _ in $(seq 1 100); do curl -fsS http://127.0.0.1:7433/health/ready >/dev/null 2>&1 && break; sleep .05; done
URL='vyrn://vyrn:realtime-password@127.0.0.1:7432/default?tls=disable'
"$ROOT/target/release/vyrn-watch" --url "$URL" --prefix realtime/ --count 2 >"$TMP/watch.log" 2>&1 & WATCH=$!
for _ in $(seq 1 100); do grep -q subscribed "$TMP/watch.log" 2>/dev/null && break; sleep .02; done
START=$(date +%s%N)
"$ROOT/target/release/vyrn" --url "$URL" put realtime/one first >/dev/null
"$ROOT/target/release/vyrn" --url "$URL" put ignored/one nope >/dev/null
"$ROOT/target/release/vyrn" --url "$URL" delete realtime/one >/dev/null
wait "$WATCH"; WATCH=""
END=$(date +%s%N)
printf 'roundtrip_sequence_ms=%s\n' "$(((END-START)/1000000))"
cat "$TMP/watch.log"
test "$(grep -c '^change ' "$TMP/watch.log")" = 2
! grep -q ignored "$TMP/watch.log"
