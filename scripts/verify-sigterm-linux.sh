#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
PID=""
cleanup(){ if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT
cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-term-build.log 2>&1
printf '%s\n' 'term-password' > "$TMP/password.txt"
"$ROOT/target/release/vyrn" --hash-password "$TMP/password.phc" --password-input "$TMP/password.txt" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_ALLOW_PLAINTEXT=true "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/log" 2>&1 &
PID=$!
for _ in $(seq 1 100); do curl -fsS http://127.0.0.1:7433/health/ready >/dev/null 2>&1 && break; sleep .05; done
kill -TERM "$PID"
wait "$PID"
STATUS=$?
PID=""
printf 'sigterm_exit=%s\n' "$STATUS"
grep -E 'draining connections|shutdown complete' "$TMP/log"
