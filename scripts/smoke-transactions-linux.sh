#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
PID=""
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  [[ -n "$PID" ]] && wait "$PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-transaction-build.log 2>&1
cargo build --manifest-path "$ROOT/Cargo.toml" -p vyrn-client --example transaction-smoke --release --locked >>/tmp/vyrn-transaction-build.log 2>&1
printf '%s\n' tx-pass > "$TMP/password"
"$ROOT/target/release/vyrn" --hash-password "$TMP/hash" --password-input "$TMP/password" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/hash" VYRN_ALLOW_PLAINTEXT=true VYRN_ADMIN_BIND=127.0.0.1:17433 \
  "$ROOT/target/release/vyrnd" --bind 127.0.0.1:17432 --data "$TMP/data" >"$TMP/server.log" 2>&1 &
PID=$!
for _ in $(seq 1 100); do
  curl -fsS http://127.0.0.1:17433/health/ready >/dev/null 2>&1 && break
  sleep .05
done
VYRN_URL='vyrn://vyrn:tx-pass@127.0.0.1:17432/default?tls=disable' \
  "$ROOT/target/release/examples/transaction-smoke"
