#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d); PID=""
cleanup(){ [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; [[ -n "$PID" ]] && wait "$PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-realtime-build.log 2>&1
printf '%s\n' rt-pass > "$TMP/password"
"$ROOT/target/release/vyrn" --hash-password "$TMP/hash" --password-input "$TMP/password" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/hash" VYRN_ALLOW_PLAINTEXT=true VYRN_DURABILITY="${VYRN_DURABILITY:-durable}" VYRN_ASYNC_SYNC_MS="${VYRN_ASYNC_SYNC_MS:-5}" "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/log" 2>&1 & PID=$!
for _ in $(seq 1 100); do curl -fsS http://127.0.0.1:7433/health/ready >/dev/null 2>&1 && break; sleep .05; done
"$ROOT/target/release/vyrn-realtime" --url 'vyrn://vyrn:rt-pass@127.0.0.1:7432/default?tls=disable' --operations 1000
