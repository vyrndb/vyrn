#!/usr/bin/env bash
# Breaks a durable commit into its stages and prints the per-request budget.
#
# The comparison benchmark reports what a write costs; this reports where that
# cost goes. Counters are sampled either side of the load run, so the prepare
# phase and the server's own startup writes are excluded.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENTS=${CLIENTS:-16}
OPERATIONS=${OPERATIONS:-600}
VALUE_SIZE=${VALUE_SIZE:-128}
MODE=${MODE:-write}
ADMIN=${ADMIN:-http://127.0.0.1:7433}
TMP=$(mktemp -d)
PID=""
cleanup(){ [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; [[ -n "$PID" ]] && wait "$PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >"$TMP/build.log" 2>&1
fi

printf '%s\n' benchmark-password > "$TMP/password"
"$ROOT/target/release/vyrn" --hash-password "$TMP/hash" --password-input "$TMP/password" >/dev/null
VYRN_PASSWORD_HASH_FILE="$TMP/hash" VYRN_ALLOW_PLAINTEXT=true VYRN_CHECKPOINT_WRITES=1000000 \
VYRN_WRITE_BATCH_SIZE="${VYRN_WRITE_BATCH_SIZE:-128}" \
VYRN_WRITE_BATCH_DELAY_US="${VYRN_WRITE_BATCH_DELAY_US:-500}" \
VYRN_DURABILITY="${VYRN_DURABILITY:-durable}" \
  "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/server.log" 2>&1 &
PID=$!
ready=0
for _ in $(seq 1 100); do
  if curl -fsS "$ADMIN/health/ready" >/dev/null 2>&1; then ready=1; break; fi
  sleep .05
done
if [[ "$ready" != 1 ]]; then cat "$TMP/server.log" >&2; exit 1; fi

# Sample a named counter out of the Prometheus text body.
sample(){ curl -fsS "$ADMIN/metrics" | awk -v key="$1" '$1==key {print $2}'; }
KEYS="vyrn_commit_batches_total vyrn_commit_requests_total vyrn_commit_front_nanoseconds_total \
vyrn_commit_lock_nanoseconds_total vyrn_commit_apply_nanoseconds_total \
vyrn_commit_flush_queue_nanoseconds_total vyrn_commit_sync_nanoseconds_total \
vyrn_commit_publish_nanoseconds_total vyrn_wal_flushes_total vyrn_flushed_batches_total"

declare -A before
for key in $KEYS; do before[$key]=$(sample "$key"); done

URL='vyrn://vyrn:benchmark-password@127.0.0.1:7432/default?tls=disable'
"$ROOT/target/release/vyrn-load" --url "$URL" --clients "$CLIENTS" \
  --operations "$OPERATIONS" --mode "$MODE" --value-size "$VALUE_SIZE"

METRICS=$(curl -fsS "$ADMIN/metrics")
sampled(){ printf '%s\n' "$METRICS" | awk -v key="$1" '$1==key {print $2}'; }
declare -A delta
for key in $KEYS; do delta[$key]=$(( $(sampled "$key") - ${before[$key]} )); done

batches=${delta[vyrn_commit_batches_total]}
requests=${delta[vyrn_commit_requests_total]}
if [[ "$batches" -eq 0 || "$requests" -eq 0 ]]; then
  echo "no commits observed for mode=$MODE" >&2
  exit 1
fi

# `front` is already per request; the rest are per batch and shared by every
# request in it, so dividing by batches and not by requests is what makes the
# means add up to one request's server-side latency. The p50 column is over the
# whole process, which is why this script runs one server per configuration —
# this host stalls often enough that the mean column alone is not readable.
printf '\nstage budget  mode=%s clients=%s value_size=%s\n' "$MODE" "$CLIENTS" "$VALUE_SIZE"
printf '  requests %s in %s batches (%.1f per batch), %s barriers (%.2f batches per barrier)\n' \
  "$requests" "$batches" \
  "$(awk -v r="$requests" -v b="$batches" 'BEGIN{print r/b}')" \
  "${delta[vyrn_wal_flushes_total]}" \
  "$(awk -v f="${delta[vyrn_flushed_batches_total]}" -v s="${delta[vyrn_wal_flushes_total]}" \
     'BEGIN{print (s?f/s:0)}')"
printf '  %-12s %9s %9s %9s\n' stage mean p50 p99
mean_total=0; p50_total=0
for stage in front:requests lock:batches apply:batches flush_queue:batches sync:batches publish:batches; do
  name=${stage%%:*}; per=${stage##*:}
  divisor=$batches; [[ "$per" == requests ]] && divisor=$requests
  mean=$(awk -v n="${delta[vyrn_commit_${name}_nanoseconds_total]}" -v d="$divisor" \
    'BEGIN{printf "%.0f", n/d/1000}')
  p50=$(awk -v n="$(sampled "vyrn_commit_${name}_p50_nanoseconds")" 'BEGIN{printf "%.0f", n/1000}')
  p99=$(awk -v n="$(sampled "vyrn_commit_${name}_p99_nanoseconds")" 'BEGIN{printf "%.0f", n/1000}')
  mean_total=$((mean_total + mean)); p50_total=$((p50_total + p50))
  printf '  %-12s %6s us %6s us %6s us\n' "$name" "$mean" "$p50" "$p99"
done
printf '  %-12s %6s us %6s us            (server side, one request)\n' \
  TOTAL "$mean_total" "$p50_total"
