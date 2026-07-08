#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENT_MATRIX=${CLIENT_MATRIX:-"1 16 64 256"}
VALUE_SIZE_MATRIX=${VALUE_SIZE_MATRIX:-"128 4096 65536 1048576"}
MODES=${MODES:-"read write mixed transaction index"}
OPERATIONS=${OPERATIONS:-1000}
RESULTS=${RESULTS:-"$ROOT/benchmark-results-$(date -u +%Y%m%dT%H%M%SZ).csv"}

cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-comparison-build.log 2>&1
printf 'backend,mode,clients,operations_per_client,value_size,operations,elapsed_ms,ops_per_sec,p50_us,p95_us,p99_us,p999_us,max_us\n' > "$RESULTS"

record() {
  local line=$1
  printf '%s\n' "$line"
  printf '%s\n' "$line" | tr ' ' '\n' | cut -d= -f2- | paste -sd, - >> "$RESULTS"
}

for value_size in $VALUE_SIZE_MATRIX; do
  for clients in $CLIENT_MATRIX; do
    printf 'matrix clients=%s value_size=%s operations_per_client=%s\n' "$clients" "$value_size" "$OPERATIONS" >&2
    while IFS= read -r line; do record "$line"; done < <(
      CLIENTS="$clients" OPERATIONS="$OPERATIONS" VALUE_SIZE="$value_size" MODES="$MODES" SKIP_BUILD=1 \
        bash "$ROOT/scripts/benchmark-vyrn.sh"
    )
    while IFS= read -r line; do record "$line"; done < <(
      CLIENTS="$clients" OPERATIONS="$OPERATIONS" VALUE_SIZE="$value_size" MODES="$MODES" SKIP_BUILD=1 \
        bash "$ROOT/scripts/benchmark-postgres.sh"
    )
  done
done
printf 'results=%s\n' "$RESULTS"
