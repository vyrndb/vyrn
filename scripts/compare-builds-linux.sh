#!/usr/bin/env bash
# Alternates two builds within one session and reports each paired difference.
#
# This host stalls a flush for tens of milliseconds at unpredictable moments, so
# consecutive runs of identical code differ by up to 2x. Every misleading write
# path result recorded in docs/benchmarks.md came from comparing runs taken at
# different times. Pairing is the fix: run A then B, repeat, and quote only what
# moves in the same direction in every pair.
#
#   A=/tmp/bin-base B=/tmp/bin-runway ROUNDS=5 bash scripts/compare-builds-linux.sh
set -euo pipefail
A=${A:?set A to a directory holding vyrnd, vyrn, and vyrn-load}
B=${B:?set B to a directory holding vyrnd, vyrn, and vyrn-load}
A_NAME=${A_NAME:-A}
B_NAME=${B_NAME:-B}
ROUNDS=${ROUNDS:-5}
CLIENTS=${CLIENTS:-16}
OPERATIONS=${OPERATIONS:-600}
VALUE_SIZE=${VALUE_SIZE:-128}
MODE=${MODE:-write}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf '%s\n' benchmark-password > "$TMP/password"
"$A/vyrn" --hash-password "$TMP/hash" --password-input "$TMP/password" >/dev/null
URL='vyrn://vyrn:benchmark-password@127.0.0.1:7432/default?tls=disable'

# One run: fresh server, fresh data directory, fresh database each time, so no
# run inherits another's dirty page cache or tree size.
run(){
  local binaries=$1 data="$TMP/data-$2"
  VYRN_PASSWORD_HASH_FILE="$TMP/hash" VYRN_ALLOW_PLAINTEXT=true VYRN_CHECKPOINT_WRITES=1000000 \
  VYRN_WRITE_BATCH_SIZE=128 VYRN_WRITE_BATCH_DELAY_US=500 VYRN_DURABILITY=durable \
    "$binaries/vyrnd" --data "$data" >"$TMP/server-$2.log" 2>&1 &
  local pid=$!
  local ready=0
  for _ in $(seq 1 200); do
    if curl -fsS http://127.0.0.1:7433/health/ready >/dev/null 2>&1; then ready=1; break; fi
    sleep .05
  done
  if [[ "$ready" != 1 ]]; then cat "$TMP/server-$2.log" >&2; kill "$pid" 2>/dev/null; return 1; fi
  local line
  line=$("$binaries/vyrn-load" --url "$URL" --clients "$CLIENTS" \
    --operations "$OPERATIONS" --mode "$MODE" --value-size "$VALUE_SIZE")
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -rf "$data"
  # p50, p99, requests per second
  printf '%s' "$line" | tr ' ' '\n' | awk -F= '
    $1=="p50_us"{p50=$2} $1=="p99_us"{p99=$2} $1=="requests_per_sec"{rate=$2}
    END{print p50, p99, rate}'
}

printf 'mode=%s clients=%s value_size=%s  %s rounds, alternating within one session\n\n' \
  "$MODE" "$CLIENTS" "$VALUE_SIZE" "$ROUNDS"
printf '%-7s %26s %26s\n' round "$A_NAME (p50/p99/rate)" "$B_NAME (p50/p99/rate)"
a50s=(); b50s=(); wins=0
for round in $(seq 1 "$ROUNDS"); do
  read -r a50 a99 arate <<<"$(run "$A" "a$round")"
  read -r b50 b99 brate <<<"$(run "$B" "b$round")"
  a50s+=("$a50"); b50s+=("$b50")
  [[ "$b50" -lt "$a50" ]] && wins=$((wins + 1))
  printf '%-7s %8s %8s %8s   %8s %8s %8s\n' "$round" "$a50" "$a99" "$arate" "$b50" "$b99" "$brate"
done

median(){ printf '%s\n' "$@" | sort -n | awk '{v[NR]=$1} END{print v[int((NR+1)/2)]}'; }
am=$(median "${a50s[@]}"); bm=$(median "${b50s[@]}")
printf '\nmedian p50: %s %s us, %s %s us (%.2fx)\n' \
  "$A_NAME" "$am" "$B_NAME" "$bm" "$(awk -v a="$am" -v b="$bm" 'BEGIN{print a/b}')"
printf '%s won %s of %s paired rounds on p50\n' "$B_NAME" "$wins" "$ROUNDS"
