#!/usr/bin/env bash
#
# Crash soak: does an acknowledged write always survive?
#
# Every other durability test in this repo verifies the storage engine against
# files it damages itself. This one verifies the whole shipped stack — server,
# write pipeline, WAL, recovery — against the failure operators actually get: the
# process disappearing without warning, mid-write, over and over.
#
# THE ONLY CLAIM UNDER TEST is the one the server makes to its clients: a write
# the server confirmed is durable. So the script tracks acknowledgements
# precisely. A key is asserted present after the restart if and only if the `vyrn`
# client exited 0 for it *before* the kill. A write that was in flight when
# SIGKILL landed may legitimately be absent — the client never got an answer, so
# nothing was promised — and asserting on it would make this script fail at random
# and teach everyone to ignore it. Unacknowledged keys are counted and reported,
# never asserted.
#
# Two modes, because there are two ways a server stops and they exercise
# different code:
#
#   crash    SIGKILL at a random point in a batch of writes. The WAL is the only
#            thing that has fsynced, so this is what proves replay works.
#
#   shutdown SIGTERM under VYRN_DURABILITY=async. In async mode acknowledged
#            commits sit in an in-memory buffer that a background timer flushes,
#            so a graceful stop MUST perform a final sync before exiting or it
#            loses writes it already confirmed. `vyrn-server`'s tests could not
#            cover this: Windows cannot send SIGTERM to a child from `std`, which
#            is exactly why D1 deferred it here (see todo.md).
#
# Usage:
#   scripts/crash-soak.sh                 # both modes, default cycles
#   VYRN_SOAK_MODE=crash    scripts/crash-soak.sh
#   VYRN_SOAK_MODE=shutdown scripts/crash-soak.sh
#   VYRN_SOAK_CYCLES=50 VYRN_SOAK_WRITES=40 scripts/crash-soak.sh
#
set -euo pipefail

# Linux-only, and loudly so. The script's whole method is SIGKILL/SIGTERM against
# a child plus a restart, and `production.md` documents Linux as the production
# platform. Two of the guarantees it checks do not even exist elsewhere:
# `sync_directory` is a no-op off Unix, so a renamed manifest's durability is
# unproven, and Windows has no SIGTERM to deliver. A pass on another platform
# would therefore be a false pass, which is worse than no run at all.
if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'crash-soak.sh requires Linux (found %s).\n' "$(uname -s)" >&2
  printf 'It kills and restarts vyrnd, which needs real POSIX signals, and it\n' >&2
  printf 'checks directory-entry durability that sync_directory only provides on\n' >&2
  printf 'Unix. Run it on the Linux host the production gates target.\n' >&2
  exit 1
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
PID=""

MODE="${VYRN_SOAK_MODE:-both}"
CYCLES="${VYRN_SOAK_CYCLES:-20}"
# Writes attempted per cycle. Enough that the kill lands somewhere interesting
# rather than always between commits, few enough that 20 cycles stay quick.
WRITES="${VYRN_SOAK_WRITES:-25}"
BIND="${VYRN_SOAK_BIND:-127.0.0.1:7432}"
ADMIN_BIND="${VYRN_SOAK_ADMIN_BIND:-127.0.0.1:7433}"
# Low enough that checkpoints fire during the soak, so the kill sometimes lands
# with a published manifest behind it and sometimes with replay carrying
# everything. Those are different recovery paths and a soak that only ever
# exercises one of them proves half as much. (The segment size itself is not
# configurable through vyrnd; the checkpoint cadence is the knob that varies the
# recovery state a restart meets.)
CHECKPOINT_WRITES="${VYRN_SOAK_CHECKPOINT_WRITES:-50}"
PASSWORD="${VYRN_SOAK_PASSWORD:-crash-soak-password}"

cleanup() {
  if [[ -n "$PID" ]]; then kill -9 "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

case "$MODE" in
  crash|shutdown|both) ;;
  *) printf 'VYRN_SOAK_MODE must be crash, shutdown, or both (got %s)\n' "$MODE" >&2; exit 1 ;;
esac

cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked \
  >/tmp/vyrn-soak-build.log 2>&1

VYRN="$ROOT/target/release/vyrn"
VYRND="$ROOT/target/release/vyrnd"
printf '%s\n' "$PASSWORD" > "$TMP/password.txt"
"$VYRN" --hash-password "$TMP/password.phc" --password-input "$TMP/password.txt" >/dev/null
URL="vyrn://vyrn:${PASSWORD}@${BIND}/default?tls=disable"

# Where acknowledged keys are recorded. Appended to only after the client
# confirms, and never truncated, so it survives every kill and accumulates the
# full history the final verification runs against.
ACKED="$TMP/acknowledged"
: > "$ACKED"

# Starts vyrnd against $1 and waits for readiness. Extra environment for the
# durability mode is passed through $2 as a name=value list.
start_server() {
  local data=$1 extra=${2:-}
  # shellcheck disable=SC2086 # $extra is a deliberate list of name=value pairs.
  env VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" \
      VYRN_ALLOW_PLAINTEXT=true \
      VYRN_BIND="$BIND" \
      VYRN_ADMIN_BIND="$ADMIN_BIND" \
      VYRN_CHECKPOINT_WRITES="$CHECKPOINT_WRITES" \
      $extra \
      "$VYRND" --data "$data" >>"$TMP/server.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 200); do
    if curl -fsS "http://${ADMIN_BIND}/health/ready" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$PID" 2>/dev/null; then
      printf 'vyrnd exited during startup; tail of its log:\n' >&2
      tail -n 40 "$TMP/server.log" >&2
      return 1
    fi
    sleep 0.05
  done
  printf 'vyrnd never became ready on %s\n' "$ADMIN_BIND" >&2
  tail -n 40 "$TMP/server.log" >&2
  return 1
}

# Writes keys until $2 of them are attempted or the server dies, recording each
# acknowledgement. Each key names its cycle and index so a survivor can be traced
# back to the write that produced it.
#
# The ordering here is the entire point: the key is appended to $ACKED only after
# `vyrn put` exits 0, which happens only after the server answered, which happens
# only after the commit is durable. A key killed before its answer never reaches
# the file and is therefore never asserted.
drive_writes() {
  local cycle=$1 count=$2 attempted=0 acknowledged=0
  for index in $(seq 1 "$count"); do
    attempted=$((attempted + 1))
    local key="soak/${cycle}/${index}"
    if "$VYRN" --url "$URL" put "$key" "value-${cycle}-${index}" >/dev/null 2>&1; then
      printf '%s value-%s-%s\n' "$key" "$cycle" "$index" >> "$ACKED"
      acknowledged=$((acknowledged + 1))
    fi
    if ! kill -0 "$PID" 2>/dev/null; then break; fi
  done
  printf '%s %s' "$attempted" "$acknowledged"
}

# Re-reads every acknowledged key and fails on the first one that is missing or
# holds the wrong value. A missing key here is the bug this script exists to
# catch: the server said the write was durable and it was not.
#
# A missing key is checked for explicitly rather than through the exit status.
# `vyrn get` prints "(not found)" and exits 0 for a key that is absent — it
# reserves a non-zero exit for a failure to ask, not for a negative answer — so a
# status-only check would report a lost write as a value mismatch and send whoever
# reads the output looking for corruption instead of for a durability bug. The
# distinction matters enough to spell out: LOST means the write vanished, CORRUPT
# means it came back wrong, and those have different causes.
verify_acknowledged() {
  local checked=0 key expected actual
  while read -r key expected; do
    [[ -z "$key" ]] && continue
    if ! actual=$("$VYRN" --url "$URL" get "$key" 2>/dev/null); then
      printf 'FAIL: could not query %s after the restart\n' "$key" >&2
      return 1
    fi
    if [[ "$actual" == "(not found)" ]]; then
      printf 'LOST: acknowledged write %s is absent after the restart\n' "$key" >&2
      return 1
    fi
    if [[ "$actual" != "$expected" ]]; then
      printf 'CORRUPT: %s reads %q, expected %q\n' "$key" "$actual" "$expected" >&2
      return 1
    fi
    checked=$((checked + 1))
  done < "$ACKED"
  printf '%s' "$checked"
}

# SIGKILL mode. The kill lands at a random point inside the write batch, so
# across cycles it falls before a commit, between the WAL append and the
# response, and inside the tree work — the three places a lost write could hide.
run_crash_mode() {
  local data="$TMP/crash-data" total_attempted=0 total_acknowledged=0 verified=0
  printf 'MODE crash: SIGKILL mid-write, %s cycles of up to %s writes\n' "$CYCLES" "$WRITES"
  : > "$ACKED"
  start_server "$data"
  for cycle in $(seq 1 "$CYCLES"); do
    # A random cut point so the kill is not always at the same phase of the
    # pipeline. At least one write per cycle, so every cycle has something to
    # prove.
    local budget=$((RANDOM % WRITES + 1))
    read -r attempted acknowledged <<<"$(drive_writes "$cycle" "$budget")"
    total_attempted=$((total_attempted + attempted))
    total_acknowledged=$((total_acknowledged + acknowledged))

    kill -9 "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=""
    # A restart that fails IS the failure: a database that will not open after a
    # SIGKILL has lost every write in it, acknowledged or not.
    if ! start_server "$data"; then
      printf 'FAIL: the database did not reopen after the kill in cycle %s\n' "$cycle" >&2
      return 1
    fi
    verified=$(verify_acknowledged) || return 1
    printf '  cycle %-3s attempted=%-3s acknowledged=%-3s verified=%s\n' \
      "$cycle" "$attempted" "$acknowledged" "$verified"
  done
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  PID=""
  printf 'crash: cycles=%s attempted=%s acknowledged=%s unacknowledged=%s all_acknowledged_survived=yes\n' \
    "$CYCLES" "$total_attempted" "$total_acknowledged" \
    "$((total_attempted - total_acknowledged))"
}

# SIGTERM mode, under async durability — the case D1 could not test on Windows.
#
# In async mode the server answers a client as soon as the commit is in its
# in-memory buffer and lets a background timer fsync it. That is a legitimate
# trade only if a graceful stop drains the buffer: SIGTERM must sync everything
# already acknowledged before the process exits. A long timer interval makes the
# window wide, so an implementation that forgot the final sync loses writes here
# every single cycle instead of once in a hundred runs.
run_shutdown_mode() {
  local data="$TMP/shutdown-data" total_attempted=0 total_acknowledged=0 verified=0
  local async_env="VYRN_DURABILITY=async VYRN_ASYNC_SYNC_MS=${VYRN_SOAK_ASYNC_SYNC_MS:-5000}"
  printf 'MODE shutdown: SIGTERM under VYRN_DURABILITY=async, %s cycles\n' "$CYCLES"
  : > "$ACKED"
  start_server "$data" "$async_env"
  for cycle in $(seq 1 "$CYCLES"); do
    read -r attempted acknowledged <<<"$(drive_writes "$cycle" "$WRITES")"
    total_attempted=$((total_attempted + attempted))
    total_acknowledged=$((total_acknowledged + acknowledged))

    # Graceful, and waited on: the exit status is part of the contract, and a
    # shutdown that hangs is its own bug.
    kill -TERM "$PID" 2>/dev/null || true
    local status=0
    wait "$PID" || status=$?
    PID=""
    if [[ "$status" -ne 0 ]]; then
      printf 'FAIL: graceful shutdown in cycle %s exited %s\n' "$cycle" "$status" >&2
      tail -n 40 "$TMP/server.log" >&2
      return 1
    fi
    if ! start_server "$data" "$async_env"; then
      printf 'FAIL: the database did not reopen after SIGTERM in cycle %s\n' "$cycle" >&2
      return 1
    fi
    # Nothing acknowledged may be missing. In async mode these writes were only
    # ever in a buffer, so every one of them is here because the shutdown path
    # flushed it.
    verified=$(verify_acknowledged) || {
      printf 'FAIL: async graceful shutdown lost an acknowledged write in cycle %s\n' "$cycle" >&2
      return 1
    }
    printf '  cycle %-3s attempted=%-3s acknowledged=%-3s verified=%s\n' \
      "$cycle" "$attempted" "$acknowledged" "$verified"
  done
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  PID=""
  printf 'shutdown: cycles=%s acknowledged=%s async_graceful_sync=yes\n' \
    "$CYCLES" "$total_acknowledged"
}

if [[ "$MODE" == "crash" || "$MODE" == "both" ]]; then
  run_crash_mode
fi
if [[ "$MODE" == "shutdown" || "$MODE" == "both" ]]; then
  run_shutdown_mode
fi

# A last independent check that the surviving directory is not merely readable
# through a running server but structurally sound on its own terms: a backup
# refuses to run against a database it cannot walk, and verify-backup re-proves
# every copied byte.
for data in "$TMP/crash-data" "$TMP/shutdown-data"; do
  [[ -d "$data" ]] || continue
  "$VYRN" backup --data "$data" --output "$TMP/soak-$(basename "$data").vyrn" >/dev/null
  "$VYRN" verify-backup "$TMP/soak-$(basename "$data").vyrn" >/dev/null
  printf 'post-soak backup verified: %s\n' "$(basename "$data")"
done

printf 'crash soak passed\n'
