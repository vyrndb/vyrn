#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENTS=${CLIENTS:-16}
OPERATIONS=${OPERATIONS:-1000}
VALUE_SIZE=${VALUE_SIZE:-128}
MODES=${MODES:-"write read mixed transaction index"}
CONTAINER=${POSTGRES_CONTAINER:-vyrn-postgres-benchmark}
PASSWORD=${POSTGRES_PASSWORD:-benchmark-password}
PORT=${POSTGRES_PORT:-15432}
DOCKER=${DOCKER:-docker}
cleanup() { "$DOCKER" rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  cargo build --manifest-path "$ROOT/Cargo.toml" -p vyrn --bin postgres-load --release --locked >/tmp/vyrn-postgres-benchmark-build.log 2>&1
fi
"$DOCKER" run --rm -d --name "$CONTAINER" -e POSTGRES_PASSWORD="$PASSWORD" -p "$PORT:5432" postgres:17-alpine \
  -c synchronous_commit=on -c fsync=on -c full_page_writes=on >/dev/null
ready=0
for _ in $(seq 1 120); do
  if "$DOCKER" exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1; then ready=1; break; fi
  sleep .25
done
if [[ "$ready" != 1 ]]; then
  "$DOCKER" logs "$CONTAINER" >&2
  exit 1
fi
"$DOCKER" exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL' >/dev/null
CREATE TABLE kv (key bytea PRIMARY KEY, value bytea NOT NULL);
CREATE TABLE indexed_rows (id bytea PRIMARY KEY, indexed_value bytea NOT NULL, value bytea NOT NULL);
CREATE INDEX indexed_rows_value ON indexed_rows(indexed_value, id);
SQL
URL="postgres://postgres:$PASSWORD@127.0.0.1:$PORT/postgres"
for mode in $MODES; do
  "$ROOT/target/release/postgres-load" --url "$URL" --clients "$CLIENTS" --operations "$OPERATIONS" --mode "$mode" --value-size "$VALUE_SIZE"
done
