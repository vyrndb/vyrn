#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
PID=""
cleanup(){ if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT
cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --release --locked >/tmp/vyrn-runtime-build.log 2>&1
printf '%s\n' 'runtime-test-password' > "$TMP/password.txt"
"$ROOT/target/release/vyrn" --hash-password "$TMP/password.phc" --password-input "$TMP/password.txt" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Vyrn Runtime CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$TMP/ca.key" -out "$TMP/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' -keyout "$TMP/server.key" -out "$TMP/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' > "$TMP/server.ext"
openssl x509 -req -in "$TMP/server.csr" -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" -CAcreateserial -days 1 -extfile "$TMP/server.ext" -out "$TMP/server.crt" >/dev/null 2>&1
start(){
  VYRN_PASSWORD_HASH_FILE="$TMP/password.phc" VYRN_TLS_CERT_FILE="$TMP/server.crt" VYRN_TLS_KEY_FILE="$TMP/server.key" VYRN_CHECKPOINT_WRITES=100000 \
    "$ROOT/target/release/vyrnd" --data "$TMP/data" >"$TMP/server.log" 2>&1 & PID=$!
  for _ in $(seq 1 100); do curl -fsS http://127.0.0.1:7433/health/ready >/dev/null 2>&1 && return; sleep .05; done
  cat "$TMP/server.log"; exit 1
}
start
URL='vyrn://vyrn:runtime-test-password@localhost:7432/default'
"$ROOT/target/release/vyrn" --url "$URL" --tls-ca-file "$TMP/ca.crt" put load/hot hot >/dev/null
printf 'TLS_LOAD\n'
"$ROOT/target/release/vyrn-load" --url "$URL" --ca "$TMP/ca.crt" --clients 8 --operations 500 --mode mixed --value-size 128
if "$ROOT/target/release/vyrn" --url "$URL" --tls-ca-file "$TMP/server.crt" get load/hot >/dev/null 2>&1; then echo 'wrong CA unexpectedly accepted' >&2; exit 1; fi
python3 - <<'PY'
import socket, struct
s=socket.create_connection(('127.0.0.1',7432)); s.sendall(struct.pack('>I', 32)+b'not-a-tls-client-at-all........'); s.close()
PY
curl -fsS http://127.0.0.1:7433/health/ready >/dev/null
for cycle in $(seq 1 10); do
  "$ROOT/target/release/vyrn" --url "$URL" --tls-ca-file "$TMP/ca.crt" put "crash/$cycle" "value-$cycle" >/dev/null
  kill -9 "$PID"; wait "$PID" 2>/dev/null || true; PID=""; start
  test "$("$ROOT/target/release/vyrn" --url "$URL" --tls-ca-file "$TMP/ca.crt" get "crash/$cycle")" = "value-$cycle"
done
printf 'wrong_ca_rejected=yes malformed_client_survived=yes crash_cycles=10\n'
