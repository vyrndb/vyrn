# Security model — what 1.0 does and does not defend

Vyrn 1.0 is built for **one trusting application on a private network**.
This page is the contract: everything the design defends, and everything it
deliberately leaves to the operator. If a listed non-goal is a requirement
for your deployment, do not deploy 1.0.

## Authentication and authorization

- **One shared credential per server** (Argon2id verifier, supplied as a
  read-only secret). A client that authenticates can do everything:
  read, write, subscribe, manage indexes. There are **no per-principal
  identities, no ACLs, no roles**.
- **No revocation short of rotation**: replacing the verifier and
  restarting is the only way to expel a credential holder. There is **no
  audit trail** of who did what — there is no "who".
- Brute force is throttled (`AuthThrottle`, refusal happens before the
  Argon2 work, `vyrn_auth_failures_total` counts it), and pre-auth frames
  are capped at 64 KiB so an unauthenticated peer cannot make the server
  buffer more than that.

## Transport

- TLS 1.3 on the client listener. The admin listener binds loopback by
  default and must stay private; it is not designed for hostile networks.
- The HTTP gateway caps connections but has **no per-route rate limiting
  and no per-IP fairness**: an authenticated client can squat connection
  slots. Put a reverse proxy in front if that matters.

## What the checksums are for

Page, WAL-record, and value-log checksums (and the v5 header
self-checksums) defend against **rot and torn writes** — bit flips,
truncated syscalls, damaged restores. They are **not** a defense against
an attacker who can write the data directory: whoever holds file access
owns the database (forged structures are detected on a best-effort basis
and refused loudly where possible, but that is robustness, not a security
boundary). Protect the data directory with filesystem permissions; run
`vyrnd` as a dedicated user.

## Replication and availability

- Replication streams verified records over the authenticated transport.
  There is **no automatic failover and no fencing**: promotion is a manual,
  documented procedure, and running two writers against one keyspace is
  operator error the system cannot detect for you.

## Client caveats

- The TypeScript SDK loses precision on integers above 2^53 (`Number` +
  `JSON.parse`); values written by Rust clients that exceed it are
  corrupted on read through the TS SDK. Keep large integers as strings
  cross-language until the protocol grows a decimal/BigInt type.

## Operator checklist

Private network, one credential per deployment, rotate by re-provisioning
the verifier and restarting, dedicated OS user for the data directory,
backups stored encrypted (vyrn does not encrypt at rest), and the admin
listener never exposed.
