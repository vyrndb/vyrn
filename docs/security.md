# Security model — what this build does and does not defend

Vyrn is built for **trusting applications on a private network**. This page
is the contract: everything the design defends, and everything it
deliberately leaves to the operator. If a listed non-goal is a requirement
for your deployment, do not deploy it.

## Authentication

Two mutually exclusive credential stores, chosen at startup. Setting both
is refused with an error rather than picking a winner.

- **Single credential** (`VYRN_PASSWORD_HASH_FILE`): one username
  (`VYRN_USERNAME`) verified against one Argon2id PHC string, supplied as a
  read-only secret. The authenticated session holds every permission —
  this is the pre-1.1 model, unchanged, and remains supported: a client
  that authenticates can read, write, subscribe, and manage indexes,
  and there is one shared identity for everything. Rotation is still
  replace-the-verifier-and-restart.
- **Users file** (`VYRN_USERS_FILE`): per-user accounts with prefix ACLs.
  A JSON array of entries:

  ```json
  [
    {
      "user": "orders-service",
      "phc": "$argon2id$v=19$m=19456,t=2,p=1$...",
      "permissions": [
        { "prefix": "orders/", "access": "write" },
        { "prefix": "catalog/", "access": "read" }
      ]
    }
  ]
  ```

  `access` is `read`, `write` (implies read on that prefix), or `admin`
  (implies write and read, and additionally permits index/collection DDL
  and other admin operations). An empty `prefix` means the whole keyspace.
  Several entries may name the same user: any listed verifier
  authenticates (which makes credential rotation a file edit — add the new
  entry, remove the old one later), and the grants are the union. Unknown
  fields and unknown access levels are refused at load, so a typo cannot
  silently grant or deny.

The wire protocol is unchanged in both modes: the connection URL
(`vyrn://user:password@host/db`) has always carried the username in the
authentication frame, so existing clients and SDKs work against both
modes without modification.

Brute force is throttled per address (`AuthThrottle`, refusal happens
before the Argon2 work, `vyrn_auth_failures_total` counts it), an unknown
username costs the same verification as a wrong password so response time
does not reveal which accounts exist, and pre-auth frames are capped at
64 KiB so an unauthenticated peer cannot make the server buffer more than
that.

## Authorization

Every operation on an authenticated connection passes one authorization
check before it is dispatched — plain reads and writes, every statement
inside a transaction, document operations (mapped to their collection's
underlying key prefix), subscriptions (the subscribed prefix must be
readable), and the replica handshake (a whole-keyspace read, so it
requires a whole-keyspace `admin` grant). Denials are their own error
shape — `InvalidRequest` with `permission denied for <op> on <scope>` —
never `AuthenticationFailed`: the credential is fine, the operation is
not allowed.

Granularity and limits, stated plainly:

- **ACLs are prefix-granularity.** There is no per-key, per-row, or
  attribute-level control, and a scan or subscription must sit entirely
  inside one granted prefix.
- **Secondary indexes span the whole keyspace.** An index lookup returns
  primary keys from anywhere, so index DDL requires whole-keyspace
  `admin`, index updates whole-keyspace `write`, and index lookups
  whole-keyspace `read`. Prefix-scoped users cannot use the global index
  facility; document collections (whose indexes are scoped to the
  collection) are the per-application alternative.
- **Collection DDL is scoped**: creating a collection requires `admin`
  over that collection's own key prefix, so an application administrator
  does not need the whole keyspace.
- **Revocation without a restart.** The users file is re-checked
  (mtime + length) on every authentication attempt; a changed file is
  reloaded before verifying. Each reload bumps a generation counter that
  live sessions compare on every operation: a user removed from the file
  is terminated on their next operation. A file that fails to parse keeps
  the previously loaded users (a typo saved mid-edit must not lock every
  operator out); the failure is logged and the next attempt retries.
- Note the reload trigger: with no authentication attempts at all, the
  file is not re-read and live sessions keep their scope. Any new
  connection — including a failed one — forces the check.

## Audit trail

`VYRN_AUDIT_LOG=<path>` appends one structured line per security event
(off when unset): authentication success/failure/throttle with the user
and remote address, every write, delete, and DDL operation with its user,
key or scope, and result, and every permission denial. Reads join only
under `VYRN_AUDIT_READS=1`. Lines are the same single-write RFC 3339 UTC
format as the server log, so one parser reads both.

What the trail never contains: **values and credentials**. Keys and
prefixes appear (escaped to one printable token); payloads do not. A
failed authentication names the account only when the attempted username
matches a real one — an unknown "username" is as likely a mistyped
password, and those must not be stored.

**The audit trail is best-effort and non-blocking, by design.** A commit
is never blocked on the audit file and no fsync is issued for it; an
audit write failure (disk full, permissions) is reported to stderr once
per failure streak and the server keeps serving. The reasoning: losing an
audit line is recoverable, refusing or losing an acknowledged write is
not. If your compliance regime requires audit-before-ack, this trail does
not provide it — front the database with something that does.

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
`vyrnd` as a dedicated user. **There is no encryption at rest** — ACLs
are enforced by the server process, not by the files, so anyone who can
read the data directory can read every prefix.

## Replication and availability

- Replication streams verified records over the authenticated transport.
  In users-file mode the replica's account needs a whole-keyspace `admin`
  grant, because the stream is every committed record. There is **no
  automatic failover and no fencing**: promotion is a manual, documented
  procedure, and running two writers against one keyspace is operator
  error the system cannot detect for you.

## Client caveats

- The TypeScript SDK loses precision on integers above 2^53 (`Number` +
  `JSON.parse`); values written by Rust clients that exceed it are
  corrupted on read through the TS SDK. Keep large integers as strings
  cross-language until the protocol grows a decimal/BigInt type.

## Operator checklist

Private network; per-user accounts with least-privilege prefixes where
identities matter (or the single shared credential where one trusting
application owns the database — but know that a leak there is a leak of
everything); rotate users-file credentials by editing the file, no
restart; audit trail on (`VYRN_AUDIT_LOG`) and shipped off-host, knowing
it is best-effort; dedicated OS user for the data directory; backups
stored encrypted (vyrn does not encrypt at rest); and the admin listener
never exposed.
