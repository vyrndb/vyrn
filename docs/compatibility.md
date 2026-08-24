# Compatibility and versioning — the 1.0 contract

This page states what a 1.0 release freezes, what may still change inside
1.x, and the upgrade rules. Anything not listed here — internal crate APIs,
profile counters, the benchmark harness, log line wording — is not covered.

## On-disk formats

Every format below is **readable by every later 1.x build, forever**.
Writers always write the newest version; older data converts only when it
is naturally rewritten, never in place at open. **Downgrade is not
supported**: a database touched by a newer build may hold structures an
older build refuses (loudly, as a version error — never as silent
misreads).

| Structure | Written today | Still readable | Notes |
| --- | --- | --- | --- |
| Tree pages | v5 (slot directory) | v4 | v4 pages convert as copy-on-write or checkpoint compaction rewrites them; a long-lived database may hold both versions indefinitely, which is supported. |
| WAL records | v5 (header self-checksum) | v4 | v4 records predate the header checksum; their headers are trusted as they always were. |
| WAL segment headers | v4 | v4 | Unchanged at 1.0. |
| Manifest | v4 | v4 | Unchanged at 1.0. |
| Value log | v1 framing | v1 | Unchanged at 1.0. |
| Portable export | current | current | The version-independent interchange format; an export from ANY build imports into any 1.x build. This is also the escape hatch any future major version must honour. |

## Replication

Records ship **verbatim** — a replica's WAL is byte-interchangeable with
its primary's. That property fixes the version rule: **a replica must run
the same or a newer build than its primary.** A newer primary's records
(e.g. v5 with header checksums) are refused by an older replica as a
version error, by design. Upgrade replicas first, then the primary.

## The change log

`EngineOptions::change_log` (default on; the server requires it) is a
**per-database** choice. A database that alternates loses change history
for the disabled stretches; subscribers see silence, not an error. The
change-log record encoding may evolve within 1.x (the queued multi-part
split), which is invisible to same-build databases and covered across
builds by the replica rule above.

## Documented limits are the contract

The effective maximum value size is the documented one (the advertised
ceiling minus the change record's framing — see `docs/production.md`), and
it shrinks with batch size when the change log is enabled. A later 1.x may
RAISE the effective limit (the change-record split); it will not lower it.

## Environment knobs

`VYRN_PAGE_CACHE_PAGES`, `VYRN_VALUE_CACHE_BYTES`, `VYRN_ROW_CACHE_BYTES`
are stable names in 1.x. Their defaults are tuning, not contract, and may
change with a changelog note.

## Wire protocol

The protocol handshake names its version and a mismatch is a codec error,
not corruption. Within 1.x the protocol only gains optional messages;
existing message encodings do not change. Client SDKs are supported
against a server of the same or newer 1.x version.
