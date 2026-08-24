//! The append-only audit trail (`VYRN_AUDIT_LOG`).
//!
//! One line per event, in the same shape as the server log (RFC 3339 UTC
//! timestamp, single `write` per line so concurrent sessions cannot interleave
//! halves of a record), but to its own file: the audit trail answers "who did
//! what", which must survive log levels and must not be diluted by operational
//! records. Recorded events: authentication outcomes, every write, delete, and
//! DDL operation with its result, and every permission denial. Reads join only
//! under `VYRN_AUDIT_READS=1` — they dominate most workloads and the trail
//! must stay affordable to keep.
//!
//! VALUES AND CREDENTIALS NEVER APPEAR HERE. Keys, prefixes, usernames, and
//! results do; payloads and anything password-shaped do not.
//!
//! BEST-EFFORT BY CONTRACT (see docs/security.md): a commit is never blocked
//! on the audit file and no fsync is issued for it. A write failure is
//! reported to stderr once per failure streak and the server keeps serving —
//! losing an audit line is recoverable, losing an acknowledged write is not.

use anyhow::{Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use vyrn_log::{log_error, Level, Record};

use crate::auth::Intent;

pub struct AuditLog {
    file: Mutex<File>,
    audit_reads: bool,
    /// Set while writes are failing, so a full disk reports once instead of
    /// once per operation.
    failing: AtomicBool,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open audit log {}", path.display()))?;
        let audit_reads = std::env::var("VYRN_AUDIT_READS")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(Self {
            file: Mutex::new(file),
            audit_reads,
            failing: AtomicBool::new(false),
        })
    }

    /// An authentication attempt's outcome. `user` must already be safe to
    /// record: a caller passes a real account name or `"unknown"`, never the
    /// raw string a peer supplied.
    pub fn auth(&self, outcome: &str, user: &str, peer: &dyn std::fmt::Display) {
        let mut record = Record::new(Level::Info, "vyrnd.audit", "auth");
        record
            .field("outcome", &outcome)
            .field("user", &user)
            .field("peer", peer);
        self.write(record);
    }

    /// A permitted operation and how it ended. Reads are dropped unless the
    /// operator opted into them.
    pub fn operation(&self, user: &str, intent: &Intent, result: &str) {
        if intent.read && !self.audit_reads {
            return;
        }
        let mut record = Record::new(Level::Info, "vyrnd.audit", "operation");
        record
            .field("user", &user)
            .field("op", &intent.op)
            .field("scope", &intent.scope)
            .field("result", &result);
        self.write(record);
    }

    /// A refused operation. Always recorded — denials are the events an audit
    /// trail exists for, whatever the read setting says.
    pub fn denied(&self, user: &str, op: &str, scope: &str) {
        let mut record = Record::new(Level::Info, "vyrnd.audit", "denied");
        record
            .field("user", &user)
            .field("op", &op)
            .field("scope", &scope);
        self.write(record);
    }

    fn write(&self, record: Record) {
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        let mut line = record.rendered().to_owned();
        line.push('\n');
        match file.write_all(line.as_bytes()) {
            Ok(()) => self.failing.store(false, Ordering::Relaxed),
            Err(error) => {
                if !self.failing.swap(true, Ordering::Relaxed) {
                    log_error!(
                        "vyrnd.audit",
                        "audit write failed; continuing to serve without the trail",
                        detail = error
                    );
                }
            }
        }
    }
}
