//! Structured, dependency-free logging for the Vyrn binaries.
//!
//! Vyrn's binaries used to diagnose themselves with bare `eprintln!`, which
//! emits lines carrying no timestamp, no severity and no machine-readable
//! structure. That is the failure mode this module exists to prevent: an
//! operator holding such a log cannot filter by severity, cannot order two
//! records in time, and cannot ship the stream to anything that indexes fields.
//! `docs/production.md` tells operators to act when "a storage error is
//! logged", which was not a thing the process could do.
//!
//! It is written by hand rather than delegated to `tracing` because this
//! workspace is deliberately dependency-light — `vyrn-core` carries five
//! dependencies, and every version is pinned once at the workspace root. A
//! subscriber crate would add a transitive tree far larger than this module for
//! a facility used at a few dozen call sites, none of them on a hot path and
//! none of them needing spans or per-span filtering.
//!
//! Records are one line each, on stderr:
//!
//! ```text
//! 2026-08-22T09:14:02.481Z WARN vyrn-http.auth bearer token rejected peer=203.0.113.7 reason=mismatch
//! ```
//!
//! `VYRN_LOG` selects the level (`off`, `error`, `warn`, `info`, `debug`,
//! `trace`; default `info`). Nothing is formatted when the level is disabled:
//! every macro tests [`enabled`] before it evaluates its message or its field
//! expressions, so a `log_debug!` on a per-request path costs one relaxed
//! atomic load in a production configuration.
//!
//! The client crate itself logs only at `debug`. A library that writes to
//! stderr behind its caller's back is a nuisance; the facility lives here
//! because this is the one crate every Vyrn binary already depends on, not
//! because the client wants a voice.
//!
//! ## Why this is its own crate
//!
//! The facility started inside `vyrn-client`, because that was the one crate
//! every binary already linked. That made `vyrnd` — a storage server — depend on
//! the client library to write a log line, which is backwards: the dependency
//! points from the thing being served toward the thing consuming it, and it
//! would drag rustls, tokio-rustls and the whole connection stack into any
//! future binary that only wanted to log. A leaf crate with no dependencies of
//! its own costs one workspace member and inverts nothing.

use std::fmt::{self, Write as _};
use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Severity, ordered so that `level <= filter` means "emit this".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Emits nothing. Only valid as a filter.
    Off = 0,
    /// The process cannot do what it was asked and an operator must act:
    /// storage failures, a background worker that will not come back.
    Error = 1,
    /// Something was refused or degraded but the process carries on:
    /// rejected credentials, a discarded connection, a failed probe.
    Warn = 2,
    /// Lifecycle. Startup with the effective configuration, bind
    /// addresses, readiness transitions, drain and shutdown, checkpoint
    /// and backup outcomes. Deliberately not per-request: a log that
    /// carries one record per key served is a log nobody keeps.
    Info = 3,
    /// Per-request and per-connection detail, for chasing a specific
    /// failure. Safe to leave off in production.
    Debug = 4,
    /// Anything finer. Currently unused; reserved so callers do not invent
    /// a competing scale.
    Trace = 5,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    /// Parses a `VYRN_LOG` value, case-insensitively.
    ///
    /// An unrecognised value returns `None` so the caller can fall back to
    /// the default rather than silently muting the log: a typo in a
    /// deployment's environment must not be the reason an incident has no
    /// diagnostics.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "silent" => Some(Self::Off),
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }
}

/// The active filter, cached as a `u8`.
///
/// `UNRESOLVED` rather than an `Option` in a lock: reading the environment
/// takes a process-wide lock inside libstd, and the level is tested before
/// every record including ones on request paths. A relaxed load of an
/// already-resolved filter is the whole cost in steady state. A race
/// between two first callers is harmless — both compute the same value from
/// the same environment and store it.
const UNRESOLVED: u8 = u8::MAX;
static FILTER: AtomicU8 = AtomicU8::new(UNRESOLVED);

/// The default when `VYRN_LOG` is unset or unparseable: lifecycle events
/// and everything worse.
const DEFAULT_LEVEL: Level = Level::Info;

fn from_environment() -> Level {
    std::env::var("VYRN_LOG")
        .ok()
        .and_then(|value| Level::parse(&value))
        .unwrap_or(DEFAULT_LEVEL)
}

/// The level currently being emitted, resolving `VYRN_LOG` on first call.
pub fn level() -> Level {
    match FILTER.load(Ordering::Relaxed) {
        UNRESOLVED => {
            let resolved = from_environment();
            FILTER.store(resolved as u8, Ordering::Relaxed);
            resolved
        }
        0 => Level::Off,
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        4 => Level::Debug,
        _ => Level::Trace,
    }
}

/// Overrides the environment for the rest of the process.
///
/// For a binary that exposes its own verbosity flag, and for tests that
/// must observe a record regardless of how the suite was invoked.
pub fn set_level(level: Level) {
    FILTER.store(level as u8, Ordering::Relaxed);
}

/// Whether a record at `level` would be emitted.
///
/// Call this before building anything: it is the guard that keeps disabled
/// levels free, and the macros in this crate apply it for you.
#[inline]
pub fn enabled(level: Level) -> bool {
    level != Level::Off && level <= level_cached()
}

#[inline]
fn level_cached() -> Level {
    // Fast path: the filter is resolved after the first record and every
    // later test is one relaxed load.
    match FILTER.load(Ordering::Relaxed) {
        UNRESOLVED => level(),
        0 => Level::Off,
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        4 => Level::Debug,
        _ => Level::Trace,
    }
}

/// One log line under construction.
///
/// The record is assembled into a single `String` and written with one
/// `write_all`, because two threads logging concurrently must not interleave
/// halves of their records: a torn line breaks every downstream parser and,
/// worse, reads as a record that nothing ever emitted.
pub struct Record {
    level: Level,
    buffer: String,
}

impl Record {
    /// Starts a record. Prefer the `log_*` macros, which test [`enabled`]
    /// first — constructing a `Record` already does the formatting work.
    pub fn new(level: Level, target: &str, message: impl fmt::Display) -> Self {
        let mut buffer = String::with_capacity(160);
        write_timestamp(&mut buffer, SystemTime::now());
        buffer.push(' ');
        buffer.push_str(level.as_str());
        buffer.push(' ');
        buffer.push_str(target);
        buffer.push(' ');
        let mut record = Self { level, buffer };
        // The message goes through the same escaping as a field value. A
        // message built from client-supplied text could otherwise carry a
        // newline and forge a second record.
        let start = record.buffer.len();
        let _ = write!(record.buffer, "{message}");
        record.escape_from(start, false);
        record
    }

    /// Appends `key=value`, quoting and escaping the value when it would
    /// otherwise be ambiguous.
    pub fn field(&mut self, key: &str, value: &dyn fmt::Display) -> &mut Self {
        self.buffer.push(' ');
        self.buffer.push_str(key);
        self.buffer.push('=');
        let start = self.buffer.len();
        let _ = write!(self.buffer, "{value}");
        self.escape_from(start, true);
        self
    }

    /// Escapes the text appended since `start`.
    ///
    /// Field values are additionally wrapped in quotes when they contain a
    /// space, an `=`, or a quote, so a value can never be mistaken for the
    /// start of the next field. Messages are escaped but never quoted —
    /// they are free prose and always the last thing before the fields.
    fn escape_from(&mut self, start: usize, quote_when_ambiguous: bool) {
        let raw = self.buffer.split_off(start);
        let needs_escape = raw
            .bytes()
            .any(|byte| byte < b' ' || byte == b'"' || byte == b'\\' || byte == 0x7f);
        let needs_quotes = quote_when_ambiguous
            && (needs_escape
                || raw.is_empty()
                || raw.bytes().any(|byte| byte == b' ' || byte == b'='));
        if !needs_escape && !needs_quotes {
            self.buffer.push_str(&raw);
            return;
        }
        if needs_quotes {
            self.buffer.push('"');
        }
        for character in raw.chars() {
            match character {
                '"' => self.buffer.push_str("\\\""),
                '\\' => self.buffer.push_str("\\\\"),
                '\n' => self.buffer.push_str("\\n"),
                '\r' => self.buffer.push_str("\\r"),
                '\t' => self.buffer.push_str("\\t"),
                // Remaining control characters become an escape rather than
                // reaching a terminal, where they would move the cursor and
                // let a log line repaint the ones above it.
                character if character.is_control() => {
                    let _ = write!(self.buffer, "\\u{{{:x}}}", character as u32);
                }
                character => self.buffer.push(character),
            }
        }
        if needs_quotes {
            self.buffer.push('"');
        }
    }

    /// Writes the record to stderr.
    ///
    /// A failed write is dropped: logging must never be the reason a
    /// request fails or a shutdown path stops early, and there is nowhere
    /// left to report a broken stderr to.
    pub fn emit(&mut self) {
        self.buffer.push('\n');
        let _ = std::io::stderr().write_all(self.buffer.as_bytes());
    }

    /// The severity this record was built at, so callers can branch on it
    /// without repeating themselves.
    pub fn level(&self) -> Level {
        self.level
    }

    /// The assembled line, without its trailing newline. For tests.
    pub fn rendered(&self) -> &str {
        &self.buffer
    }
}

/// Writes an RFC 3339 UTC timestamp with millisecond precision.
///
/// Hand-rolled from the Unix second count because pulling a date library in
/// for one format string is exactly the dependency this module is avoiding.
/// A clock stepped behind the epoch clamps to the epoch instead of
/// panicking: a logger that aborts the process on a bad clock is worse than
/// a wrong timestamp.
fn write_timestamp(buffer: &mut String, now: SystemTime) {
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = since_epoch.as_secs();
    let milliseconds = since_epoch.subsec_millis();
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let second_of_day = seconds % 86_400;
    let _ = write!(
        buffer,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z",
        hour = second_of_day / 3_600,
        minute = (second_of_day / 60) % 60,
        second = second_of_day % 60,
    );
}

/// Converts a count of days since 1970-01-01 into a civil date.
///
/// Howard Hinnant's `civil_from_days`, which shifts the era to start in
/// March so the leap day lands at the end of a year and the month-length
/// pattern becomes arithmetic. Integer-only, no table, no branch on leap
/// years.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Rewrites a `vyrn://` connection URL so it is safe to log.
///
/// A Vyrn connection URL carries the database password in its userinfo
/// component, so the one string an operator most wants in a startup record
/// is also a credential. Logged verbatim it would reach every sink,
/// archive, ticket and screenshot the record ever touches, and a password
/// that has been in a log is a password that must be rotated. This keeps
/// the parts that identify the endpoint — scheme, username, host, port,
/// database, options — and replaces the password with a fixed marker.
///
/// Deliberately string surgery rather than a URL parse. A URL that fails to
/// parse is precisely the case a startup error wants to report, so this
/// function must have an answer for malformed input instead of handing the
/// raw string back to the caller to log. Only userinfo is rewritten:
/// [`ConnectionOptions::parse`](crate::ConnectionOptions::parse) rejects
/// every query option except `tls`, so a Vyrn URL cannot legally carry a
/// secret in its query string.
pub fn redact_url(url: &str) -> String {
    let (prefix, rest) = match url.find("://") {
        Some(index) => url.split_at(index + 3),
        None => ("", url),
    };
    // A well-formed authority ends at the first path, query or fragment
    // delimiter, and the last '@' within it separates userinfo from host —
    // the last, because a password may itself contain an '@'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if let Some(separator) = rest[..authority_end].rfind('@') {
        let (userinfo, tail) = rest.split_at(separator);
        return match userinfo.split_once(':') {
            // Keep the username: which principal was used is most of the
            // diagnostic value, and a username is not a secret.
            Some((username, _)) => format!("{prefix}{username}:[REDACTED]{tail}"),
            // No password to hide. Reproduced as-is rather than gaining a
            // marker for a secret that was never there, which would have an
            // operator hunting for a credential nobody configured.
            None => url.to_owned(),
        };
    }
    // No userinfo in a well-formed reading, yet an '@' appears further
    // along: the password itself contained a '/', '?' or '#', which RFC 3986
    // requires percent-encoding inside userinfo. No parser accepts this
    // string — which is exactly why it is being logged — but it is still a
    // live credential, so redact instead of reproducing it. Everything
    // between the first ':' and the last '@' goes. That over-redacts a host
    // or path in the rare string that carries an '@' outside userinfo, and
    // over-redaction is the direction to fail in: a vague log line costs an
    // operator a minute, a leaked password costs them a rotation.
    match (rest.find(':'), rest.rfind('@')) {
        (Some(colon), Some(separator)) if colon < separator => format!(
            "{prefix}{}:[REDACTED]{}",
            &rest[..colon],
            &rest[separator..]
        ),
        _ => url.to_owned(),
    }
}

/// Emits one structured record, if `level` is enabled.
///
/// `log_record!(level, target, message, key = value, ...)`. The message and
/// every field expression are evaluated only when the level is enabled, so a
/// disabled record costs one atomic load and formats nothing.
#[macro_export]
macro_rules! log_record {
    ($level:expr, $target:expr, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {{
        let level = $level;
        if $crate::enabled(level) {
            let mut record = $crate::Record::new(level, $target, $message);
            $(record.field(stringify!($key), &$value);)*
            record.emit();
        }
    }};
}

/// The process cannot do what it was asked; an operator must act.
#[macro_export]
macro_rules! log_error {
    ($($arguments:tt)*) => {
        $crate::log_record!($crate::Level::Error, $($arguments)*)
    };
}

/// Something was refused or degraded, and the process carries on.
#[macro_export]
macro_rules! log_warn {
    ($($arguments:tt)*) => {
        $crate::log_record!($crate::Level::Warn, $($arguments)*)
    };
}

/// A lifecycle event: startup, readiness, drain, checkpoint, backup.
#[macro_export]
macro_rules! log_info {
    ($($arguments:tt)*) => {
        $crate::log_record!($crate::Level::Info, $($arguments)*)
    };
}

/// Per-request or per-connection detail, off by default in production.
#[macro_export]
macro_rules! log_debug {
    ($($arguments:tt)*) => {
        $crate::log_record!($crate::Level::Debug, $($arguments)*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64, milliseconds: u32) -> String {
        let mut buffer = String::new();
        write_timestamp(
            &mut buffer,
            UNIX_EPOCH + std::time::Duration::new(seconds, milliseconds * 1_000_000),
        );
        buffer
    }

    /// The calendar conversion is hand-rolled, so it is pinned against
    /// known epoch seconds rather than only checked for shape. A timestamp
    /// that is wrong by a day makes a log actively misleading, which is
    /// worse than one carrying no timestamp at all.
    #[test]
    fn timestamps_match_known_epoch_seconds() {
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(1, 500), "1970-01-01T00:00:01.500Z");
        // Leap day and the day after it: the month-length arithmetic is
        // where an off-by-one in this conversion shows up first.
        assert_eq!(at(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
        assert_eq!(at(1_709_251_199, 999), "2024-02-29T23:59:59.999Z");
        assert_eq!(at(1_709_251_200, 0), "2024-03-01T00:00:00.000Z");
        // 2000 is a leap year, 2100 is not; the century rules are the other
        // place this arithmetic can drift.
        assert_eq!(at(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        assert_eq!(at(4_107_542_400, 0), "2100-03-01T00:00:00.000Z");
        assert_eq!(at(1_767_225_599, 0), "2025-12-31T23:59:59.000Z");
        assert_eq!(at(1_767_225_600, 0), "2026-01-01T00:00:00.000Z");
    }

    /// A clock stepped behind the epoch clamps instead of panicking: a
    /// logger that aborts the process over a bad clock has turned a
    /// cosmetic fault into an outage.
    #[test]
    fn a_clock_before_the_epoch_does_not_panic() {
        let mut buffer = String::new();
        write_timestamp(
            &mut buffer,
            UNIX_EPOCH - std::time::Duration::from_secs(86_400),
        );
        assert_eq!(buffer, "1970-01-01T00:00:00.000Z");
    }
    /// A Vyrn URL carries the password in its userinfo, so a startup record
    /// that logged one verbatim would put a live credential into every sink the
    /// log reaches. These are the shapes that must survive redaction.
    #[test]
    fn url_redaction_removes_the_password_and_keeps_the_endpoint() {
        let redacted = redact_url("vyrn://alica:s3cr3t@db.internal:7432/app?tls=require");
        assert_eq!(
            redacted,
            "vyrn://alica:[REDACTED]@db.internal:7432/app?tls=require"
        );
        assert!(!redacted.contains("s3cr3t"));
    }

    #[test]
    fn url_redaction_survives_awkward_passwords() {
        // A password may contain '@', ':', '/' and '?'. Splitting on the first
        // '@' or treating the first '/' as the path would leak a fragment of it.
        for (url, secret) in [
            ("vyrn://user:p@ss@host/app", "p@ss"),
            ("vyrn://user:a:b:c@host:7432/app", "a:b:c"),
            ("vyrn://user:pa/ss@host/app", "pa/ss"),
            ("vyrn://user:pa?ss@host/app?tls=disable", "pa?ss"),
            ("vyrn://user:pass#@host/app", "pass#"),
            // Not a URL at all: the caller is logging whatever the operator
            // supplied, and a parse failure is exactly when it must stay safe.
            ("user:hunter2@host", "hunter2"),
        ] {
            let redacted = redact_url(url);
            assert!(
                !redacted.contains(secret),
                "password leaked from {url}: {redacted}"
            );
            assert!(redacted.contains("[REDACTED]"), "{url} -> {redacted}");
        }
    }

    #[test]
    fn url_redaction_leaves_credential_free_urls_intact() {
        // Nothing to hide, so nothing is invented: an operator reading
        // "[REDACTED]" would otherwise conclude a password was configured.
        assert_eq!(redact_url("vyrn://host:7432/app"), "vyrn://host:7432/app");
        assert_eq!(redact_url("vyrn://user@host/app"), "vyrn://user@host/app");
        assert_eq!(redact_url("127.0.0.1:7433"), "127.0.0.1:7433");
    }

    #[test]
    fn records_carry_a_timestamp_level_and_target() {
        let record = Record::new(Level::Warn, "vyrn-http.auth", "token rejected");
        let rendered = record.rendered();
        // 2026-08-22T09:14:02.481Z WARN vyrn-http.auth token rejected
        let (timestamp, rest) = rendered.split_once(' ').expect("timestamp then the rest");
        assert_eq!(timestamp.len(), 24, "{timestamp}");
        assert!(
            timestamp.ends_with('Z') && timestamp.contains('T'),
            "{timestamp}"
        );
        assert!(
            rest.starts_with("WARN vyrn-http.auth token rejected"),
            "{rest}"
        );
    }

    #[test]
    fn fields_are_appended_as_key_value_pairs() {
        let mut record = Record::new(Level::Info, "vyrn-http", "listening");
        record.field("bind", &"127.0.0.1:7434").field("tls", &false);
        assert!(
            record
                .rendered()
                .ends_with("listening bind=127.0.0.1:7434 tls=false"),
            "{}",
            record.rendered()
        );
    }

    /// A field value built from client-supplied text must not be able to end
    /// its own record: a newline would forge a second line that no code emitted,
    /// and an unquoted space would move the rest of the value into a new key.
    #[test]
    fn field_values_cannot_forge_a_second_record() {
        let mut record = Record::new(Level::Error, "vyrn-http", "upstream failed");
        record.field(
            "detail",
            &"line one\n2026-08-22T00:00:00.000Z INFO forged all clear",
        );
        let rendered = record.rendered();
        assert_eq!(rendered.lines().count(), 1, "{rendered}");
        assert!(rendered.contains("\\n"), "{rendered}");
        assert!(rendered.contains(r#"detail=""#), "{rendered}");
    }

    #[test]
    fn messages_are_escaped_too() {
        let record = Record::new(Level::Error, "vyrn-http", "first\nsecond");
        assert_eq!(record.rendered().lines().count(), 1);
        assert!(record.rendered().ends_with("first\\nsecond"));
    }

    #[test]
    fn level_filtering_follows_the_configured_level() {
        assert_eq!(Level::parse("WARN"), Some(Level::Warn));
        assert_eq!(Level::parse(" debug "), Some(Level::Debug));
        // An unparseable VYRN_LOG must not mute the log: a typo in a
        // deployment's environment cannot be the reason an incident has no
        // diagnostics.
        assert_eq!(Level::parse("verbose"), None);

        let restore = level();
        set_level(Level::Warn);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));
        set_level(Level::Off);
        assert!(!enabled(Level::Error));
        // `Off` is a filter, never a record's own severity.
        assert!(!enabled(Level::Off));
        set_level(restore);
    }

    /// The macros must not evaluate their arguments when the level is off —
    /// that is what keeps a `log_debug!` affordable on a per-request path.
    #[test]
    fn disabled_records_evaluate_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static EVALUATIONS: AtomicUsize = AtomicUsize::new(0);

        fn expensive() -> usize {
            EVALUATIONS.fetch_add(1, Ordering::Relaxed)
        }

        let restore = level();
        set_level(Level::Off);
        log_debug!(
            "vyrn-client.test",
            format!("{}", expensive()),
            field = expensive()
        );
        assert_eq!(EVALUATIONS.load(Ordering::Relaxed), 0);
        set_level(restore);
    }
}
