//! Per-user accounts, prefix ACLs, and the authorization decision.
//!
//! Two modes, chosen at startup and mutually exclusive:
//!
//! - **Single credential** (`VYRN_PASSWORD_HASH_FILE`): the pre-1.1 model, one
//!   username and one Argon2id verifier. The authenticated session holds every
//!   permission, so enforcement is a no-op and the wire behaviour is
//!   byte-for-byte what it was — this mode is the compatibility contract.
//! - **Users file** (`VYRN_USERS_FILE`): a JSON array of
//!   `{"user", "phc", "permissions": [{"prefix", "access"}]}` entries. The file
//!   is re-checked (mtime + length) on every authentication attempt, so adding,
//!   removing, or re-scoping a user needs no restart. Each successful reload
//!   bumps a generation counter; live sessions compare it on every operation,
//!   which is what makes removal from the file take effect mid-session.
//!
//! Access levels nest: `write` implies `read` on the same prefix, `admin`
//! implies both and additionally permits DDL and other admin operations. A
//! grant's empty prefix means the whole keyspace. Secondary indexes span the
//! whole keyspace by construction — a lookup returns primary keys from
//! anywhere — so index DDL, index mutation, and index lookups require the
//! corresponding access on the empty prefix rather than on any narrower one.

use anyhow::{bail, Context, Result};
use argon2::{password_hash::PasswordHashString, Argon2, PasswordHasher, PasswordVerifier};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock, RwLock,
    },
    time::SystemTime,
};
use vyrn_log::{log_error, log_warn};
use vyrn_protocol::Message;

/// What a grant permits, ordered so `write` implies `read` and `admin` implies
/// both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    Read,
    Write,
    Admin,
}

impl Access {
    fn allows(self, required: Access) -> bool {
        self >= required
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// One `{"prefix", "access"}` entry: `access` on every key starting with
/// `prefix`.
struct Grant {
    prefix: Vec<u8>,
    access: Access,
}

/// A user's merged grants. Deny-by-default: an operation is permitted only if
/// some grant covers it.
pub struct Permissions {
    grants: Vec<Grant>,
}

impl Permissions {
    /// The single-credential session: admin on the whole keyspace.
    fn all() -> Self {
        Self {
            grants: vec![Grant {
                prefix: Vec::new(),
                access: Access::Admin,
            }],
        }
    }

    /// Whether one key is covered: some grant's prefix is a prefix of `key`.
    fn allows_key(&self, required: Access, key: &[u8]) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.access.allows(required) && key.starts_with(&grant.prefix))
    }

    /// Whether every key under `prefix` is covered — the subscription check.
    /// The requested prefix must extend a granted one, not the reverse: a
    /// grant on `app/` covers a subscription to `app/user/`, never vice versa.
    fn allows_prefix(&self, required: Access, prefix: &[u8]) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.access.allows(required) && prefix.starts_with(&grant.prefix))
    }

    /// Whether every key in `[start, end)` is covered by a single grant.
    ///
    /// The keys with prefix `p` are exactly `[p, upper_bound(p))`, so the range
    /// is covered when `start` carries the grant's prefix and `end` does not
    /// exceed that bound. Unbounded ends are covered only by a grant whose
    /// prefix reaches the top of the keyspace (empty, or all `0xff`).
    fn allows_range(&self, required: Access, start: Option<&[u8]>, end: Option<&[u8]>) -> bool {
        self.grants.iter().any(|grant| {
            if !grant.access.allows(required) {
                return false;
            }
            if grant.prefix.is_empty() {
                return true;
            }
            if !start.is_some_and(|start| start.starts_with(&grant.prefix)) {
                return false;
            }
            match prefix_upper_bound(&grant.prefix) {
                Some(bound) => end.is_some_and(|end| end <= bound.as_slice()),
                None => true,
            }
        })
    }
}

/// The smallest key greater than every key with `prefix`, or `None` when the
/// prefix is all `0xff` bytes and no such key exists.
fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut bound = prefix.to_vec();
    while let Some(last) = bound.last_mut() {
        if *last < 0xff {
            *last += 1;
            return Some(bound);
        }
        bound.pop();
    }
    None
}

/// A user as loaded from the users file. Several entries naming the same user
/// merge: any listed verifier authenticates (which is what makes credential
/// rotation a file edit), and the grants are the union.
struct LoadedUser {
    verifiers: Vec<PasswordHashString>,
    permissions: Arc<Permissions>,
}

/// The parsed users file plus the stamp it was parsed from.
struct Loaded {
    users: HashMap<String, LoadedUser>,
    stamp: Option<Stamp>,
    generation: u64,
}

/// What decides whether the file must be re-read. Length is included because
/// filesystems with coarse mtime can miss two writes in one tick.
#[derive(PartialEq, Eq, Clone, Copy)]
struct Stamp {
    modified: SystemTime,
    len: u64,
}

pub struct Registry {
    path: PathBuf,
    /// Mirror of `Loaded::generation`, so the per-operation freshness check is
    /// one relaxed load instead of a lock.
    generation: AtomicU64,
    state: RwLock<Loaded>,
}

/// The credential store the server was started with.
pub enum Authenticator {
    Single {
        username: String,
        hash: PasswordHashString,
    },
    Users(Registry),
}

/// What one authenticated connection is allowed to do, refreshed against the
/// registry's generation on every operation.
pub struct SessionAuth {
    pub user: String,
    pub permissions: Arc<Permissions>,
    generation: u64,
}

pub enum AuthOutcome {
    Granted(SessionAuth),
    /// `known_user` carries the attempted username only when it names a real
    /// account: an unknown "username" is as likely to be a mistyped password,
    /// and those must never reach a log or the audit trail.
    Refused {
        known_user: Option<String>,
    },
}

/// The per-operation freshness verdict.
pub enum Refresh {
    Active,
    /// The user is gone from the reloaded file; the session must terminate.
    Revoked,
}

impl Authenticator {
    pub fn single(username: String, hash: PasswordHashString) -> Self {
        Self::Single { username, hash }
    }

    /// Loads the users file once, failing startup on an unreadable or invalid
    /// file — a server that starts with nobody able to authenticate helps no
    /// one. Later reload failures keep the last good set instead (see
    /// [`Registry::reload_if_changed`]).
    pub fn users(path: PathBuf) -> Result<Self> {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read users file {}", path.display()))?;
        let users =
            parse_users(&text).with_context(|| format!("invalid users file {}", path.display()))?;
        let stamp = std::fs::metadata(&path).ok().map(|metadata| Stamp {
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            len: metadata.len(),
        });
        Ok(Self::Users(Registry {
            path,
            generation: AtomicU64::new(1),
            state: RwLock::new(Loaded {
                users,
                stamp,
                generation: 1,
            }),
        }))
    }

    /// Verifies a credential. Blocking (Argon2 plus possibly a file re-read);
    /// call from a blocking context.
    pub fn authenticate(&self, username: &str, password: &str) -> AuthOutcome {
        match self {
            Self::Single {
                username: expected,
                hash,
            } => {
                let verified = Argon2::default()
                    .verify_password(password.as_bytes(), &hash.password_hash())
                    .is_ok();
                if verified && username == expected {
                    AuthOutcome::Granted(SessionAuth {
                        user: expected.clone(),
                        permissions: Arc::new(Permissions::all()),
                        generation: 0,
                    })
                } else {
                    AuthOutcome::Refused {
                        known_user: (username == expected).then(|| expected.clone()),
                    }
                }
            }
            Self::Users(registry) => registry.authenticate(username, password),
        }
    }

    /// Re-checks a session against the current user set. One relaxed load when
    /// nothing has been reloaded, which is the per-operation steady state.
    pub fn refresh(&self, session: &mut SessionAuth) -> Refresh {
        let Self::Users(registry) = self else {
            return Refresh::Active;
        };
        if registry.generation.load(Ordering::Acquire) == session.generation {
            return Refresh::Active;
        }
        // Fail closed: a poisoned registry must not freeze stale permissions
        // into every live session.
        let Ok(loaded) = registry.state.read() else {
            return Refresh::Revoked;
        };
        match loaded.users.get(&session.user) {
            Some(user) => {
                session.permissions = Arc::clone(&user.permissions);
                session.generation = loaded.generation;
                Refresh::Active
            }
            None => Refresh::Revoked,
        }
    }
}

impl Registry {
    fn authenticate(&self, username: &str, password: &str) -> AuthOutcome {
        self.reload_if_changed();
        let Ok(loaded) = self.state.read() else {
            return AuthOutcome::Refused { known_user: None };
        };
        let generation = loaded.generation;
        let Some(user) = loaded.users.get(username) else {
            drop(loaded);
            /* An unknown username still pays for one verification, so response
             * time does not reveal which usernames exist. */
            let _ = Argon2::default().verify_password(password.as_bytes(), &dummy_verifier());
            return AuthOutcome::Refused { known_user: None };
        };
        let verified = user.verifiers.iter().any(|verifier| {
            Argon2::default()
                .verify_password(password.as_bytes(), &verifier.password_hash())
                .is_ok()
        });
        if verified {
            AuthOutcome::Granted(SessionAuth {
                user: username.to_owned(),
                permissions: Arc::clone(&user.permissions),
                generation,
            })
        } else {
            AuthOutcome::Refused {
                known_user: Some(username.to_owned()),
            }
        }
    }

    /// Re-reads the users file when its stamp has moved.
    ///
    /// A file that fails to parse KEEPS THE LAST GOOD SET rather than emptying
    /// it: a typo saved mid-edit must not lock every operator out. The failure
    /// is logged and retried on the next attempt, so fixing the file recovers
    /// without a restart. A file that fails to stat is treated the same way.
    fn reload_if_changed(&self) {
        let stamp = match std::fs::metadata(&self.path) {
            Ok(metadata) => Stamp {
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                len: metadata.len(),
            },
            Err(error) => {
                log_warn!(
                    "vyrnd.auth",
                    "users file cannot be checked; keeping the loaded users",
                    path = self.path.display(),
                    detail = error
                );
                return;
            }
        };
        if let Ok(loaded) = self.state.read() {
            if loaded.stamp == Some(stamp) {
                return;
            }
        }
        let parsed = std::fs::read_to_string(&self.path)
            .map_err(anyhow::Error::from)
            .and_then(|text| parse_users(&text));
        let users = match parsed {
            Ok(users) => users,
            Err(error) => {
                log_error!(
                    "vyrnd.auth",
                    "users file reload failed; keeping the previously loaded users",
                    path = self.path.display(),
                    detail = format!("{error:#}")
                );
                return;
            }
        };
        let Ok(mut loaded) = self.state.write() else {
            return;
        };
        // Another authentication may have reloaded the same revision already.
        if loaded.stamp == Some(stamp) {
            return;
        }
        loaded.users = users;
        loaded.stamp = Some(stamp);
        loaded.generation += 1;
        self.generation.store(loaded.generation, Ordering::Release);
    }
}

/// The verifier unknown usernames are checked against, so the refusal costs the
/// same Argon2 work either way. Hashed once per process.
fn dummy_verifier() -> argon2::PasswordHash<'static> {
    static DUMMY: OnceLock<PasswordHashString> = OnceLock::new();
    DUMMY
        .get_or_init(|| {
            let salt = argon2::password_hash::SaltString::from_b64("dnlybmR1bW15c2FsdA")
                .expect("valid salt");
            Argon2::default()
                .hash_password(b"vyrn-unknown-user-padding", &salt)
                .expect("hash dummy password")
                .serialize()
        })
        .password_hash()
}

/// Parses the `VYRN_USERS_FILE` format: a JSON array of
/// `{"user": "...", "phc": "$argon2id$...", "permissions":
/// [{"prefix": "...", "access": "read" | "write" | "admin"}]}`.
///
/// Strict on purpose — an unknown field or access level is refused rather than
/// ignored, because a misspelled `"acess"` silently granting nothing (or a
/// future field silently granting everything) is exactly the failure an access
/// control file must not have.
fn parse_users(text: &str) -> Result<HashMap<String, LoadedUser>> {
    let root: serde_json::Value =
        serde_json::from_str(text).context("users file is not valid JSON")?;
    let entries = root.as_array().context("users file must be a JSON array")?;
    let mut merged: HashMap<String, (Vec<PasswordHashString>, Vec<Grant>)> = HashMap::new();
    for entry in entries {
        let object = entry
            .as_object()
            .context("each users-file entry must be an object")?;
        for field in object.keys() {
            if !matches!(field.as_str(), "user" | "phc" | "permissions") {
                bail!("unknown users-file field {field:?}");
            }
        }
        let user = object
            .get("user")
            .and_then(serde_json::Value::as_str)
            .filter(|user| !user.is_empty())
            .context("each entry needs a non-empty string \"user\"")?;
        let phc = object
            .get("phc")
            .and_then(serde_json::Value::as_str)
            .context("each entry needs a \"phc\" string")?;
        if !phc.starts_with("$argon2id$") {
            bail!("user {user:?}: \"phc\" must be an Argon2id PHC string");
        }
        let phc = PasswordHashString::new(phc)
            .map_err(|_| anyhow::anyhow!("user {user:?}: \"phc\" is not a valid PHC string"))?;
        let permissions = object
            .get("permissions")
            .and_then(serde_json::Value::as_array)
            .context("each entry needs a \"permissions\" array")?;
        let mut grants = Vec::new();
        for grant in permissions {
            let grant = grant
                .as_object()
                .context("each permission must be an object")?;
            for field in grant.keys() {
                if !matches!(field.as_str(), "prefix" | "access") {
                    bail!("unknown permission field {field:?}");
                }
            }
            let prefix = grant
                .get("prefix")
                .and_then(serde_json::Value::as_str)
                .context("each permission needs a \"prefix\" string (empty = whole keyspace)")?;
            let access = grant
                .get("access")
                .and_then(serde_json::Value::as_str)
                .and_then(Access::parse)
                .context("each permission needs \"access\": \"read\", \"write\", or \"admin\"")?;
            grants.push(Grant {
                prefix: prefix.as_bytes().to_vec(),
                access,
            });
        }
        let entry = merged.entry(user.to_owned()).or_default();
        entry.0.push(phc);
        entry.1.extend(grants);
    }
    if merged.is_empty() {
        bail!("users file names no users");
    }
    Ok(merged
        .into_iter()
        .map(|(user, (verifiers, grants))| {
            (
                user,
                LoadedUser {
                    verifiers,
                    permissions: Arc::new(Permissions { grants }),
                },
            )
        })
        .collect())
}

/// A refused operation, carrying what the error message and the audit line
/// need.
pub struct Denial {
    pub op: &'static str,
    pub scope: String,
}

/// What the audit trail records about a permitted operation.
pub struct Intent {
    pub op: &'static str,
    pub scope: String,
    /// Reads are audited only under `VYRN_AUDIT_READS=1`.
    pub read: bool,
}

/// What one request needs, in the permission model's terms.
enum Requirement<'a> {
    /// No data access of its own (Begin, Rollback, Commit — the operations
    /// inside a transaction were each checked as they arrived).
    None,
    Key(Access, &'a [u8]),
    EachKey(Access, &'a [Vec<u8>]),
    Prefix(Access, Vec<u8>),
    Range(Access, Option<&'a [u8]>, Option<&'a [u8]>),
}

struct Classified<'a> {
    op: &'static str,
    read: bool,
    requirement: Requirement<'a>,
    /// Audit scope when it reads better than raw key bytes (collections).
    scope: Option<String>,
}

/// Maps a request to its requirement. `None` for messages that are not
/// requests (responses, replica frames past the handshake); the dispatcher
/// refuses those on its own and they touch no data.
fn classify(message: &Message) -> Option<Classified<'_>> {
    use Access::{Admin, Read, Write};
    let classified = match message {
        Message::Get { key } => Classified {
            op: "get",
            read: true,
            requirement: Requirement::Key(Read, key),
            scope: None,
        },
        Message::MultiGet { keys } => Classified {
            op: "multi-get",
            read: true,
            requirement: Requirement::EachKey(Read, keys),
            scope: Some(format!("{} keys", keys.len())),
        },
        Message::Put { key, .. } => Classified {
            op: "put",
            read: false,
            requirement: Requirement::Key(Write, key),
            scope: None,
        },
        Message::Delete { key } => Classified {
            op: "delete",
            read: false,
            requirement: Requirement::Key(Write, key),
            scope: None,
        },
        Message::Scan { start, end, .. } => Classified {
            op: "scan",
            read: true,
            requirement: Requirement::Range(Read, start.as_deref(), end.as_deref()),
            scope: None,
        },
        Message::Subscribe { prefix } | Message::SubscribeFrom { prefix, .. } => Classified {
            op: "subscribe",
            read: true,
            requirement: Requirement::Prefix(Read, prefix.clone()),
            scope: None,
        },
        Message::SubscribeCollection { collection }
        | Message::SubscribeCollectionFrom { collection, .. } => Classified {
            op: "subscribe-collection",
            read: true,
            requirement: collection_requirement(Read, collection),
            scope: Some(collection.clone()),
        },
        /* Collection DDL is scoped to the collection's own key prefix, so an
         * admin over one application prefix can manage its collections without
         * holding the whole keyspace. */
        Message::CreateCollection { collection, .. } => Classified {
            op: "create-collection",
            read: false,
            requirement: collection_requirement(Admin, collection),
            scope: Some(collection.clone()),
        },
        Message::PutDocument { collection, id, .. } => Classified {
            op: "put-document",
            read: false,
            requirement: collection_requirement(Write, collection),
            scope: Some(format!("{collection}/{id}")),
        },
        Message::DeleteDocument { collection, id } => Classified {
            op: "delete-document",
            read: false,
            requirement: collection_requirement(Write, collection),
            scope: Some(format!("{collection}/{id}")),
        },
        Message::GetDocument { collection, .. }
        | Message::ListDocuments { collection, .. }
        | Message::QueryDocuments { collection, .. } => Classified {
            op: "read-documents",
            read: true,
            requirement: collection_requirement(Read, collection),
            scope: Some(collection.clone()),
        },
        /* Secondary indexes span the whole keyspace — a lookup returns primary
         * keys from anywhere and an update rewrites entries any reader sees —
         * so nothing narrower than a whole-keyspace grant is sound here. */
        Message::CreateIndex { .. } => Classified {
            op: "create-index",
            read: false,
            requirement: Requirement::Prefix(Admin, Vec::new()),
            scope: None,
        },
        Message::DropIndex { .. } => Classified {
            op: "drop-index",
            read: false,
            requirement: Requirement::Prefix(Admin, Vec::new()),
            scope: None,
        },
        Message::IndexUpdate { .. } => Classified {
            op: "index-update",
            read: false,
            requirement: Requirement::Prefix(Write, Vec::new()),
            scope: None,
        },
        Message::IndexLookup { .. } => Classified {
            op: "index-lookup",
            read: true,
            requirement: Requirement::Prefix(Read, Vec::new()),
            scope: None,
        },
        // Streams every committed record, so it is a whole-keyspace read that
        // only a whole-keyspace administrator may open.
        Message::ReplicaHello { .. } => Classified {
            op: "replica-stream",
            read: true,
            requirement: Requirement::Prefix(Admin, Vec::new()),
            scope: None,
        },
        // A vote decides who may serve the whole keyspace, so requesting one
        // is gated exactly like the replica handshake.
        Message::VoteRequest { .. } => Classified {
            op: "vote-request",
            read: true,
            requirement: Requirement::Prefix(Admin, Vec::new()),
            scope: None,
        },
        Message::Commit => Classified {
            op: "commit",
            read: false,
            requirement: Requirement::None,
            scope: None,
        },
        _ => return None,
    };
    Some(classified)
}

/// A collection's underlying key prefix. An invalid collection name yields an
/// impossible requirement here only if it would grant something; instead it is
/// passed through as no requirement, because the dispatcher rejects the name
/// before touching any key.
fn collection_requirement(access: Access, collection: &str) -> Requirement<'static> {
    match vyrn_core::document::collection_key_prefix(collection) {
        Ok(prefix) => Requirement::Prefix(access, prefix),
        Err(_) => Requirement::None,
    }
}

/// The single authorization decision, applied to every decoded request before
/// it is dispatched. `Ok` carries the audit intent when `want_intent` (the
/// audit log is configured); building it costs a rendering, so it is skipped
/// otherwise.
pub fn authorize(
    permissions: &Permissions,
    message: &Message,
    want_intent: bool,
) -> std::result::Result<Option<Intent>, Denial> {
    let Some(classified) = classify(message) else {
        return Ok(None);
    };
    let allowed = match &classified.requirement {
        Requirement::None => true,
        Requirement::Key(access, key) => permissions.allows_key(*access, key),
        Requirement::EachKey(access, keys) => {
            if let Some(denied) = keys
                .iter()
                .find(|key| !permissions.allows_key(*access, key))
            {
                return Err(Denial {
                    op: classified.op,
                    scope: render_bytes(denied),
                });
            }
            true
        }
        Requirement::Prefix(access, prefix) => permissions.allows_prefix(*access, prefix),
        Requirement::Range(access, start, end) => permissions.allows_range(*access, *start, *end),
    };
    if !allowed {
        return Err(Denial {
            op: classified.op,
            scope: requirement_scope(&classified),
        });
    }
    Ok(want_intent.then(|| Intent {
        op: classified.op,
        scope: requirement_scope(&classified),
        read: classified.read,
    }))
}

fn requirement_scope(classified: &Classified<'_>) -> String {
    if let Some(scope) = &classified.scope {
        return scope.clone();
    }
    match &classified.requirement {
        Requirement::None => "-".to_owned(),
        Requirement::Key(_, key) => render_bytes(key),
        Requirement::EachKey(_, keys) => format!("{} keys", keys.len()),
        Requirement::Prefix(_, prefix) => render_bytes(prefix),
        Requirement::Range(_, start, end) => format!(
            "{}..{}",
            start.map_or_else(String::new, render_bytes),
            end.map_or_else(String::new, render_bytes),
        ),
    }
}

/// Keys and prefixes as one printable token: ASCII stays, everything else
/// becomes `\xNN`. Empty renders as `<all>`, which is what an empty prefix
/// means. NEVER applied to values — values do not reach denials or the audit
/// trail at all.
pub fn render_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<all>".to_owned();
    }
    let mut rendered = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b' '..=b'~' if byte != b'\\' => rendered.push(byte as char),
            _ => rendered.push_str(&format!("\\x{byte:02x}")),
        }
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permissions(grants: &[(&[u8], Access)]) -> Permissions {
        Permissions {
            grants: grants
                .iter()
                .map(|(prefix, access)| Grant {
                    prefix: prefix.to_vec(),
                    access: *access,
                })
                .collect(),
        }
    }

    #[test]
    fn write_implies_read_and_admin_implies_both() {
        let writer = permissions(&[(b"app/", Access::Write)]);
        assert!(writer.allows_key(Access::Read, b"app/x"));
        assert!(writer.allows_key(Access::Write, b"app/x"));
        assert!(!writer.allows_key(Access::Admin, b"app/x"));
        let admin = permissions(&[(b"app/", Access::Admin)]);
        assert!(admin.allows_key(Access::Read, b"app/x"));
        assert!(admin.allows_key(Access::Write, b"app/x"));
    }

    #[test]
    fn prefixes_isolate_in_both_directions() {
        let scoped = permissions(&[(b"app/", Access::Write)]);
        assert!(!scoped.allows_key(Access::Read, b"other/x"));
        assert!(!scoped.allows_key(Access::Read, b"ap"));
        // A grant on a DEEPER prefix must not cover the shallower subscription.
        assert!(!scoped.allows_prefix(Access::Read, b"a"));
        assert!(scoped.allows_prefix(Access::Read, b"app/user/"));
    }

    #[test]
    fn range_cover_respects_the_prefix_upper_bound() {
        let scoped = permissions(&[(b"app/", Access::Read)]);
        assert!(scoped.allows_range(Access::Read, Some(b"app/a"), Some(b"app/z")));
        // The exclusive end may be the prefix's own upper bound ("app0").
        assert!(scoped.allows_range(Access::Read, Some(b"app/"), Some(b"app0")));
        assert!(!scoped.allows_range(Access::Read, Some(b"app/"), Some(b"apq")));
        assert!(!scoped.allows_range(Access::Read, Some(b"app/"), None));
        assert!(!scoped.allows_range(Access::Read, None, Some(b"app/z")));
        let all = permissions(&[(b"", Access::Read)]);
        assert!(all.allows_range(Access::Read, None, None));
        // A prefix of all 0xff bytes reaches the top of the keyspace, so an
        // unbounded end is covered.
        let top = permissions(&[(b"\xff\xff", Access::Read)]);
        assert!(top.allows_range(Access::Read, Some(b"\xff\xffa"), None));
    }

    #[test]
    fn users_file_rejects_unknown_fields_and_access_levels() {
        assert!(
            parse_users(r#"[{"user":"a","phc":"$argon2id$x","permissions":[],"extra":1}]"#)
                .is_err()
        );
        assert!(parse_users(
            r#"[{"user":"a","phc":"$argon2id$x","permissions":[{"prefix":"","access":"owner"}]}]"#
        )
        .is_err());
        assert!(parse_users("[]").is_err());
    }
}
