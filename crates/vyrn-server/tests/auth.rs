//! Per-user accounts, prefix ACLs, revocation, and the audit trail, exercised
//! against the shipped `vyrnd` binary over plaintext loopback — the same shape
//! as `hardening.rs`, and for the same reason: what a credential can and
//! cannot do is only proven on the real socket path.

use std::{
    io::Write as _,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// A spawned node, killed on drop so a failing assertion cannot leak a process.
struct Node {
    child: Child,
    port: u16,
    admin_port: u16,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn url(&self, user: &str, password: &str) -> String {
        format!(
            "vyrn://{user}:{password}@127.0.0.1:{}/default?tls=disable",
            self.port
        )
    }

    /// Waits until the admin endpoint answers, so tests never race startup.
    fn wait_ready(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if http_get(self.admin_port, "/health/live").is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

fn vyrnd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vyrnd"))
}

/// An Argon2id PHC string for `password`. Fixed salt, as in `hardening.rs`:
/// these credentials are constants in a test whose directory is deleted, so a
/// per-run salt would protect nothing.
fn phc(password: &str) -> String {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::from_b64("dmVyeXNhbHR5c2FsdA").expect("valid salt");
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("hash password")
        .to_string()
}

/// One users-file entry; `grants` are `(prefix, access)` pairs.
fn user_entry(user: &str, password: &str, grants: &[(&str, &str)]) -> String {
    let permissions: Vec<String> = grants
        .iter()
        .map(|(prefix, access)| format!(r#"{{"prefix":"{prefix}","access":"{access}"}}"#))
        .collect();
    format!(
        r#"{{"user":"{user}","phc":"{}","permissions":[{}]}}"#,
        phc(password),
        permissions.join(",")
    )
}

fn write_users_file(path: &Path, entries: &[String]) {
    std::fs::write(path, format!("[{}]", entries.join(","))).expect("write users file");
}

/// Spawns a users-file node, optionally with an audit log and read auditing.
fn spawn_users(data: &Path, users: &Path, audit: Option<&Path>, audit_reads: bool) -> Node {
    let port = free_port();
    let admin_port = free_port();
    let mut command = Command::new(vyrnd());
    command
        .env("VYRN_BIND", format!("127.0.0.1:{port}"))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("VYRN_DATA", data)
        .env("VYRN_USERS_FILE", users)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        .env_remove("VYRN_PASSWORD_HASH_FILE")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(audit) = audit {
        command.env("VYRN_AUDIT_LOG", audit);
    }
    if audit_reads {
        command.env("VYRN_AUDIT_READS", "1");
    }
    let child = command.spawn().expect("spawn vyrnd");
    let node = Node {
        child,
        port,
        admin_port,
    };
    assert!(
        node.wait_ready(Duration::from_secs(30)),
        "node did not become ready"
    );
    node
}

fn http_get(port: u16, path: &str) -> Option<String> {
    use std::io::Read;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime")
}

fn put(url: &str, key: &[u8], value: &[u8]) -> Result<(), vyrn_client::Error> {
    runtime().block_on(async {
        let mut client = vyrn_client::Client::connect(url).await?;
        client.put(key.to_vec(), value.to_vec()).await
    })
}

fn get(url: &str, key: &[u8]) -> Result<Option<Vec<u8>>, vyrn_client::Error> {
    runtime().block_on(async {
        let mut client = vyrn_client::Client::connect(url).await?;
        client.get(key.to_vec()).await
    })
}

fn delete(url: &str, key: &[u8]) -> Result<bool, vyrn_client::Error> {
    runtime().block_on(async {
        let mut client = vyrn_client::Client::connect(url).await?;
        client.delete(key.to_vec()).await
    })
}

fn create_index(url: &str, name: &[u8]) -> Result<(), vyrn_client::Error> {
    runtime().block_on(async {
        let mut client = vyrn_client::Client::connect(url).await?;
        client.create_index(name.to_vec(), false).await
    })
}

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

fn scan(url: &str, start: Option<&[u8]>, end: Option<&[u8]>) -> Result<Rows, vyrn_client::Error> {
    runtime().block_on(async {
        let mut client = vyrn_client::Client::connect(url).await?;
        client
            .scan(start.map(<[u8]>::to_vec), end.map(<[u8]>::to_vec), None)
            .await
    })
}

/// Asserts a refusal is the DENIAL shape: refused as not-permitted, never as a
/// credential problem, and naming the operation and scope.
fn assert_denied(result: Result<impl std::fmt::Debug, vyrn_client::Error>, op_and_scope: &str) {
    match result {
        Err(vyrn_client::Error::Server { code, message }) => {
            assert_ne!(
                code,
                vyrn_protocol::ErrorCode::AuthenticationFailed,
                "a permission denial must not masquerade as a credential failure: {message}"
            );
            assert_eq!(code, vyrn_protocol::ErrorCode::InvalidRequest, "{message}");
            let expected = format!("permission denied for {op_and_scope}");
            assert!(
                message.contains(&expected),
                "denial should say {expected:?}, got {message:?}"
            );
        }
        other => panic!("expected a permission denial, got {other:?}"),
    }
}

const READER: (&str, &str) = ("reader", "reader-password-1");
const WRITER: (&str, &str) = ("writer", "writer-password-2");
const ADMIN: (&str, &str) = ("admin", "admin-password-3");

fn standard_users(path: &Path) {
    write_users_file(
        path,
        &[
            user_entry(READER.0, READER.1, &[("app/", "read")]),
            user_entry(WRITER.0, WRITER.1, &[("app/", "write")]),
            user_entry(ADMIN.0, ADMIN.1, &[("", "admin")]),
        ],
    );
}

#[test]
fn the_authorization_matrix_holds_in_both_directions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    standard_users(&users);
    let node = spawn_users(&dir.path().join("data"), &users, None, false);

    let admin = node.url(ADMIN.0, ADMIN.1);
    let writer = node.url(WRITER.0, WRITER.1);
    let reader = node.url(READER.0, READER.1);

    // Admin holds the whole keyspace, DDL included.
    put(&admin, b"app/seed", b"seeded").expect("admin writes anywhere");
    put(&admin, b"other/seed", b"seeded").expect("admin writes outside app/");
    create_index(&admin, b"by-name").expect("admin runs index DDL");

    // TWO USERS, DIFFERENT ENFORCEMENT, over the same client code path: the
    // writer commits exactly the request the reader is refused.
    put(&writer, b"app/item", b"from-writer").expect("writer writes inside its prefix");
    assert_denied(put(&reader, b"app/item", b"from-reader"), "put on app/item");

    // Write implies read; read does not imply write.
    assert_eq!(
        get(&writer, b"app/item").expect("writer reads inside its prefix"),
        Some(b"from-writer".to_vec())
    );
    assert_eq!(
        get(&reader, b"app/item").expect("reader reads inside its prefix"),
        Some(b"from-writer".to_vec())
    );

    // Prefix isolation cuts both ways: neither scoped user reaches other/.
    assert_denied(get(&reader, b"other/seed"), "get on other/seed");
    assert_denied(put(&writer, b"other/item", b"x"), "put on other/item");
    assert_denied(delete(&writer, b"other/seed"), "delete on other/seed");

    // A writer is not an administrator: DDL needs an admin grant.
    assert_denied(create_index(&writer, b"by-writer"), "create-index on <all>");

    // A scan must sit inside a granted prefix; a scan past it is refused even
    // though some of its rows would have been readable.
    let rows = scan(&reader, Some(b"app/"), Some(b"app0")).expect("reader scans its own prefix");
    assert!(rows.iter().any(|(key, _)| key == b"app/item"));
    assert_denied(scan(&reader, Some(b"app/"), None), "scan on app/..");

    // Subscriptions: the subscribed prefix must be readable.
    runtime().block_on(async {
        let client = vyrn_client::Client::connect(&reader)
            .await
            .expect("connect");
        client
            .subscribe(b"app/".to_vec())
            .await
            .expect("reader subscribes inside its prefix");
        let client = vyrn_client::Client::connect(&reader)
            .await
            .expect("connect");
        match client.subscribe(Vec::new()).await.err() {
            Some(vyrn_client::Error::Server { code, message }) => {
                assert_eq!(code, vyrn_protocol::ErrorCode::InvalidRequest);
                assert!(
                    message.contains("permission denied for subscribe"),
                    "{message}"
                );
            }
            other => panic!("a whole-keyspace subscription must be denied: {other:?}"),
        }
    });

    // Transactions check every statement inside: the denied put never reaches
    // the buffered write set, and the transaction itself stays usable.
    runtime().block_on(async {
        let mut client = vyrn_client::Client::connect(&writer)
            .await
            .expect("connect");
        let mut transaction = client.transaction().await.expect("begin");
        transaction
            .put(b"app/txn".to_vec(), b"inside".to_vec())
            .await
            .expect("in-prefix write inside a transaction");
        match transaction
            .put(b"other/txn".to_vec(), b"outside".to_vec())
            .await
        {
            Err(vyrn_client::Error::Server { code, message }) => {
                assert_eq!(code, vyrn_protocol::ErrorCode::InvalidRequest);
                assert!(
                    message.contains("permission denied for put on other/txn"),
                    "{message}"
                );
            }
            other => {
                panic!("an out-of-prefix write inside a transaction must be denied: {other:?}")
            }
        }
        transaction
            .commit()
            .await
            .expect("commit the permitted write");
    });
    assert_eq!(
        get(&admin, b"app/txn").expect("admin reads"),
        Some(b"inside".to_vec())
    );
    assert_eq!(get(&admin, b"other/txn").expect("admin reads"), None);
}

#[test]
fn document_collections_enforce_through_their_key_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    standard_users(&users);
    let node = spawn_users(&dir.path().join("data"), &users, None, false);
    let admin = node.url(ADMIN.0, ADMIN.1);
    let writer = node.url(WRITER.0, WRITER.1);

    runtime().block_on(async {
        let mut client = vyrn_client::Client::connect(&admin).await.expect("connect");
        client
            .create_collection("orders", &[])
            .await
            .expect("admin creates a collection");
        client
            .put_document("orders", "1", &serde_json::json!({"total": 5}))
            .await
            .expect("admin writes a document");

        // The collection's underlying keys live outside app/, so the scoped
        // writer holds neither DDL nor document access to it.
        let mut client = vyrn_client::Client::connect(&writer)
            .await
            .expect("connect");
        match client.create_collection("mine", &[]).await {
            Err(vyrn_client::Error::Server { code, message }) => {
                assert_eq!(code, vyrn_protocol::ErrorCode::InvalidRequest);
                assert!(
                    message.contains("permission denied for create-collection"),
                    "{message}"
                );
            }
            other => panic!("collection DDL from a non-admin must be denied: {other:?}"),
        }
        match client
            .put_document("orders", "2", &serde_json::json!({"total": 9}))
            .await
        {
            Err(vyrn_client::Error::Server { code, message }) => {
                assert_eq!(code, vyrn_protocol::ErrorCode::InvalidRequest);
                assert!(
                    message.contains("permission denied for put-document on orders/2"),
                    "{message}"
                );
            }
            other => panic!("a document write outside the grants must be denied: {other:?}"),
        }
    });
}

#[test]
fn removing_a_user_terminates_their_live_session_without_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    standard_users(&users);
    let node = spawn_users(&dir.path().join("data"), &users, None, false);

    let runtime = runtime();
    let mut session = runtime
        .block_on(vyrn_client::Client::connect(&node.url(WRITER.0, WRITER.1)))
        .expect("connect the session to be revoked");
    runtime
        .block_on(session.put(b"app/before".to_vec(), b"v".to_vec()))
        .expect("the writer works before revocation");

    /* Revoke: rewrite the users file without the writer. The stamp check is
     * mtime plus length, so the sleep guards against a same-tick rewrite on a
     * coarse-mtime filesystem. */
    std::thread::sleep(Duration::from_millis(50));
    write_users_file(
        &users,
        &[
            user_entry(READER.0, READER.1, &[("app/", "read")]),
            user_entry(ADMIN.0, ADMIN.1, &[("", "admin")]),
        ],
    );

    // The file is re-checked on each authentication attempt: the writer's own
    // reconnect is refused, and that same attempt loads the new user set.
    let refused = runtime
        .block_on(vyrn_client::Client::connect(&node.url(WRITER.0, WRITER.1)))
        .map(drop)
        .expect_err("a removed user must not authenticate");
    assert!(
        matches!(
            refused,
            vyrn_client::Error::Server {
                code: vyrn_protocol::ErrorCode::AuthenticationFailed,
                ..
            }
        ),
        "{refused:?}"
    );

    // The live session dies on its next operation against the new generation.
    let terminated = runtime
        .block_on(session.put(b"app/after".to_vec(), b"v".to_vec()))
        .expect_err("a revoked session must not keep writing");
    assert!(
        matches!(
            terminated,
            vyrn_client::Error::Server {
                code: vyrn_protocol::ErrorCode::AuthenticationFailed,
                ..
            }
        ),
        "revocation should terminate the session, got {terminated:?}"
    );

    // Users still in the file are untouched, at their reloaded scope.
    put(&node.url(ADMIN.0, ADMIN.1), b"app/admin", b"v").expect("remaining users keep working");
}

#[test]
fn the_single_credential_mode_is_unchanged_and_all_powerful() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    std::fs::write(&hash, phc("compat-password")).expect("write hash");
    let port = free_port();
    let admin_port = free_port();
    let child = Command::new(vyrnd())
        .env("VYRN_BIND", format!("127.0.0.1:{port}"))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("VYRN_DATA", dir.path().join("data"))
        .env("VYRN_PASSWORD_HASH_FILE", &hash)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vyrnd");
    let node = Node {
        child,
        port,
        admin_port,
    };
    assert!(node.wait_ready(Duration::from_secs(30)), "node not ready");

    // The one credential still does everything, exactly as before 1.1.
    let url = node.url("vyrn", "compat-password");
    put(&url, b"anywhere/at/all", b"v").expect("single credential writes anywhere");
    create_index(&url, b"any-index").expect("single credential runs DDL");
    assert_eq!(
        get(&url, b"anywhere/at/all").expect("single credential reads"),
        Some(b"v".to_vec())
    );
}

#[test]
fn setting_both_credential_stores_refuses_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    std::fs::write(&hash, phc("p")).expect("write hash");
    let users = dir.path().join("users.json");
    standard_users(&users);
    let log = dir.path().join("stderr.log");
    let mut child = Command::new(vyrnd())
        .env("VYRN_BIND", format!("127.0.0.1:{}", free_port()))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{}", free_port()))
        .env("VYRN_DATA", dir.path().join("data"))
        .env("VYRN_PASSWORD_HASH_FILE", &hash)
        .env("VYRN_USERS_FILE", &users)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&log).expect("create log"),
        ))
        .spawn()
        .expect("spawn vyrnd");

    // Startup refusal is observed by sampling, never by a single blocking wait.
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "a server with both credential stores must refuse to start"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(!status.success(), "startup must fail, got {status}");
    let written = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        written.contains("VYRN_PASSWORD_HASH_FILE") && written.contains("VYRN_USERS_FILE"),
        "the refusal must name both settings:\n{written}"
    );
}

/// Polls the audit file until `predicate` holds or the deadline passes,
/// returning the last contents read. Cross-process file observation is always
/// sampled: the server's write races the assertion.
fn wait_for_audit(path: &Path, predicate: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut contents = String::new();
    while Instant::now() < deadline {
        contents = std::fs::read_to_string(path).unwrap_or_default();
        if predicate(&contents) {
            return contents;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    contents
}

#[test]
fn the_audit_trail_records_who_did_what_but_never_values_or_credentials() {
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    standard_users(&users);
    let audit = dir.path().join("audit.log");
    let node = spawn_users(&dir.path().join("data"), &users, Some(&audit), false);
    let writer = node.url(WRITER.0, WRITER.1);
    let admin = node.url(ADMIN.0, ADMIN.1);

    // Distinctive strings a substring search cannot miss.
    const VALUE: &[u8] = b"secret-payload-7c19e2-must-never-be-audited";
    const WRONG_PASSWORD: &str = "wrong-password-4b8d11";

    put(&writer, b"app/audited", VALUE).expect("writer writes");
    delete(&writer, b"app/audited").expect("writer deletes");
    let _ = get(&writer, b"app/audited"); // reads are NOT audited by default
    assert_denied(
        put(&writer, b"other/audited", VALUE),
        "put on other/audited",
    );
    create_index(&admin, b"audited-index").expect("admin DDL");
    let _ = put(&node.url(WRITER.0, WRONG_PASSWORD), b"app/x", b"v");

    let contents = wait_for_audit(&audit, |contents| {
        [
            "op=put",
            "op=delete",
            "denied",
            "op=create-index",
            "outcome=rejected",
        ]
        .iter()
        .all(|needle| contents.contains(needle))
    });

    // Who did what: user, operation, scope, and result, one line per event.
    assert!(
        contents.contains("outcome=success user=writer"),
        "auth success with the user is missing:\n{contents}"
    );
    assert!(
        contents.contains("outcome=rejected user=writer"),
        "auth failure with the (real) user is missing:\n{contents}"
    );
    assert!(
        contents.contains("user=writer op=put scope=app/audited result=ok"),
        "the write audit line is missing:\n{contents}"
    );
    assert!(
        contents.contains("user=writer op=delete scope=app/audited result=ok"),
        "the delete audit line is missing:\n{contents}"
    );
    assert!(
        contents.contains("denied user=writer op=put scope=other/audited"),
        "the denial audit line is missing:\n{contents}"
    );
    assert!(
        contents.contains("user=admin op=create-index"),
        "the DDL audit line is missing:\n{contents}"
    );

    // Reads stay out of the trail unless VYRN_AUDIT_READS=1.
    assert!(
        !contents.contains("op=get"),
        "reads must not be audited by default:\n{contents}"
    );

    // NEVER values, NEVER credentials. The value was written and the audit
    // names its key, so this greps the real exposure surface.
    let value = std::str::from_utf8(VALUE).unwrap();
    assert!(
        !contents.contains(value),
        "a written VALUE appears in the audit trail:\n{contents}"
    );
    assert!(
        !contents.contains(WRONG_PASSWORD) && !contents.contains(WRITER.1),
        "a password appears in the audit trail:\n{contents}"
    );
}

#[test]
fn reads_join_the_audit_trail_only_when_asked_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let users = dir.path().join("users.json");
    standard_users(&users);
    let audit = dir.path().join("audit.log");
    let node = spawn_users(&dir.path().join("data"), &users, Some(&audit), true);
    let reader = node.url(READER.0, READER.1);

    let _ = get(&reader, b"app/read-me").expect("reader reads");
    let contents = wait_for_audit(&audit, |contents| contents.contains("op=get"));
    assert!(
        contents.contains("user=reader op=get scope=app/read-me"),
        "with VYRN_AUDIT_READS=1 a read must be audited:\n{contents}"
    );
}
