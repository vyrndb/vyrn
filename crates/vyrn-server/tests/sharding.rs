//! `--shards N` against the shipped binary: routing, scan merges, the fixed
//! shard count, and every combination sharding refuses.
//!
//! The routing hash is REIMPLEMENTED here rather than imported. FNV-1a 64 over
//! the key bytes is an on-disk contract (docs/compatibility.md): a key's shard
//! is derivable from these constants forever, and a server whose placement
//! disagrees with this file's arithmetic has broken that contract even if it
//! agrees with itself.

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const PASSWORD: &str = "sharding-integration-test-password";
const SHARDS: u64 = 4;

/// The placement contract, independently restated (see the module doc).
fn shard_of(key: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash % SHARDS
}

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
    fn url(&self) -> String {
        format!(
            "vyrn://vyrn:{PASSWORD}@127.0.0.1:{}/default?tls=disable",
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

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

fn vyrnd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vyrnd"))
}

/// See `replication.rs` for why the salt is fixed: the password is a constant
/// in this file and the data directory dies with the test.
fn write_password_hash(path: &Path) {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::from_b64("dmVyeXNhbHR5c2FsdA").expect("valid salt");
    let hash = Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &salt)
        .expect("hash password")
        .to_string();
    std::fs::write(path, hash).expect("write hash");
}

/// Spawns without waiting: refusal tests need the child so they can watch it
/// exit, and success paths call `wait_ready` themselves.
fn spawn_raw(data: &Path, hash: &Path, extra: &[(&str, String)]) -> Node {
    let port = free_port();
    let admin_port = free_port();
    let mut command = Command::new(vyrnd());
    command
        .env("VYRN_BIND", format!("127.0.0.1:{port}"))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("VYRN_DATA", data)
        .env("VYRN_PASSWORD_HASH_FILE", hash)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in extra {
        command.env(key, value);
    }
    Node {
        child: command.spawn().expect("spawn vyrnd"),
        port,
        admin_port,
    }
}

fn spawn(data: &Path, hash: &Path, extra: &[(&str, String)]) -> Node {
    let node = spawn_raw(data, hash, extra);
    assert!(
        node.wait_ready(Duration::from_secs(30)),
        "node did not become ready"
    );
    node
}

/// Asserts the node refuses to start: the process must EXIT, and with failure.
/// Sampled rather than waited once — startup work happens before the checks.
fn assert_refuses_startup(mut node: Node, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match node.child.try_wait().expect("query child") {
            Some(status) => {
                assert!(!status.success(), "{what}: exited but reported success");
                return;
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            None => panic!("{what}: still running; the refusal never happened"),
        }
    }
}

/// Minimal HTTP GET against the admin endpoint.
fn http_get(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write as _};
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

/// Runs one client operation against `url`, in-process via the client crate —
/// the same shape as `replication.rs`, for the same build-order reason.
fn run_client<F, T>(url: &str, operation: F) -> Result<T, String>
where
    F: for<'a> FnOnce(
        &'a mut vyrn_client::Client,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, vyrn_client::Error>> + 'a>,
    >,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    runtime.block_on(async {
        let mut client = vyrn_client::Client::connect(url)
            .await
            .map_err(|error| error.to_string())?;
        operation(&mut client)
            .await
            .map_err(|error| error.to_string())
    })
}

fn put(url: &str, key: &str, value: &str) -> Result<(), String> {
    let key = key.to_owned();
    let value = value.to_owned();
    run_client(url, move |client| {
        Box::pin(async move { client.put(key.into_bytes(), value.into_bytes()).await })
    })
}

fn get(url: &str, key: &str) -> Result<Option<String>, String> {
    let key = key.to_owned();
    run_client(url, move |client| {
        Box::pin(async move {
            let value = client.get(key.into_bytes()).await?;
            Ok(value.map(|bytes| String::from_utf8_lossy(bytes.as_slice()).into_owned()))
        })
    })
}

fn shards_env(count: u64) -> Vec<(&'static str, String)> {
    vec![("VYRN_SHARDS", count.to_string())]
}

/// Keys grouped by the shard this file's own FNV arithmetic assigns them.
/// Panicking here would mean four shards swallowed fifty keys — the hash
/// would have to be broken in a way every other test also catches.
fn keys_by_shard() -> Vec<Vec<String>> {
    let mut by_shard = vec![Vec::new(); SHARDS as usize];
    for index in 0..50 {
        let key = format!("pin/{index:02}");
        by_shard[shard_of(key.as_bytes()) as usize].push(key);
    }
    assert!(
        by_shard.iter().all(|keys| keys.len() >= 2),
        "50 keys left a shard near-empty: {by_shard:?}"
    );
    by_shard
}

#[test]
fn a_sharded_server_round_trips_and_places_data_on_every_shard() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);
    let data = directory.path().join("data");
    let node = spawn(&data, &hash, &shards_env(SHARDS));
    let url = node.url();

    for index in 0..64 {
        put(&url, &format!("key/{index:03}"), &format!("value-{index}")).expect("put");
    }
    for index in 0..64 {
        assert_eq!(
            get(&url, &format!("key/{index:03}")).expect("get"),
            Some(format!("value-{index}")),
            "key/{index:03} did not round-trip"
        );
    }
    // Deletes route like puts; a delete that landed on the wrong shard would
    // report `existed: false` and leave the value readable.
    for index in (0..64).step_by(2) {
        let key = format!("key/{index:03}");
        let existed = run_client(&url, move |client| {
            Box::pin(async move { client.delete(key.into_bytes()).await })
        })
        .expect("delete");
        assert!(existed, "key/{index:03} was not found by its own shard");
    }
    for index in 0..64 {
        let expected = (index % 2 == 1).then(|| format!("value-{index}"));
        assert_eq!(
            get(&url, &format!("key/{index:03}")).expect("get"),
            expected
        );
    }

    // The layout the flag promises: a marker recording the count, one
    // subdirectory per shard, and pages in every one of them (64 keys miss a
    // shard with probability (3/4)^64).
    assert_eq!(
        std::fs::read_to_string(data.join("SHARDS"))
            .expect("SHARDS marker")
            .trim(),
        "4"
    );
    for shard in 0..SHARDS {
        let shard_dir = data.join(format!("shard-{shard}"));
        let pages = std::fs::read_dir(&shard_dir)
            .unwrap_or_else(|_| panic!("shard-{shard} directory missing"))
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("pages-"));
        assert!(pages, "shard-{shard} holds no pages; routing skipped it");
    }
}

#[test]
fn sharded_scans_merge_in_key_order() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&directory.path().join("data"), &hash, &shards_env(SHARDS));
    let url = node.url();

    // Inserted in an order that is neither sorted nor shard-grouped, so the
    // result order below can only come from the merge.
    let mut expected = Vec::new();
    for index in (0..90).rev() {
        let key = format!("scan/{index:02}");
        put(&url, &key, &format!("v{index}")).expect("put");
        expected.push((key.into_bytes(), format!("v{index}").into_bytes()));
    }
    expected.sort();
    put(&url, "zz/outside", "x").expect("put outside");

    let rows = run_client(&url, |client| {
        Box::pin(async move {
            client
                .scan(Some(b"scan/".to_vec()), Some(b"scan0".to_vec()), None)
                .await
        })
    })
    .expect("scan");
    assert_eq!(rows, expected, "full range must be every row, in key order");

    // The limit applies to the MERGED result. Each shard returns up to 7 of
    // its own rows; only a sort-then-truncate yields the globally first 7.
    let rows = run_client(&url, |client| {
        Box::pin(async move {
            client
                .scan(Some(b"scan/".to_vec()), Some(b"scan0".to_vec()), Some(7))
                .await
        })
    })
    .expect("limited scan");
    assert_eq!(rows, expected[..7], "limit must keep the smallest keys");
}

#[test]
fn multi_get_answers_in_request_order_across_shards() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&directory.path().join("data"), &hash, &shards_env(SHARDS));
    let url = node.url();

    for index in 0..24 {
        put(&url, &format!("mg/{index:02}"), &format!("v{index}")).expect("put");
    }
    // Descending, with misses interleaved: the reply must be positional even
    // though each shard answers its own subset in its own time.
    let mut keys = Vec::new();
    let mut expected = Vec::new();
    for index in (0..24).rev() {
        keys.push(format!("mg/{index:02}").into_bytes());
        expected.push(Some(format!("v{index}").into_bytes()));
        keys.push(format!("missing/{index:02}").into_bytes());
        expected.push(None);
    }
    let values = run_client(&url, move |client| {
        Box::pin(async move { client.multi_get(keys).await })
    })
    .expect("multi_get");
    assert_eq!(values, expected);
}

#[test]
fn the_shard_count_is_fixed_at_creation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);
    let data = directory.path().join("data");

    let mut node = spawn(&data, &hash, &shards_env(2));
    put(&node.url(), "fixed/key", "survives").expect("put");
    node.kill();

    // A different count must refuse startup: placement depends on it, and a
    // 3-shard server would look for this key on the wrong shard.
    assert_refuses_startup(
        spawn_raw(&data, &hash, &shards_env(3)),
        "restart with --shards 3 against a 2-shard directory",
    );

    // The recorded count still serves everything it stored.
    let node = spawn(&data, &hash, &shards_env(2));
    assert_eq!(
        get(&node.url(), "fixed/key").expect("get"),
        Some("survives".to_owned())
    );
}

#[test]
fn sharding_an_existing_unsharded_database_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);
    let data = directory.path().join("data");

    let mut node = spawn(&data, &hash, &[]);
    put(&node.url(), "already/here", "value").expect("put");
    node.kill();

    // The key above lives in the root directory; no shard would ever look
    // there, so the flag must refuse rather than strand it.
    assert_refuses_startup(
        spawn_raw(&data, &hash, &shards_env(SHARDS)),
        "--shards 4 against an existing unsharded database",
    );
}

#[test]
fn sharding_refuses_what_it_cannot_compose_with() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);

    // Startup shapes. Each gets a fresh directory so the refusal under test
    // is the only possible one.
    let with = |name: &str, extra: Vec<(&'static str, String)>| {
        let mut env = shards_env(2);
        env.extend(extra);
        assert_refuses_startup(spawn_raw(&directory.path().join(name), &hash, &env), name);
    };
    with(
        "replica",
        vec![
            (
                "VYRN_REPLICA_OF",
                "vyrn://127.0.0.1:1/default?tls=disable".to_owned(),
            ),
            ("VYRN_REPLICA_PASSWORD_FILE", hash.display().to_string()),
        ],
    );
    with(
        "min-acks",
        vec![("VYRN_REPLICATION_MIN_ACKS", "1".to_owned())],
    );
    with(
        "archive",
        vec![(
            "VYRN_WAL_ARCHIVE_DIR",
            directory.path().join("archive").display().to_string(),
        )],
    );
    with(
        "async",
        vec![
            ("VYRN_DURABILITY", "async".to_owned()),
            ("VYRN_ASYNC_SYNC_MS", "50".to_owned()),
        ],
    );

    // Dispatch refusals on a healthy sharded server.
    let node = spawn(&directory.path().join("data"), &hash, &shards_env(SHARDS));
    let url = node.url();
    let error = run_client(&url, |client| {
        Box::pin(async move { client.create_index(b"by-email".to_vec(), false).await })
    })
    .expect_err("global index creation must be refused");
    assert!(error.contains("sharded"), "unexpected refusal: {error}");
    let error = run_client(&url, |client| {
        Box::pin(async move {
            client
                .lookup_index(b"by-email".to_vec(), b"x".to_vec(), Some(10))
                .await
        })
    })
    .expect_err("global index lookup must be refused");
    assert!(error.contains("sharded"), "unexpected refusal: {error}");
    // `subscribe_from` consumes the client, so it gets its own connection.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let error = runtime
        .block_on(async {
            let client = vyrn_client::Client::connect(&url)
                .await
                .map_err(|error| error.to_string())?;
            client
                .subscribe_from(Vec::new(), Some(String::new()))
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
        .expect_err("key-space cursor subscription must be refused");
    assert!(error.contains("sharded"), "unexpected refusal: {error}");
}

#[test]
fn transactions_pin_to_one_shard() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&directory.path().join("data"), &hash, &shards_env(SHARDS));
    let url = node.url();

    let by_shard = keys_by_shard();
    let same_a = by_shard[0][0].clone();
    let same_b = by_shard[0][1].clone();
    let elsewhere = by_shard[1][0].clone();

    // Two keys on one shard: full transaction semantics.
    {
        let (a, b) = (same_a.clone(), same_b.clone());
        run_client(&url, move |client| {
            Box::pin(async move {
                let mut transaction = client.transaction().await?;
                transaction.put(a.into_bytes(), b"first".to_vec()).await?;
                transaction.put(b.into_bytes(), b"second".to_vec()).await?;
                transaction.commit().await
            })
        })
        .expect("same-shard transaction commits");
        assert_eq!(get(&url, &same_a).expect("get"), Some("first".to_owned()));
        assert_eq!(get(&url, &same_b).expect("get"), Some("second".to_owned()));
    }

    // A key from another shard: refused at the operation, before commit, so
    // the client knows exactly which key broke the pin.
    {
        let (a, other) = (same_a.clone(), elsewhere.clone());
        let error = run_client(&url, move |client| {
            Box::pin(async move {
                let mut transaction = client.transaction().await?;
                transaction.put(a.into_bytes(), b"same".to_vec()).await?;
                transaction
                    .put(other.into_bytes(), b"other".to_vec())
                    .await?;
                transaction.commit().await
            })
        })
        .expect_err("cross-shard transaction must be refused");
        assert!(error.contains("cross-shard"), "unexpected refusal: {error}");
        assert_eq!(
            get(&url, &elsewhere).expect("get"),
            None,
            "the refused write must not have reached the other shard"
        );
    }

    // Range scans inside a transaction: every range is cross-shard by
    // construction under hash placement.
    let error = run_client(&url, |client| {
        Box::pin(async move {
            let mut transaction = client.transaction().await?;
            transaction.scan(None, None, Some(10)).await.map(|_| ())
        })
    })
    .expect_err("transactional scan must be refused");
    assert!(error.contains("sharded"), "unexpected refusal: {error}");
}

#[test]
fn documents_live_with_their_collection() {
    let directory = tempfile::tempdir().expect("tempdir");
    let hash = directory.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&directory.path().join("data"), &hash, &shards_env(SHARDS));
    let url = node.url();

    run_client(&url, |client| {
        Box::pin(async move {
            client.create_collection("users", &[]).await?;
            client.create_collection("orders", &[]).await?;
            for index in 0..12 {
                client
                    .put_document(
                        "users",
                        &format!("u{index}"),
                        &serde_json::json!({ "n": index }),
                    )
                    .await?;
                client
                    .put_document(
                        "orders",
                        &format!("o{index}"),
                        &serde_json::json!({ "n": index }),
                    )
                    .await?;
            }
            Ok(())
        })
    })
    .expect("create and fill collections");

    // Reads route by the same collection hash the writes used; a mismatch
    // would answer "not found" from an innocent shard.
    let document = run_client(&url, |client| {
        Box::pin(async move { client.get_document("users", "u7").await })
    })
    .expect("get document")
    .expect("u7 exists");
    assert_eq!(document.value.get("n"), Some(&serde_json::json!(7)));
    let listed = run_client(&url, |client| {
        Box::pin(async move { client.list_documents("orders", None).await })
    })
    .expect("list documents");
    assert_eq!(listed.len(), 12, "orders must all be on one shard");
}
