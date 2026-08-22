//! Two real nodes over a real socket.
//!
//! `vyrn-server` had no `tests/` directory before this, and no test anywhere in
//! the workspace opened a socket — `vyrn-core`'s suites are all in-process. So
//! this is new scaffolding, and it deliberately spawns the SHIPPED BINARIES via
//! `CARGO_BIN_EXE_vyrnd` rather than calling into the crate. Replication is a
//! property of two processes talking to each other; an in-process harness would
//! test a different thing than what ships.
//!
//! Plaintext on loopback with ephemeral ports. TLS is covered by the unit tests in
//! `replica.rs` (which assert it is required by default and that a password in the
//! URL is refused); repeating a certificate dance here would slow every run
//! without testing more replication.

use std::{
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const PASSWORD: &str = "replication-integration-test-password";

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
    /// Connection string including the password.
    ///
    /// In-URL passwords are wrong for real deployments — they reach logs, shell
    /// history and `ps` — which is why `replica.rs` refuses them for the
    /// replication link. Here the whole cluster is ephemeral and the credential
    /// is a constant in this file, so there is nothing to leak.
    fn url(&self) -> String {
        format!(
            "vyrn://vyrn:{PASSWORD}@127.0.0.1:{}/default?tls=disable",
            self.port
        )
    }

    fn metrics(&self) -> String {
        http_get(self.admin_port, "/metrics").unwrap_or_default()
    }

    /// One numeric metric, or 0 when absent.
    fn metric(&self, name: &str) -> u64 {
        self.metrics()
            .lines()
            .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
            .unwrap_or(0)
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

    /// Kills the node the way a crash would: no shutdown, no flush.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Claims a free port by binding and immediately closing.
///
/// Racy in principle, fine in practice for a test, and far better than fixed
/// ports that collide with whatever else is running on a dev machine.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

fn vyrnd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vyrnd"))
}

/// The Argon2id verifier the server needs, written with the same crate the CLI
/// uses, so this test does not depend on the CLI binary being built.
fn write_password_hash(path: &Path) {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    /* A fixed salt, which would be wrong anywhere but here.
     *
     * `OsRng` lives behind rand_core's `getrandom` feature, which this workspace
     * does not enable for the argon2 dependency, and turning it on just for a test
     * would change what the production build pulls in. The password is a constant
     * in this file and the cluster is deleted at the end of the test, so there is
     * nothing a per-run salt would protect. */
    let salt = SaltString::from_b64("dmVyeXNhbHR5c2FsdA").expect("valid salt");
    let hash = Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &salt)
        .expect("hash password")
        .to_string();
    std::fs::write(path, hash).expect("write hash");
}

fn write_password(path: &Path) {
    let mut file = std::fs::File::create(path).expect("create password file");
    writeln!(file, "{PASSWORD}").expect("write password");
}

fn spawn(data: &Path, hash: &Path, extra: &[(&str, String)]) -> Node {
    let port = free_port();
    let admin_port = free_port();
    let mut command = Command::new(vyrnd());
    command
        .env("VYRN_BIND", format!("127.0.0.1:{port}"))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("VYRN_DATA", data)
        .env("VYRN_PASSWORD_HASH_FILE", hash)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        // Quiet: these tests spawn several nodes and their logs interleave.
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in extra {
        command.env(key, value);
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

/// Minimal HTTP GET against the admin endpoint.
fn http_get(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write as _};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

/// Runs one client operation against `url`, in-process via the client crate.
///
/// NOT through the `vyrn` CLI binary: `CARGO_BIN_EXE_*` only exposes binaries
/// from the crate under test, so reaching the CLI would mean depending on build
/// order across packages. The client crate speaks the same native protocol.
///
/// Each call opens its own connection, which is what a separate client would do
/// and keeps a failed write from poisoning later assertions in the same test.
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

/// `put`, returning the server's error text on failure.
fn put(url: &str, key: &str, value: &str) -> Result<(), String> {
    let key = key.to_owned();
    let value = value.to_owned();
    run_client(url, move |client| {
        Box::pin(async move { client.put(key.into_bytes(), value.into_bytes()).await })
    })
}

/// `get`, returning the value as a string when present.
fn get(url: &str, key: &str) -> Result<Option<String>, String> {
    let key = key.to_owned();
    run_client(url, move |client| {
        Box::pin(async move {
            let value = client.get(key.into_bytes()).await?;
            Ok(value.map(|bytes| String::from_utf8_lossy(bytes.as_slice()).into_owned()))
        })
    })
}

/// Waits for a metric to reach `target`, so tests do not sleep arbitrarily.
fn wait_for_metric(node: &Node, name: &str, target: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if node.metric(name) >= target {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

struct Cluster {
    /// Held to keep the temporary directory alive for the test's duration.
    _dir: tempfile::TempDir,
    /// Needed to respawn a node against the same credentials (promotion test).
    hash: PathBuf,
    primary: Node,
    /// `Option` so a test can drop the replica to simulate losing it. Dropping
    /// stops the process, which is exactly the failure being tested.
    replica: Option<Node>,
}

/// A primary requiring one acknowledgement, plus a connected replica.
fn cluster(ack_timeout_ms: u64) -> Cluster {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    let password = dir.path().join("password.txt");
    write_password_hash(&hash);
    write_password(&password);

    let primary = spawn(
        &dir.path().join("primary"),
        &hash,
        &[
            ("VYRN_REPLICATION_MIN_ACKS", "1".into()),
            (
                "VYRN_REPLICATION_ACK_TIMEOUT_MS",
                ack_timeout_ms.to_string(),
            ),
        ],
    );

    let replica = spawn(
        &dir.path().join("replica"),
        &hash,
        &[
            (
                "VYRN_REPLICA_OF",
                format!(
                    "vyrn://vyrn@127.0.0.1:{}/default?tls=disable",
                    primary.port
                ),
            ),
            (
                "VYRN_REPLICA_PASSWORD_FILE",
                password.to_string_lossy().into_owned(),
            ),
            ("VYRN_REPLICA_ID", "replica-under-test".into()),
        ],
    );

    assert!(
        wait_for_metric(
            &primary,
            "vyrn_replicas_connected",
            1,
            Duration::from_secs(30)
        ),
        "the replica never connected to the primary"
    );

    Cluster {
        _dir: dir,
        hash,
        primary,
        replica: Some(replica),
    }
}

#[test]
fn an_acknowledged_write_is_durable_on_the_replica() {
    let cluster = cluster(5_000);
    let replica = cluster.replica.as_ref().expect("replica");

    put(&cluster.primary.url(), "signup/1", "alica@example.com")
        .expect("the write should have been acknowledged");

    // The acknowledgement means the replica already has it durably, so this read
    // needs no polling.
    assert_eq!(
        get(&replica.url(), "signup/1").expect("replica read"),
        Some("alica@example.com".to_owned()),
        "replica should hold the acknowledged write"
    );
    assert_eq!(
        replica.metric("vyrn_replication_last_lsn"),
        cluster.primary.metric("vyrn_replication_last_lsn"),
        "replica and primary should agree on the last LSN"
    );
}

#[test]
fn losing_the_primary_does_not_lose_acknowledged_writes() {
    let mut cluster = cluster(5_000);

    for index in 0..5 {
        put(
            &cluster.primary.url(),
            &format!("signup/{index}"),
            &format!("value-{index}"),
        )
        .unwrap_or_else(|error| panic!("write {index} failed: {error}"));
    }

    // Kill, not shut down: no flush, no drain — what a power cut looks like.
    cluster.primary.kill();

    let replica = cluster.replica.as_ref().expect("replica");
    for index in 0..5 {
        assert_eq!(
            get(&replica.url(), &format!("signup/{index}")).expect("replica read"),
            Some(format!("value-{index}")),
            "acknowledged write {index} was lost when the primary died"
        );
    }
}

#[test]
fn a_replica_can_be_promoted_by_restarting_without_replica_of() {
    let mut cluster = cluster(5_000);
    put(&cluster.primary.url(), "before/promotion", "kept").expect("write before promotion");

    let replica_data = {
        let replica = cluster.replica.take().expect("replica");
        // Derived rather than remembered: the replica's data directory is the one
        // `cluster` created for it.
        let path = cluster._dir.path().join("replica");
        drop(replica); // stops the process
        path
    };
    cluster.primary.kill();
    std::thread::sleep(Duration::from_millis(500));

    // Same binary, same data directory, no --replica-of: that is the promotion.
    let promoted = spawn(&replica_data, &cluster.hash, &[]);

    assert_eq!(
        get(&promoted.url(), "before/promotion").expect("read after promotion"),
        Some("kept".to_owned()),
        "promoted node lost data written before promotion"
    );
    put(&promoted.url(), "after/promotion", "accepted")
        .expect("a promoted node must accept writes");
}

#[test]
fn a_replica_refuses_client_writes() {
    let cluster = cluster(5_000);
    let replica = cluster.replica.as_ref().expect("replica");

    let error = put(&replica.url(), "should/fail", "nope")
        .expect_err("a replica must refuse client writes");
    assert!(
        error.contains("does not accept writes"),
        "a replica must refuse client writes, or its log diverges from the \
         primary's and it can never be promoted. Got: {error}"
    );

    // Reads must still work — a replica exists to serve them.
    put(&cluster.primary.url(), "k", "v").expect("primary write");
    assert_eq!(
        get(&replica.url(), "k").expect("replica read"),
        Some("v".to_owned()),
        "replica reads should work"
    );
}

#[test]
fn writes_fail_rather_than_silently_dropping_the_guarantee() {
    // A short timeout so the test is quick; the behaviour is the same at any.
    let mut cluster = cluster(800);

    // Drop the replica. The primary now cannot reach its quorum.
    cluster.replica.take();
    assert!(
        wait_for_metric(
            &cluster.primary,
            "vyrn_replication_dropped_replicas_total",
            1,
            Duration::from_secs(15)
        ),
        "the primary should have noticed the replica leaving"
    );

    let error = put(&cluster.primary.url(), "unreplicated", "value")
        .expect_err("a write with no replica must fail");
    /* THE CENTRAL ASSERTION OF THIS FEATURE. With min-acks 1 and no replica, the
     * write must FAIL. Acknowledging it would mean reporting a write as
     * replicated when no other node holds it — the exact data loss synchronous
     * replication is configured to prevent. */
    assert!(
        error.contains("quorum not reached"),
        "a write with no replica must fail, not be silently acknowledged \
         unreplicated. Got: {error}"
    );
    assert_eq!(
        cluster.primary.metric("vyrn_replication_ack_timeouts_total"),
        1,
        "the timeout should be counted"
    );

    // And readiness must reflect it: this node cannot honour its durability.
    let ready = http_get(cluster.primary.admin_port, "/health/ready").unwrap_or_default();
    assert!(
        ready.contains("503"),
        "a primary that cannot reach quorum must report itself not ready: {ready}"
    );
}
