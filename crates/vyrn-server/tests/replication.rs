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
                format!("vyrn://vyrn@127.0.0.1:{}/default?tls=disable", primary.port),
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
    /* The LSN gauges, unlike the read above, are REPORTING, and reporting is
     * asynchronous on both sides — the tag-run CI caught the primary's gauge
     * still at 0 an instant after the acknowledged write. Sampled until they
     * agree at a nonzero LSN; the durability guarantee itself was already
     * proven by the un-polled read. */
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let replica_lsn = replica.metric("vyrn_replication_last_lsn");
        let primary_lsn = cluster.primary.metric("vyrn_replication_last_lsn");
        if replica_lsn == primary_lsn && replica_lsn > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "replica ({replica_lsn}) and primary ({primary_lsn}) never agreed on the last LSN"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
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
fn a_replica_whose_records_were_pruned_rebuilds_from_the_archive() {
    /* THE FAILURE THIS COVERS. A replica that is offline while the primary
     * checkpoints comes back needing WAL records the primary has already pruned.
     * `decide_join` used to answer `Refuse`, the replica bailed with "rebuild from
     * a base backup", and its reconnect loop repeated that forever — so an
     * ordinary absence became a permanent breakage, while a primary running
     * `--replication-min-acks 1` BLOCKED WRITES waiting for the quorum that very
     * replica was supposed to supply. Only an operator noticing and rebuilding by
     * hand ended it.
     *
     * Now the primary streams from the oldest LSN it still holds, the replica
     * recognises the gap that leaves, and closes it from the WAL ARCHIVE — which
     * holds exactly the pruned segments, byte for byte the primary's own records.
     *
     * The whole cluster is built by hand here rather than through `cluster()`,
     * because the primary needs an archive directory and the replica has to be
     * stopped, left behind, and restarted — none of which the shared helper does.
     */
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    let password = dir.path().join("password.txt");
    write_password_hash(&hash);
    write_password(&password);
    // Outside the data directory: backup enumeration is non-recursive, so a
    // nested archive would be excluded from backups yet destroyed by a restore —
    // the server refuses to start that way.
    let archive = dir.path().join("archive");

    let primary = spawn(
        &dir.path().join("primary"),
        &hash,
        &[
            ("VYRN_REPLICATION_MIN_ACKS", "1".into()),
            /* SHORT ON PURPOSE, and it dominates this test's runtime. Every write
             * made during the outage below has no replica to acknowledge it, so
             * each one waits out this timeout in full. At the 5s default the sixty
             * outage writes took five minutes; at 300ms they take twenty seconds,
             * and the behaviour under test is identical either way — what matters
             * is that the writes are durable locally and get archived, not how
             * long their doomed quorum wait lasts. */
            ("VYRN_REPLICATION_ACK_TIMEOUT_MS", "300".into()),
            (
                "VYRN_WAL_ARCHIVE_DIR",
                archive.to_string_lossy().into_owned(),
            ),
            // Archive promptly so the test does not wait on a long interval.
            ("VYRN_WAL_ARCHIVE_INTERVAL_MS", "200".into()),
            /* A low checkpoint threshold is what makes the primary PRUNE while the
             * replica is away. Without pruning there is no gap, and this test
             * would silently degrade into an ordinary reconnect. */
            ("VYRN_CHECKPOINT_WRITES", "5".into()),
        ],
    );

    let replica_data = dir.path().join("replica");
    let replica_settings = |include_archive: bool| {
        let mut settings = vec![
            (
                "VYRN_REPLICA_OF",
                format!("vyrn://vyrn@127.0.0.1:{}/default?tls=disable", primary.port),
            ),
            (
                "VYRN_REPLICA_PASSWORD_FILE",
                password.to_string_lossy().into_owned(),
            ),
            ("VYRN_REPLICA_ID", "rebuild-under-test".into()),
        ];
        if include_archive {
            settings.push((
                "VYRN_REPLICA_WAL_ARCHIVE_DIR",
                archive.to_string_lossy().into_owned(),
            ));
        }
        settings
    };

    // Phase one: an ordinary replica, caught up by streaming.
    {
        let replica = spawn(&replica_data, &hash, &replica_settings(true));
        assert!(
            wait_for_metric(
                &primary,
                "vyrn_replicas_connected",
                1,
                Duration::from_secs(30)
            ),
            "the replica never connected to the primary"
        );
        put(&primary.url(), "before/outage", "kept").expect("write with the replica present");
        assert_eq!(
            get(&replica.url(), "before/outage").expect("replica read"),
            Some("kept".to_owned()),
            "the replica should hold the acknowledged write"
        );
        // Dropping stops the process: the outage begins here.
        drop(replica);
    }
    assert!(
        wait_for_metric(
            &primary,
            "vyrn_replication_dropped_replicas_total",
            1,
            Duration::from_secs(15)
        ),
        "the primary should have noticed the replica leaving"
    );

    /* THE OUTAGE. Writes continue and cross the checkpoint threshold repeatedly,
     * so segments holding the records this replica needs are archived and then
     * pruned from the primary's live WAL.
     *
     * `min-acks 1` with no replica means every one of these writes FAILS its
     * quorum — and that is fine, because the failure is the quorum promise, not
     * the write: the record is durable locally and applied, which the flush
     * stage's comment spells out. That is exactly the situation being recovered
     * from, and it is why the results are deliberately not asserted on. */
    for index in 0..60 {
        let _ = put(
            &primary.url(),
            &format!("during/outage/{index:03}"),
            &format!("value-{index}"),
        );
    }
    // Give the archiver its ticks, so the pruned segments are safely in the
    // archive before the replica asks for them.
    std::thread::sleep(Duration::from_secs(2));

    /* Phase two: the SAME data directory rejoins. Its log ends in the outage's
     * past, and the records it needs next are gone from the primary. */
    let rebuilt = spawn(&replica_data, &hash, &replica_settings(true));
    assert!(
        wait_for_metric(
            &primary,
            "vyrn_replicas_connected",
            1,
            Duration::from_secs(60)
        ),
        "the lagging replica never rejoined; a replica whose records were pruned \
         must rebuild from the archive rather than being refused forever"
    );

    /* THE CENTRAL ASSERTION: the replica caught up to the primary, across records
     * that only ever existed in the archive. `during/outage/000` is the important
     * one — it was written immediately after the replica left, so it is deep
     * inside the pruned range and can ONLY have arrived through the archive. */
    let caught_up = {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last = None;
        while Instant::now() < deadline {
            last = get(&rebuilt.url(), "during/outage/000").unwrap_or(None);
            if last.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        last
    };
    assert_eq!(
        caught_up,
        Some("value-0".to_owned()),
        "the replica did not recover the records the primary had pruned; the gap was \
         not closed from the WAL archive"
    );
    // And the tail of the outage too, so this is a full catch-up rather than one
    // lucky segment.
    assert_eq!(
        get(&rebuilt.url(), "during/outage/059").expect("replica read"),
        Some("value-59".to_owned()),
        "the replica recovered the start of the gap but not the end of it"
    );
    // The write from before the outage must survive the rebuild: closing a gap
    // must not discard history the replica already held.
    assert_eq!(
        get(&rebuilt.url(), "before/outage").expect("replica read"),
        Some("kept".to_owned()),
        "closing the gap destroyed history the replica already had"
    );

    // Streaming works again afterwards, which is what proves the rebuild left the
    // replica in a state the ordinary path can continue from.
    put(&primary.url(), "after/rebuild", "streamed")
        .expect("with the replica rejoined, writes should reach quorum again");
    assert_eq!(
        get(&rebuilt.url(), "after/rebuild").expect("replica read"),
        Some("streamed".to_owned()),
        "the rebuilt replica should keep up by streaming once its gap is closed"
    );
}

#[test]
fn a_lagging_replica_without_an_archive_says_why_it_cannot_recover() {
    /* THE HONEST-FAILURE HALF of the same feature. Closing a gap needs the pruned
     * records, and a replica with no archive configured genuinely does not have
     * them — so it must fail, and the failure must NAME the missing archive rather
     * than repeating the old "rebuild from a base backup" for a situation that an
     * archive would have recovered automatically.
     *
     * Asserted through the primary's view: the replica bails on the gap and does
     * not stay joined, so `vyrn_replicas_connected` never settles at 1. That is
     * the observable difference from the test above, where the same outage ends
     * with the replica caught up. */
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    let password = dir.path().join("password.txt");
    write_password_hash(&hash);
    write_password(&password);
    let archive = dir.path().join("archive");

    let primary = spawn(
        &dir.path().join("primary"),
        &hash,
        &[
            ("VYRN_REPLICATION_MIN_ACKS", "1".into()),
            ("VYRN_REPLICATION_ACK_TIMEOUT_MS", "500".into()),
            (
                "VYRN_WAL_ARCHIVE_DIR",
                archive.to_string_lossy().into_owned(),
            ),
            ("VYRN_WAL_ARCHIVE_INTERVAL_MS", "200".into()),
            ("VYRN_CHECKPOINT_WRITES", "5".into()),
        ],
    );

    let replica_data = dir.path().join("replica");
    // NOTE: no VYRN_REPLICA_WAL_ARCHIVE_DIR — that is the whole point.
    let settings = vec![
        (
            "VYRN_REPLICA_OF",
            format!("vyrn://vyrn@127.0.0.1:{}/default?tls=disable", primary.port),
        ),
        (
            "VYRN_REPLICA_PASSWORD_FILE",
            password.to_string_lossy().into_owned(),
        ),
        ("VYRN_REPLICA_ID", "no-archive".into()),
    ];

    {
        let replica = spawn(&replica_data, &hash, &settings);
        assert!(
            wait_for_metric(
                &primary,
                "vyrn_replicas_connected",
                1,
                Duration::from_secs(30)
            ),
            "the replica never connected"
        );
        put(&primary.url(), "before/outage", "kept").expect("write with the replica present");
        drop(replica);
    }
    for index in 0..60 {
        let _ = put(
            &primary.url(),
            &format!("during/outage/{index:03}"),
            "value",
        );
    }
    std::thread::sleep(Duration::from_secs(2));

    let _stuck = spawn(&replica_data, &hash, &settings);
    /* It must NOT reach a steady joined state: it connects, is told where the
     * stream begins, sees the gap it cannot close, and disconnects — repeatedly.
     * Sampling over several seconds rather than checking once, because a single
     * observation could land inside one of those brief connections. */
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut recovered = false;
    while Instant::now() < deadline {
        if get(&_stuck.url(), "during/outage/059")
            .unwrap_or(None)
            .is_some()
        {
            recovered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        !recovered,
        "a replica with no WAL archive cannot have recovered pruned records — it does \
         not have them. Reporting success here would mean it had silently accepted a \
         log with a hole in it, which its own recovery would refuse to open."
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
    // Sampled like every other counter in this file, not read once: the
    // increment happens on the write path but this observation crosses the
    // admin endpoint, and the first Linux CI run caught the instant read
    // arriving before the scrape reflected it.
    assert!(
        wait_for_metric(
            &cluster.primary,
            "vyrn_replication_ack_timeouts_total",
            1,
            Duration::from_secs(10)
        ),
        "the timeout should be counted"
    );

    // And readiness must reflect it: this node cannot honour its durability.
    let ready = http_get(cluster.primary.admin_port, "/health/ready").unwrap_or_default();
    assert!(
        ready.contains("503"),
        "a primary that cannot reach quorum must report itself not ready: {ready}"
    );
}

// --- automatic failover ----------------------------------------------------

/// Like `spawn`, but on ports chosen by the caller — cluster URLs name every
/// member's address, so the addresses must exist before any member starts.
fn spawn_member(
    data: &Path,
    hash: &Path,
    port: u16,
    admin_port: u16,
    extra: &[(&str, String)],
) -> Node {
    // Each member's stderr lands beside its data, so a failed election is
    // diagnosable from the artifacts instead of re-run guesswork.
    std::fs::create_dir_all(data).expect("member data dir");
    let log = std::fs::File::create(data.join("stderr.log")).expect("member log");
    let mut command = Command::new(vyrnd());
    command
        .env("VYRN_BIND", format!("127.0.0.1:{port}"))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("VYRN_DATA", data)
        .env("VYRN_PASSWORD_HASH_FILE", hash)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::from(log));
    for (key, value) in extra {
        command.env(key, value);
    }
    let child = command.spawn().expect("spawn vyrnd");
    let node = Node {
        child,
        port,
        admin_port,
    };
    // 90s, not the spawn helper's 30: three members start at once, and
    // under full-workspace parallel load a debug build has taken over 30s
    // to bind — which is a slow host, not a failover defect.
    assert!(
        node.wait_ready(Duration::from_secs(90)),
        "member did not become ready"
    );
    node
}

/// Three members with automatic failover: `a` the initial primary, `b` and
/// `c` following it. min-acks 1 is exactly floor(3/2), so an acknowledged
/// write is on a majority (the primary plus one), which is what makes any
/// election majority provably hold it. Short lease and election timeouts so
/// the test observes a failover in seconds; every observation below is
/// still sampled with a deadline, never read once.
fn failover_trio(dir: &tempfile::TempDir) -> Vec<Node> {
    let hash = dir.path().join("password.phc");
    let password = dir.path().join("password.txt");
    write_password_hash(&hash);
    write_password(&password);
    let names = ["a", "b", "c"];
    let ports: Vec<(u16, u16)> = names.iter().map(|_| (free_port(), free_port())).collect();
    let spec = names
        .iter()
        .zip(&ports)
        .map(|(name, (port, _))| format!("{name}=vyrn://vyrn@127.0.0.1:{port}/default?tls=disable"))
        .collect::<Vec<_>>()
        .join(",");
    let mut nodes = Vec::new();
    for (index, (name, (port, admin_port))) in names.iter().zip(&ports).enumerate() {
        let mut extra = vec![
            ("VYRN_REPLICATION_MIN_ACKS", "1".to_string()),
            ("VYRN_REPLICATION_ACK_TIMEOUT_MS", "4000".to_string()),
            ("VYRN_CLUSTER", spec.clone()),
            ("VYRN_CLUSTER_SELF", (*name).to_string()),
            ("VYRN_FAILOVER_LEASE_MS", "1500".to_string()),
            ("VYRN_FAILOVER_ELECTION_MS", "2500".to_string()),
        ];
        // The initial primary never dials peers — it never stands and never
        // follows — so the replica credential belongs to followers only
        // (and clap enforces that pairing).
        if index > 0 {
            extra.push((
                "VYRN_REPLICA_PASSWORD_FILE",
                password.to_string_lossy().into_owned(),
            ));
            extra.push((
                "VYRN_REPLICA_OF",
                format!("vyrn://vyrn@127.0.0.1:{}/default?tls=disable", ports[0].0),
            ));
            extra.push(("VYRN_REPLICA_ID", (*name).to_string()));
        }
        nodes.push(spawn_member(
            &dir.path().join(name),
            &hash,
            *port,
            *admin_port,
            &extra,
        ));
    }
    assert!(
        wait_for_metric(
            &nodes[0],
            "vyrn_replicas_connected",
            2,
            Duration::from_secs(30)
        ),
        "both followers should connect to the initial primary"
    );
    nodes
}

/// THE FAILOVER CLAIM, end to end: kill the primary and a follower elects
/// itself within the timeout, serves writes, and holds every acknowledged
/// pre-kill write — the safety argument in failover.rs, observed from
/// outside. The member that lost the election keeps refusing writes.
#[test]
fn a_dead_primary_is_replaced_and_acknowledged_writes_survive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodes = failover_trio(&dir);
    for index in 0..5 {
        put(
            &nodes[0].url(),
            &format!("pre/{index}"),
            &format!("value-{index}"),
        )
        .expect("acknowledged write against the initial primary");
    }
    nodes[0].kill();

    // A new primary within the deadline: exactly one of b, c accepts writes.
    let deadline = Instant::now() + Duration::from_secs(45);
    let leader = loop {
        assert!(
            Instant::now() < deadline,
            "no member was elected primary after the kill"
        );
        let elected: Vec<usize> = (1..3)
            .filter(|index| put(&nodes[*index].url(), "post/probe", "alive").is_ok())
            .collect();
        match elected.as_slice() {
            [] => std::thread::sleep(Duration::from_millis(250)),
            [one] => break *one,
            both => panic!("split-brain: members {both:?} both accepted a write"),
        }
    };
    // Every acknowledged pre-kill write is on the elected leader.
    for index in 0..5 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match get(&nodes[leader].url(), &format!("pre/{index}")) {
                Ok(Some(value)) if value == format!("value-{index}") => break,
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
                other => panic!(
                    "acknowledged write pre/{index} missing on the elected leader: {other:?}"
                ),
            }
        }
    }
    // The loser is a follower of the new epoch: still refusing writes.
    let loser = if leader == 1 { 2 } else { 1 };
    let refusal = put(&nodes[loser].url(), "post/loser", "must-fail")
        .expect_err("the losing member must keep refusing writes");
    assert!(
        refusal.contains("follower") || refusal.contains("replica"),
        "the refusal should name the role, got: {refusal}"
    );
}

/// A minority cannot elect: with the primary AND one follower dead, the
/// survivor can gather only its own vote of the three, so it must keep
/// refusing writes — through several election timeouts, sampled.
#[test]
fn a_minority_partition_cannot_elect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodes = failover_trio(&dir);
    nodes[0].kill();
    nodes[1].kill();
    // Long enough for several candidacies (election 2.5s + jitter).
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        assert!(
            put(&nodes[2].url(), "minority/probe", "must-fail").is_err(),
            "a member without a majority elected itself: split-brain"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
}

/// Two-member automatic failover is split-brain by construction and must be
/// refused at startup, loudly.
#[test]
fn a_two_member_cluster_is_refused_at_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let output = Command::new(vyrnd())
        .env("VYRN_BIND", format!("127.0.0.1:{}", free_port()))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{}", free_port()))
        .env("VYRN_DATA", dir.path().join("solo"))
        .env("VYRN_PASSWORD_HASH_FILE", &hash)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        .env("VYRN_REPLICATION_MIN_ACKS", "1")
        .env("VYRN_CLUSTER", "a=vyrn://x,b=vyrn://y")
        .env("VYRN_CLUSTER_SELF", "a")
        .output()
        .expect("run vyrnd");
    assert!(
        !output.status.success(),
        "a two-member cluster must refuse startup"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least 3") && stderr.contains("split-brain"),
        "the refusal must carry the safety argument, got: {stderr}"
    );
}
