//! Correctness properties that only show up with several clients at once.
//!
//! Same shape as `replication.rs` and `hardening.rs`: spawn the SHIPPED `vyrnd`
//! over plaintext loopback with ephemeral ports. That matters more here than
//! elsewhere — every bug in this file is about how concurrent requests interleave
//! inside the server's own pipelines, which an in-process harness calling engine
//! methods directly cannot reproduce at all: the reorder, the stall and the
//! grouping hole are all properties of the request plumbing, not of storage.
//!
//! WHAT EACH TEST PINS DOWN, and what it looked like before:
//!
//!   - `change_stream_stays_in_commit_order_under_mixed_load`: document writes
//!     were broadcast from the write pipeline while key/value commits were
//!     broadcast from the flush stage, so a subscriber could see a later change
//!     before an earlier one — or, as this test shows, lose it entirely.
//!   - `a_large_scan_does_not_stall_other_clients`: one big scan held its read
//!     worker for its whole duration, so every request behind it waited.
//!   - `a_read_past_its_deadline_is_abandoned_not_served_forever`: nothing bounded
//!     how long one statement could occupy a shared worker.
//!   - `a_scan_returns_the_same_rows_it_did_before_chunking`: serving a scan in
//!     chunks must not change what it returns.
//!
//! NOT HERE, DELIBERATELY: the batch conflict-validation holes (a plain write and
//! an index claim being invisible to a transaction grouped with them). Whether two
//! requests land in the SAME batch is a timing property of the pipeline's
//! accumulation window — it only keeps accumulating while a barrier is in flight —
//! so an integration test has to win a race to reach the code under test, and
//! passes quietly whenever it loses. That race was observed while writing this
//! file: the version of those tests that spawned two clients passed against the
//! unfixed server. They live in `main.rs`'s unit tests instead, as direct tests of
//! `reject_conflicts` over a constructed batch, where the interleaving is stated
//! rather than hoped for.

use std::{
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const PASSWORD: &str = "correctness-integration-test-password";

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
}

/// Claims a free port by binding and immediately closing.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

fn vyrnd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vyrnd"))
}

/// Writes the Argon2id hash file the server requires.
///
/// Fixed salt, as in the sibling suites: the credential is a constant in this file
/// and the directory is deleted afterwards, so there is nothing a per-run salt
/// would protect, and enabling rand_core's `getrandom` just for a test would
/// change what the production build pulls in.
fn write_password_hash(path: &Path) {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::from_b64("dmVyeXNhbHR5c2FsdA").expect("valid salt");
    let hash = Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &salt)
        .expect("hash password")
        .to_string();
    std::fs::write(path, hash).expect("write hash");
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

/// A node with default settings, plus its temporary directory.
fn node(extra: &[(&str, String)]) -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&dir.path().join("data"), &hash, extra);
    (dir, node)
}

/// Minimal HTTP GET against the admin endpoint.
fn http_get(port: u16, path: &str) -> Option<String> {
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

/// A multi-threaded runtime, because these tests drive several clients at once
/// and a current-thread runtime would serialise exactly the concurrency under
/// test.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime")
}

async fn connect(url: &str) -> vyrn_client::Client {
    vyrn_client::Client::connect(url)
        .await
        .expect("connect to the server")
}

#[test]
fn change_stream_stays_in_commit_order_under_mixed_load() {
    let (_dir, node) = node(&[]);
    let url = node.url();

    runtime().block_on(async {
        let mut setup = connect(&url).await;
        setup
            .create_collection("orders", &[])
            .await
            .expect("create collection");

        /* Subscribed with a CURSOR, to a KEY PREFIX, which together are what let
         * this test state the property sharply.
         *
         * A cursor subscription reports the durable change-log position of every
         * event it delivers, and the change log is written by the engine under its
         * own write lock — so cursor order IS commit order, independently of the
         * order the live broadcast happens to deliver things in.
         *
         * The prefix matters for a subtler reason. Document changes are
         * deliberately NOT delivered to a key-prefix subscription (their keys are
         * an internal encoding that belongs to collection subscriptions), but
         * `stream_from_cursor` advances its tracked cursor on every live event it
         * receives, BEFORE that filter, and then drops anything at or below the
         * tracked cursor as already-delivered. So a document change published
         * ahead of an earlier key/value commit does not merely reorder this
         * stream: it moves the cursor past that commit's position, and the
         * commit is then silently DISCARDED as a duplicate. The reorder shows up
         * here as missing changes, which is the worst failure a change feed has.
         *
         * `Some(String::new())` replays everything retained, so nothing committed
         * during subscription setup can be missed. */
        let subscriber = connect(&url).await;
        let mut stream = subscriber
            .subscribe_from(b"kv/".to_vec(), Some(String::new()))
            .await
            .expect("subscribe from the start");

        /* GENUINELY CONCURRENT MIXED LOAD, on separate connections, with neither
         * side waiting for the other.
         *
         * THIS IS THE PART THAT MAKES THE TEST WORK AT ALL, and it was got wrong
         * first: an earlier version awaited each write in turn, alternating the two
         * kinds. That never reproduced the bug, because awaiting a key/value write
         * means its barrier has ALREADY completed before the next document write is
         * even sent — so there was never an unpublished key/value commit sitting in
         * the flush queue for a document change to overtake, and the reorder window
         * never opened. The unfixed server passed it. Verified, not assumed: the
         * broadcast fix was reverted and that version of this test still passed.
         *
         * Pipelining the key/value writes is what holds commits in the flush queue
         * — several are applied and awaiting one shared `fdatasync` at any moment —
         * while document writes commit alone and immediately. That overlap is the
         * race, so the two sides run as independent tasks and are only joined at
         * the end.
         */
        /* EVERY CLIENT IS CONNECTED AND AUTHENTICATED FIRST, then all of them are
         * released together by a barrier.
         *
         * This is the second thing this test got wrong, and it is worth naming
         * because it is invisible: `connect` pays a real Argon2 verification, which
         * costs tens of milliseconds. Tasks that connect and then write therefore
         * start writing at whatever staggered times their handshakes happen to
         * finish — enough stagger that the key/value writes had drained before the
         * document client had even authenticated, so once again nothing overlapped
         * and the unfixed server passed. Handshakes are paid up front so the
         * barrier releases 26 clients that are all ready to write immediately.
         */
        let mut kv_clients = Vec::new();
        for _ in 0..25 {
            kv_clients.push(connect(&url).await);
        }
        let mut document_client = connect(&url).await;
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(kv_clients.len() + 1));

        let mut writers = Vec::new();
        for (index, mut client) in kv_clients.into_iter().enumerate() {
            let start = std::sync::Arc::clone(&start);
            writers.push(tokio::spawn(async move {
                start.wait().await;
                client
                    .put(format!("kv/{index:03}").into_bytes(), b"value".to_vec())
                    .await
                    .unwrap_or_else(|error| panic!("kv write {index} failed: {error}"));
            }));
        }
        let documents = tokio::spawn({
            let start = std::sync::Arc::clone(&start);
            async move {
                start.wait().await;
                for index in 0..25 {
                    document_client
                        .put_document(
                            "orders",
                            &format!("{index:03}"),
                            &serde_json::json!({"n": index}),
                        )
                        .await
                        .unwrap_or_else(|error| panic!("document write {index} failed: {error}"));
                }
            }
        });
        for writer in writers {
            writer.await.expect("kv writer task");
        }
        documents.await.expect("document task");

        /* Collect what the stream delivered, in delivery order. Only the 25
         * key/value changes are expected — the document writes are what perturbs
         * the ordering, not what is being counted. */
        let mut delivered = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        while delivered.len() < 25 && Instant::now() < deadline {
            let next = tokio::time::timeout(Duration::from_secs(10), stream.next()).await;
            match next {
                Ok(Ok(Some(event))) => match event {
                    // `Caught` marks the end of the replayed backlog and carries
                    // no change of its own.
                    vyrn_client::StreamEvent::Caught { .. } => continue,
                    vyrn_client::StreamEvent::Change { cursor, key, .. } => {
                        delivered.push((cursor, key));
                    }
                    vyrn_client::StreamEvent::Document { .. } => {
                        panic!("a key-prefix subscription must not receive document changes")
                    }
                },
                Ok(Ok(None)) => break,
                Ok(Err(error)) => panic!("subscription failed: {error}"),
                Err(_) => break,
            }
        }

        /* NO CHANGE MAY BE MISSING. This is the assertion the two broadcast points
         * failed: a document change published from the write pipeline while an
         * earlier key/value commit was still awaiting its barrier advanced this
         * subscription's cursor past that commit, which was then dropped as a
         * duplicate it had never actually received. */
        let keys: Vec<String> = delivered
            .iter()
            .map(|(_, key)| String::from_utf8_lossy(key).into_owned())
            .collect();
        assert_eq!(
            delivered.len(),
            25,
            "the change feed lost commits under mixed document and key/value load: \
             delivered {} of 25.\ndelivered: {keys:?}",
            delivered.len()
        );

        /* THE CENTRAL ASSERTION. Cursors are ordered positions in the durable
         * change log, so a stream in commit order delivers them strictly
         * increasing. Any inversion is a subscriber having seen a later change
         * before an earlier one — which is precisely what the two broadcast points
         * produced under this exact workload.
         *
         * Compared as parsed positions rather than as token strings, because a
         * token's lexicographic order is not its numeric order. */
        let positions: Vec<(u64, u64)> = delivered
            .iter()
            .map(|(cursor, _)| position(cursor))
            .collect();
        for pair in positions.windows(2) {
            assert!(
                pair[0] < pair[1],
                "the change stream is out of commit order: {:?} was delivered before {:?}. \
                 A subscriber cannot reconstruct state from a feed that reorders commits.\n\
                 full order: {positions:?}",
                pair[0],
                pair[1]
            );
        }
    });
}

/// Parses a cursor token into its (sequence, index) position.
///
/// Tokens are `<sequence>-<index>` in fixed-width zero-padded HEXADECIMAL, so
/// they are parsed as such. Worth stating because they look decimal until a digit
/// above nine appears: a decimal parse succeeds on most tokens and quietly
/// produces nonsense on the rest, which would make this test's ordering
/// assertion fail on its own arithmetic rather than on the server's behaviour.
fn position(token: &str) -> (u64, u64) {
    let (sequence, index) = token
        .split_once('-')
        .unwrap_or_else(|| panic!("cursor token {token:?} is not <sequence>-<index>"));
    let parse = |part: &str, what: &str| {
        u64::from_str_radix(part, 16)
            .unwrap_or_else(|_| panic!("cursor {what} {part:?} is not hexadecimal"))
    };
    (parse(sequence, "sequence"), parse(index, "index"))
}

#[test]
fn a_failed_document_write_does_not_rebroadcast_the_previous_commit() {
    /* FOUND WHILE FUNNELLING BROADCASTS THROUGH ONE POINT, and deterministic where
     * the reorder it came from is not.
     *
     * The document arm read `engine.last_published()` unconditionally, including on
     * the paths where the write FAILED before reaching the change log — invalid
     * JSON, an unknown collection, a unique violation. `last_published` holds
     * whatever the last SUCCESSFUL commit published and is untouched by a failure,
     * so those records were broadcast a second time: every subscriber received a
     * duplicate of a change it had already processed, carrying a cursor it had
     * already passed. A consumer that is not idempotent applies it twice.
     *
     * Asserted through a cursor subscription because a cursor is the identity of a
     * change: the same position arriving twice is unambiguously a duplicate, where
     * a repeated key/value pair could just be a client writing the same thing
     * again. */
    let (_dir, node) = node(&[]);
    let url = node.url();

    runtime().block_on(async {
        let mut client = connect(&url).await;
        /* A UNIQUE index, which is what gives this test a document write that fails
         * at the right moment. `write_indexed_batch` validates unique claims BEFORE
         * it touches the change log, so a violation returns with `last_published`
         * still holding the previous commit's records — precisely the state the old
         * code then re-broadcast. A nonexistent collection would not do: writing to
         * one creates it, so that path succeeds. */
        client
            .create_collection("orders", &[vyrn_client::CollectionIndex::new("email", true)])
            .await
            .expect("create collection with a unique index");

        let subscriber = connect(&url).await;
        let mut stream = subscriber
            .subscribe_collection_from("orders", Some(String::new()))
            .await
            .expect("subscribe to the collection");

        // One good write, which becomes `last_published`.
        client
            .put_document(
                "orders",
                "first",
                &serde_json::json!({"email": "a@example.com"}),
            )
            .await
            .expect("the first document write should succeed");

        // Now a write that FAILS: a second document claiming the same unique value.
        let failed = client
            .put_document(
                "orders",
                "second",
                &serde_json::json!({"email": "a@example.com"}),
            )
            .await;
        assert!(
            failed.is_err(),
            "a second document claiming the same unique index value must be refused"
        );

        // A second good write, so there is something to wait for that proves the
        // stream got past the failure rather than merely being slow.
        client
            .put_document(
                "orders",
                "third",
                &serde_json::json!({"email": "c@example.com"}),
            )
            .await
            .expect("the third document write should succeed");

        let mut cursors = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        while cursors.len() < 2 && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
                Ok(Ok(Some(vyrn_client::StreamEvent::Caught { .. }))) => continue,
                Ok(Ok(Some(event))) => cursors.push(event.cursor().to_owned()),
                Ok(Ok(None)) => break,
                Ok(Err(error)) => panic!("subscription failed: {error}"),
                Err(_) => break,
            }
        }

        /* THE CENTRAL ASSERTION: every delivered cursor is distinct. Before the
         * fix the failed write re-emitted the first document's change, so the same
         * cursor arrived twice and a subscriber saw a change it had already
         * handled. */
        let mut unique = cursors.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            cursors.len(),
            "a failed document write re-broadcast an earlier commit: cursors {cursors:?} \
             contain a duplicate, so every subscriber received a change it had already \
             processed"
        );
        assert_eq!(
            cursors.len(),
            2,
            "expected exactly the two successful writes to be delivered, got {cursors:?}"
        );
    });
}

#[test]
fn a_large_scan_does_not_stall_other_clients() {
    /* ONE read handle, which is what makes the stall observable and is exactly the
     * condition it occurs under in production: requests are spread round-robin
     * across handles, so with the default sixteen a stalled handle is one
     * unlucky client in sixteen. Pinning it to one handle removes the luck and
     * measures the property directly — whether a big scan blocks the queue. */
    let (_dir, node) = node(&[("VYRN_READ_HANDLES", "1".into())]);
    let url = node.url();

    runtime().block_on(async {
        /* SIZED AGAINST TWO OPPOSING LIMITS.
         *
         * Long enough that a probe can demonstrably overlap the scan: with a small
         * seed the scan finished before the first probe was even queued, and the
         * assertion below then held vacuously whether or not chunking existed —
         * verified, not assumed, because at 4,000 rows this test passed with
         * chunking disabled.
         *
         * Small enough that the RESPONSE fits the protocol's 64 MiB frame ceiling.
         * `MAX_SCAN_LIMIT` is 10,000 rows, so the value size is what has to give:
         * 8 KiB values put the reply at 80 MiB and the server closed the connection
         * mid-scan. 4 KiB keeps it at ~40 MiB, comfortably inside the cap, while
         * still making the scan read enough of the value log to take real time. */
        let mut writer = connect(&url).await;
        let value = vec![b'v'; 4 * 1024];
        for index in 0..12_000 {
            writer
                .put(format!("row/{index:06}").into_bytes(), value.clone())
                .await
                .unwrap_or_else(|error| panic!("seed write {index} failed: {error}"));
        }

        // Connected and authenticated UP FRONT: `connect` pays an Argon2
        // verification costing tens of milliseconds, which would otherwise be
        // counted as time spent waiting on the scan.
        let mut prober = connect(&url).await;
        let mut scanner = connect(&url).await;

        /* Launch the scan, then probe REPEATEDLY while it runs, recording the worst
         * wait any probe saw. Polling rather than a single timed read because a lone
         * probe can land in a gap between chunks and prove nothing; the maximum over
         * many probes is what a client on this handle actually experiences. */
        let scan_started = Instant::now();
        let scan = tokio::spawn(async move { scanner.scan(None, None, Some(10_000)).await });

        let mut worst = Duration::ZERO;
        let mut probes = 0_u32;
        while !scan.is_finished() {
            let queued = Instant::now();
            prober
                .get(b"row/011999".to_vec())
                .await
                .expect("a point read must succeed while a scan is running");
            worst = worst.max(queued.elapsed());
            probes += 1;
        }
        let scan_elapsed = scan_started.elapsed();

        let rows = scan
            .await
            .expect("scan task")
            .expect("the scan itself must still succeed");
        assert_eq!(rows.len(), 10_000, "the scan must return its full limit");

        /* The measurement is only meaningful if probes really did overlap the scan.
         * Asserted rather than assumed, so a machine fast enough to finish the scan
         * before the first probe fails loudly instead of passing for free. */
        assert!(
            probes >= 2,
            "only {probes} probe(s) ran during a {scan_elapsed:?} scan, so this test did \
             not actually measure concurrent access; the seed is too small to overlap"
        );

        /* THE CENTRAL ASSERTION, stated against the SCAN'S OWN duration so it needs
         * no absolute timing threshold and cannot pass vacuously.
         *
         * Before chunking, a point read on this handle waited for the ENTIRE scan:
         * one thread serves one queue and the scan held it from first row to last,
         * so `worst` would be essentially `scan_elapsed`. With chunking a probe
         * waits at most for the chunk in progress — a small fraction of the whole.
         * Half is a deliberately loose line between those two regimes: it is far
         * above one chunk and far below the whole scan, so it tolerates a noisy
         * machine while still failing if the queue is being held. */
        assert!(
            worst * 2 < scan_elapsed,
            "a point read queued behind a large scan waited up to {worst:?} of the \
             scan's {scan_elapsed:?} ({probes} probes): the scan is holding its read \
             worker for the whole request, so every other client on that handle waits \
             for it"
        );
    });
}

#[test]
fn a_read_past_its_deadline_is_abandoned_not_served_forever() {
    /* A 1ms deadline, which any multi-chunk scan crosses. The specific number is
     * not the point — what is being tested is that SOME bound exists and is
     * enforced BETWEEN CHUNKS, so one statement cannot occupy a shared worker
     * without limit. Choosing a value the very first inter-chunk check exceeds
     * makes that deterministic rather than a race against how fast this machine
     * happens to read 16 MiB. One handle again, so the scan and the probe share a
     * queue. */
    let (_dir, node) = node(&[
        ("VYRN_READ_HANDLES", "1".into()),
        ("VYRN_STATEMENT_DEADLINE_MS", "1".into()),
    ]);
    let url = node.url();

    runtime().block_on(async {
        /* Enough rows to need several chunks (the chunk is 256 rows), because the
         * deadline is checked between them: a scan that fits in one chunk is served
         * whole by design, and testing against one would assert the opposite of the
         * intended behaviour. */
        let mut writer = connect(&url).await;
        let value = vec![b'v'; 4 * 1024];
        for index in 0..2_000 {
            writer
                .put(format!("row/{index:06}").into_bytes(), value.clone())
                .await
                .unwrap_or_else(|error| panic!("seed write {index} failed: {error}"));
        }

        let mut scanner = connect(&url).await;
        let started = Instant::now();
        let outcome = scanner.scan(None, None, Some(10_000)).await;
        let elapsed = started.elapsed();

        /* THE CENTRAL ASSERTION: the statement is ABANDONED, and it is abandoned
         * with an error rather than with a truncated result. Returning the rows
         * read so far would be worse than useless — the response carries no
         * "there is more" marker, so a short result is indistinguishable from a
         * range that genuinely ended, and a client would process a prefix of its
         * data believing it had all of it.
         *
         * The row COUNT is reported on failure, never the rows: a served scan here
         * is 8 MiB of values, and printing them buries the assertion in megabytes
         * of debug output. */
        let error = match outcome {
            Err(error) => error,
            Ok(rows) => panic!(
                "a scan past its deadline must be refused, not served: got {} rows. \
                 An unbounded read occupies a worker every other client on that handle \
                 is queued behind.",
                rows.len()
            ),
        };
        assert!(
            error.to_string().contains("time limit"),
            "the refusal must name the real condition so an operator is not sent \
             looking for a storage fault, got: {error}"
        );
        // Bounded in time too, or "abandoned" would be a claim about the message
        // rather than about what the worker actually did.
        assert!(
            elapsed < Duration::from_secs(20),
            "the deadline did not actually stop the statement: it ran {elapsed:?}"
        );

        // And the server is still fully usable afterwards: abandoning a statement
        // is not a fault, so nothing should have been marked failed.
        let ready = http_get(node.admin_port, "/health/ready").unwrap_or_default();
        assert!(
            ready.contains("200"),
            "abandoning one oversized read must not take the node out of service: {ready}"
        );
        let mut prober = connect(&url).await;
        prober
            .get(b"row/000000".to_vec())
            .await
            .expect("the server must keep serving reads");
    });
}

#[test]
fn a_scan_returns_the_same_rows_it_did_before_chunking() {
    /* Chunking a scan changes HOW it reads, and must not change WHAT it returns.
     * This is the regression test for the resume arithmetic: a scan is served in
     * chunks that restart at the last key already collected and drop it again, so
     * an off-by-one there would duplicate or lose one row per chunk — a bug that
     * would otherwise surface as silently missing data rather than as a failure.
     *
     * Deliberately spans many chunk boundaries (the chunk is 256 rows) and checks
     * bounds, limits and ordering, since each interacts with the resume. */
    let (_dir, node) = node(&[]);
    let url = node.url();

    runtime().block_on(async {
        let mut client = connect(&url).await;
        for index in 0..1_500 {
            client
                .put(
                    format!("row/{index:06}").into_bytes(),
                    format!("value-{index}").into_bytes(),
                )
                .await
                .unwrap_or_else(|error| panic!("seed write {index} failed: {error}"));
        }

        let all = client
            .scan(None, None, Some(10_000))
            .await
            .expect("unbounded scan");
        assert_eq!(all.len(), 1_500, "every row must be returned exactly once");
        for (index, (key, value)) in all.iter().enumerate() {
            assert_eq!(
                key,
                &format!("row/{index:06}").into_bytes(),
                "row {index} is out of order or missing: chunk resume dropped or repeated a key"
            );
            assert_eq!(value, &format!("value-{index}").into_bytes());
        }

        // A limit that falls mid-chunk, so the last chunk is a partial one.
        let limited = client
            .scan(None, None, Some(300))
            .await
            .expect("limited scan");
        assert_eq!(limited.len(), 300, "a limit must be honoured exactly");
        assert_eq!(limited[299].0, b"row/000299".to_vec());

        // A bounded range starting mid-keyspace: start is inclusive, end exclusive.
        let ranged = client
            .scan(
                Some(b"row/000500".to_vec()),
                Some(b"row/001000".to_vec()),
                Some(10_000),
            )
            .await
            .expect("ranged scan");
        assert_eq!(ranged.len(), 500, "the range bounds must be exact");
        assert_eq!(ranged.first().expect("first row").0, b"row/000500".to_vec());
        assert_eq!(ranged.last().expect("last row").0, b"row/000999".to_vec());
    });
}
