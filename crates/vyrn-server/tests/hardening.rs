//! Connection-hardening behaviours that need the real binary on a real socket.
//!
//! Same shape as `replication.rs`: spawn the SHIPPED `vyrnd` over plaintext
//! loopback with ephemeral ports. These cover what in-process unit tests
//! cannot — what an unauthenticated peer can make the server do before it has
//! shown any credential, and whether a flood of bad passwords locks the door
//! rather than paying for a password hash per guess forever.
//!
//! Plaintext is deliberate: TLS would put the same bytes behind an acceptor and
//! test rustls instead of the server.

use std::{
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const PASSWORD: &str = "hardening-integration-test-password";

/// Mirrors `AUTH_FAILURE_LIMIT` in the server.
///
/// Duplicated because `vyrnd` is a binary and cannot be imported. If the two ever
/// disagree the lockout tests fail rather than passing vacuously: too low a value
/// here would not trip the real lockout, and the assertions require it to trip.
const AUTH_FAILURE_LIMIT: u32 = 10;

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

    /// One numeric metric from `/metrics`, or 0 when absent.
    ///
    /// The name must be followed by whitespace, so asking for a metric whose name
    /// is a prefix of another cannot silently return the wrong series' value.
    fn metric(&self, name: &str) -> u64 {
        http_get(self.admin_port, "/metrics")
            .unwrap_or_default()
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix(name)?;
                if !rest.starts_with(char::is_whitespace) {
                    return None;
                }
                rest.trim().parse().ok()
            })
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
/// Fixed salt: the credential is a constant in this file and the directory is
/// deleted afterwards, so there is nothing a per-run salt would protect (same
/// reasoning as `replication.rs`; enabling `getrandom` just for tests would
/// change what production pulls in).
fn write_password_hash(path: &Path) {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::from_b64("dmVyeXNhbHR5c2FsdA").expect("valid salt");
    let hash = Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &salt)
        .expect("hash password")
        .to_string();
    std::fs::write(path, hash).expect("write hash");
}

fn spawn(data: &Path, hash: &Path) -> Node {
    spawn_with_log(data, hash, None)
}

/// Spawns a node, optionally redirecting its stderr to `log` so a test can read
/// back what it wrote.
///
/// Separate from [`spawn`] because capturing the log is the exception: a pipe
/// would fill and block the server once nothing drained it, so the capture goes
/// to a file and the ordinary case keeps discarding.
fn spawn_with_log(data: &Path, hash: &Path, log: Option<&Path>) -> Node {
    let port = free_port();
    let admin_port = free_port();
    let stderr = match log {
        Some(path) => Stdio::from(std::fs::File::create(path).expect("create log file")),
        None => Stdio::null(),
    };
    let child = Command::new(vyrnd())
        .env("VYRN_BIND", format!("127.0.0.1:{port}"))
        .env("VYRN_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("VYRN_DATA", data)
        .env("VYRN_PASSWORD_HASH_FILE", hash)
        .env("VYRN_ALLOW_PLAINTEXT", "true")
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn vyrnd");
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

/// One authentication attempt on its own connection, returning the client's
/// error so callers can inspect the code.
///
/// The connected client is dropped rather than returned: `Client` is not
/// `Debug`, and every caller here only cares about the rejection.
fn connect(url: &str) -> Result<(), vyrn_client::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    runtime
        .block_on(vyrn_client::Client::connect(url))
        .map(drop)
}

fn put(url: &str, key: &str, value: &str) -> Result<(), String> {
    let key = key.to_owned();
    let value = value.to_owned();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    runtime.block_on(async move {
        let mut client = vyrn_client::Client::connect(url)
            .await
            .map_err(|error| error.to_string())?;
        client
            .put(key.into_bytes(), value.into_bytes())
            .await
            .map_err(|error| error.to_string())
    })
}

/// The URL of `node` but with a different password, for bad-credential tries.
fn url_with_password(node: &Node, password: &str) -> String {
    format!(
        "vyrn://vyrn:{password}@127.0.0.1:{}/default?tls=disable",
        node.port
    )
}

fn is_authentication_failed(error: &vyrn_client::Error) -> bool {
    matches!(
        error,
        vyrn_client::Error::Server {
            code: vyrn_protocol::ErrorCode::AuthenticationFailed,
            ..
        }
    )
}

#[test]
fn repeated_failures_lock_out_even_the_correct_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&dir.path().join("data"), &hash);

    // Sanity: the real password works before anything is locked.
    put(&node.url(), "warmup", "value").expect("correct credentials should work");

    // AUTH_FAILURE_LIMIT bad attempts. Each one pays for a real Argon2
    // verification — that is the cost being capped here.
    let wrong = url_with_password(&node, "not-the-password");
    for attempt in 1..=10 {
        let error = connect(&wrong).expect_err("bad password must be refused");
        assert!(
            is_authentication_failed(&error),
            "attempt {attempt} should be refused as AuthenticationFailed, got {error:?}"
        );
    }

    // Now the throttle holds the door shut: the CORRECT password is refused
    // too. Reaching this state is only possible if refusal happens BEFORE the
    // password verification, because the correct password would otherwise
    // authenticate and reset the counter.
    let error = connect(&node.url()).expect_err("lockout must refuse every attempt");
    assert!(
        is_authentication_failed(&error),
        "locked-out attempt should fail fast as AuthenticationFailed, got {error:?}"
    );

    // Every rejection is counted, including the lockout refusals.
    let counted = node.metric("vyrn_auth_failures_total");
    assert!(
        counted >= 11,
        "every rejected authentication must be counted, saw {counted}"
    );

    // The server itself is fine — a lockout is not a crash.
    assert!(http_get(node.admin_port, "/health/live").is_some());
}

/// Sends raw bytes and returns what the server sends back, or `None` on a
/// clean close. `settle` bounds how long the server may take to react.
fn raw_exchange(port: u16, payload: &[u8], settle: Duration) -> Option<Vec<u8>> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(settle)).expect("read timeout");
    stream.write_all(payload).expect("write payload");
    let mut response = Vec::new();
    match stream.read(&mut response) {
        Ok(0) => None,           // clean close, nothing sent
        Ok(_) => Some(response), // the server answered
        Err(_) => None,          // reset / timeout
    }
}

/// Frames one payload the way both peers do: u32 big-endian length prefix.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[test]
fn oversized_preauth_frames_are_rejected_before_authentication() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&dir.path().join("data"), &hash);

    /* The length prefix alone claims an 8 MiB frame — far over the pre-auth
     * ceiling, far under the authenticated 64 MiB one. The server must refuse
     * this at the length header, BEFORE buffering the body: it closes almost
     * immediately. A server still willing to buffer unauthenticated frames
     * would sit reading the claimed 8 MiB until the 10s handshake timeout. */
    let mut greedy = Vec::with_capacity(4 + 64 * 1024);
    greedy.extend_from_slice(&(8 * 1024 * 1024_u32).to_be_bytes());
    greedy.extend(std::iter::repeat_n(0u8, 64 * 1024));

    let started = Instant::now();
    let reply = raw_exchange(node.port, &greedy, Duration::from_secs(2));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "an oversized pre-auth frame must be refused at the length header, \
         not buffered until the handshake timeout (took {:?})",
        started.elapsed()
    );
    assert!(
        reply.is_none(),
        "the server must not answer an unauthenticated oversized frame"
    );

    // And the refusal did not hurt the server: real clients still work.
    put(&node.url(), "after/flood", "value").expect("server should keep serving");
}

#[test]
fn a_foreign_protocol_version_is_closed_not_misread() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&dir.path().join("data"), &hash);

    /* Ten bytes of payload: version 999 plus a request id. The codec names the
     * version before reading anything else, so this is rejected as a version,
     * never decoded as a request — and the connection is closed rather than
     * answered, because there is no envelope to reply to. */
    let mut payload = Vec::new();
    payload.extend_from_slice(&999_u16.to_be_bytes());
    payload.extend_from_slice(&7_u64.to_be_bytes());
    let reply = raw_exchange(node.port, &frame(&payload), Duration::from_secs(2));
    assert!(
        reply.is_none(),
        "a foreign version must be closed, not answered: {reply:?}"
    );
}

/// Opens a transaction, writes inside it, then abandons the connection without
/// committing or rolling back — the disconnect that used to leak a snapshot pin.
fn abandon_transaction_mid_flight(url: &str) {
    let url = url.to_owned();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    runtime.block_on(async move {
        let mut client = vyrn_client::Client::connect(&url)
            .await
            .expect("connect for abandoned transaction");
        {
            let mut transaction = client.transaction().await.expect("begin");
            transaction
                .put(b"abandoned".to_vec(), b"value".to_vec())
                .await
                .expect("write inside transaction");
            /* The transaction is abandoned by letting it fall out of scope at the
             * end of this block. It has no `Drop`, and that is the point: nothing
             * is sent, so neither Commit nor Rollback ever reaches the server. The
             * only thing that can release the snapshot is the server's
             * connection-teardown path being correct. */
        }
        // Closing the socket is the "vanishing client" this test is about.
        drop(client);
    });
}

#[test]
fn abandoning_a_transaction_does_not_pin_mvcc_history_forever() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&dir.path().join("data"), &hash);

    /* WHAT THIS CATCHES: a transaction pins an engine snapshot, and the MVCC
     * floor is the minimum over live snapshots. The release used to sit after a
     * loop full of `?` on response writes, so a client that vanished
     * mid-transaction returned straight past it. One such disconnect pinned the
     * floor for the remaining life of the process: version collection stopped
     * and history grew without bound, while every metric still looked healthy.
     *
     * Asserted on `vyrn_active_transaction_snapshots`, which counts the pins
     * themselves. The obvious alternative — watching
     * `vyrn_mvcc_versions_collected_total` stall — does NOT work: history is only
     * recorded for versions some snapshot still needs, so with no open
     * transaction there is nothing to collect and the counter sits at zero
     * whether or not the pin leaked. A test built on it would pass either way. */
    assert_eq!(
        node.metric("vyrn_active_transaction_snapshots"),
        0,
        "no transaction has been opened yet"
    );

    abandon_transaction_mid_flight(&node.url());

    /* The pin is released on the server's connection-teardown path, which runs
     * asynchronously after the socket closes, so this polls rather than reading
     * once. A leak never reaches zero and the poll runs out. */
    let pinned = wait_for_metric_to_reach(&node, "vyrn_active_transaction_snapshots", 0);
    assert_eq!(
        pinned, 0,
        "a transaction abandoned by a vanishing client left its snapshot pinned; \
         MVCC collection is now blocked for the life of the process"
    );

    // The server is still fully usable, so the release path did not take the
    // connection handler down with it.
    put(&node.url(), "after/abandon", "value").expect("server should keep serving");
}

/// Polls a metric until it drops to `target`, returning the last value seen.
fn wait_for_metric_to_reach(node: &Node, name: &str, target: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = node.metric(name);
    while Instant::now() < deadline && last != target {
        std::thread::sleep(Duration::from_millis(100));
        last = node.metric(name);
    }
    last
}

/* NOT COVERED HERE: the shutdown final sync.
 *
 * `main` now syncs the engine after draining, so a write acknowledged under
 * `--durability async` survives an orderly stop. Exercising it needs a GRACEFUL
 * stop — SIGTERM or Ctrl-C — and Windows offers no portable way to send one to a
 * child process from `std`. `Child::kill` is the SIGKILL equivalent, which
 * exercises crash recovery instead of the shutdown path and would pass whether
 * or not the sync exists.
 *
 * A `#[cfg(unix)]` test would compile out on the machine this was written on and
 * so would ship unrun. `scripts/crash-soak.sh` (task E3) is the right home for
 * it, being Linux-only by design. Until then this fix is reviewed, not tested. */

#[test]
fn a_locked_out_address_is_refused_without_paying_for_a_password_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let node = spawn(&dir.path().join("data"), &hash);

    let wrong = url_with_password(&node, "not-the-password");
    // Trip the lockout, timing the attempts that DO reach Argon2.
    let verifying = Instant::now();
    for _ in 0..AUTH_FAILURE_LIMIT {
        let _ = connect(&wrong);
    }
    let per_verification = verifying.elapsed() / AUTH_FAILURE_LIMIT;

    /* Now attempts are refused before the hash. The check is comparative rather
     * than an absolute threshold, because absolute timings are meaningless on a
     * loaded CI box: a refusal must be much cheaper than a verification, and
     * "an order of magnitude" is the claim that matters. */
    let refusing = Instant::now();
    for _ in 0..AUTH_FAILURE_LIMIT {
        let _ = connect(&wrong);
    }
    let per_refusal = refusing.elapsed() / AUTH_FAILURE_LIMIT;

    assert!(
        per_refusal * 5 < per_verification,
        "a locked-out attempt must be refused before the Argon2 verification: \
         refusal took {per_refusal:?}, a real verification took {per_verification:?}"
    );
}

#[test]
fn a_rejected_handshake_is_logged_without_the_credential_it_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = dir.path().join("password.phc");
    write_password_hash(&hash);
    let log = dir.path().join("vyrnd.log");
    let node = spawn_with_log(&dir.path().join("data"), &hash, Some(&log));

    /* A log that records a failed authentication records, by definition, a string
     * somebody believed was a password — and those turn up in the right log often
     * enough that this is worth asserting rather than assuming. The wrong password
     * here is distinctive so a substring search cannot miss it. */
    const WRONG: &str = "unmistakable-wrong-password-9f3a1c";
    let wrong = url_with_password(&node, WRONG);
    let error = connect(&wrong).expect_err("bad password must be refused");
    assert!(is_authentication_failed(&error));

    // A successful handshake too: the correct credential must not leak either.
    put(&node.url(), "logged", "value").expect("correct credentials should work");

    // Stop the server so its stderr is flushed and complete before it is read.
    drop(node);
    let written = std::fs::read_to_string(&log).unwrap_or_default();

    assert!(
        !written.contains(WRONG),
        "the rejected password appears in the log:\n{written}"
    );
    assert!(
        !written.contains(PASSWORD),
        "the real password appears in the log:\n{written}"
    );
    // The Argon2 hash is a credential too — an offline cracking target.
    let stored = std::fs::read_to_string(&hash).expect("read hash");
    assert!(
        !written.contains(stored.trim()),
        "the stored password hash appears in the log:\n{written}"
    );
    // And the rejection is still reported, so this is not passing by silence.
    assert!(
        written.contains("authentication failed"),
        "a rejected handshake must be logged at all:\n{written}"
    );
}
