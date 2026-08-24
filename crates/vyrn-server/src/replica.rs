//! The replica side: connect to a primary, apply its records, acknowledge them.
//!
//! THE ORDER HERE IS THE GUARANTEE. For every batch of records:
//!
//!   1. verify framing and CRC (`replication::verify_record`)
//!   2. append + apply to the local engine (`apply_replicated_record`)
//!   3. `sync_through` — the record is now durable on THIS node's storage
//!   4. only then send `ReplicaAck`
//!
//! Acknowledging before step 3 completes would make the primary's promise to its
//! client false: it would report a write as replicated when the replica held it
//! only in a page cache that a power cut discards. Every other design decision
//! in this file is negotiable; that ordering is not.
//!
//! A replica reconnects on failure with backoff rather than exiting. An operator
//! who has configured `--replication-min-acks 1` has a primary that blocks writes
//! while this process is away, so giving up would turn a transient network fault
//! into an outage requiring manual intervention.

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::{
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;
use vyrn_core::{
    replication::{check_join, verify_record, Divergence},
    Engine, ReadEngine,
};
use vyrn_protocol::{Envelope, Message, VyrnCodec};

use crate::BoxedTransport;

/// Reconnect backoff bounds. Starts fast because most failures are transient
/// (a primary restart, a brief network blip), and caps so a long outage does not
/// become an effectively-infinite wait.
const RECONNECT_MIN: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How much archived WAL one gap-closing batch applies at a time.
///
/// Bounded because an archive can be far larger than memory: a replica that was
/// offline for a day may need more records than this process could hold, so they
/// are applied incrementally rather than read whole. Both bounds are honoured
/// together, since neither a record count nor a byte count alone describes a log
/// whose records range from tens of bytes to megabytes.
///
/// Matched to the stream's own batching intent: large enough that one `fdatasync`
/// covers many records, small enough that a failure part-way through has repeated
/// only a bounded amount of work.
const ARCHIVE_BATCH_RECORDS: usize = 1_024;
const ARCHIVE_BATCH_BYTES: usize = 32 * 1024 * 1024;

pub struct ReplicaConfig {
    /// `vyrn://user@host:port/database` of the primary.
    pub primary_url: String,
    pub password: String,
    pub ca_file: Option<std::path::PathBuf>,
    pub replica_id: String,
    pub allow_plaintext: bool,
    /// WAL archive to recover pruned records from when the primary's stream does
    /// not abut this replica's log.
    ///
    /// `None` leaves the previous behaviour for that case — a loud failure telling
    /// the operator to rebuild — because closing a gap requires the records, and
    /// without an archive this node genuinely does not have them. Pointing this at
    /// the primary's archive is what turns "rebuild this replica by hand" into an
    /// automatic recovery.
    pub wal_archive_dir: Option<std::path::PathBuf>,
    /// The read handles clients are served from.
    ///
    /// Reads do NOT go through the write engine — they use separate
    /// `ReadEngine`s, each with its own view of a published tree generation. On a
    /// primary those are advanced by `publish_commit` once a batch is durable.
    /// A replica has no such path, so without refreshing these itself an applied
    /// record is durable and invisible: the WAL and the write engine hold it, and
    /// every client read still answers from the generation before it.
    pub readers: Arc<Vec<RwLock<ReadEngine>>>,
}

/// Runs the replica loop until the process is shut down.
///
/// Never returns `Ok` in normal operation; it reconnects indefinitely.
pub async fn run(engine: Arc<RwLock<Engine>>, config: ReplicaConfig) -> Result<()> {
    let mut backoff = RECONNECT_MIN;
    loop {
        match stream_once(&engine, &config).await {
            Ok(()) => {
                // A clean end means the primary closed the stream — reconnect
                // promptly rather than backing off, since nothing is broken.
                eprintln!("replication stream ended; reconnecting");
                backoff = RECONNECT_MIN;
            }
            Err(error) => {
                eprintln!("replication failed: {error:#}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
                continue;
            }
        }
        tokio::time::sleep(RECONNECT_MIN).await;
    }
}

/// One connection's lifetime: handshake, then stream until it ends.
async fn stream_once(engine: &Arc<RwLock<Engine>>, config: &ReplicaConfig) -> Result<()> {
    let (host, port, username, database, tls_required) = parse_url(&config.primary_url)?;

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .context("timed out connecting to the primary")?
        .with_context(|| format!("failed to connect to {host}:{port}"))?;
    stream.set_nodelay(true).ok();

    let transport: BoxedTransport = if tls_required {
        let ca = config
            .ca_file
            .as_deref()
            .context("TLS requires a CA certificate; pass --replica-ca-file")?;
        Box::new(connect_tls(stream, &host, ca).await?)
    } else {
        if !config.allow_plaintext {
            bail!(
                "refusing to replicate over plaintext; supply a CA certificate or set \
                 --allow-plaintext for isolated local testing"
            );
        }
        Box::new(stream)
    };

    let mut framed = Framed::new(transport, VyrnCodec::default());

    // Same credentials and same handshake as any client: replication is a role a
    // connection takes AFTER authenticating, not a separate door into the server.
    framed
        .send(Envelope::new(
            1,
            Message::Authenticate {
                username,
                password: config.password.clone(),
                database: database.clone(),
            },
        ))
        .await?;
    match framed.next().await {
        Some(Ok(envelope)) => match envelope.message {
            Message::Authenticated => {}
            Message::Error { message, .. } => bail!("primary rejected authentication: {message}"),
            other => bail!("unexpected reply to authentication: {other:?}"),
        },
        Some(Err(error)) => return Err(error.into()),
        None => bail!("primary closed the connection during authentication"),
    }

    // Where this replica's log ends decides where the stream must start.
    let last_lsn = engine
        .read()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?
        .last_lsn();

    framed
        .send(Envelope::new(
            2,
            Message::ReplicaHello {
                database,
                last_lsn,
                replica_id: config.replica_id.clone(),
            },
        ))
        .await?;

    let first_lsn = match framed.next().await {
        Some(Ok(envelope)) => match envelope.message {
            Message::ReplicaStream { first_lsn } => first_lsn,
            /* The primary is refusing the join. This is not retryable by
             * reconnecting — the histories genuinely disagree — so it is fatal
             * and loud rather than a backoff loop that hides it. */
            Message::ReplicaDiverged { reason } => {
                bail!(
                    "primary refused replication: {reason}\n\
                     This will not resolve by retrying. Rebuild this replica from a base backup."
                )
            }
            Message::Error { message, .. } => bail!("primary refused replication: {message}"),
            other => bail!("unexpected reply to ReplicaHello: {other:?}"),
        },
        Some(Err(error)) => return Err(error.into()),
        None => bail!("primary closed the connection during the replication handshake"),
    };

    eprintln!(
        "replicating from {host}:{port} starting at LSN {first_lsn} (local log ends at {last_lsn})"
    );

    /* CLOSE A GAP BEFORE CONSUMING THE STREAM.
     *
     * `check_join` is the replica's own judgement about whether the primary's
     * stream abuts its log. `GapBeforeStream` means the records in between were
     * checkpointed and pruned on the primary, so streaming cannot deliver them —
     * and applying the stream anyway would produce a WAL with a hole in it, which
     * this node's own recovery would refuse to open on the next restart.
     *
     * This used to be fatal. The primary refused the join outright, the replica
     * bailed with "rebuild from a base backup", and the reconnect loop repeated
     * that forever — so a replica that had merely been offline across a few
     * checkpoints came back permanently broken, while a `min-acks 1` primary
     * blocked writes waiting for the quorum that replica was supposed to supply.
     * Only an operator noticing and rebuilding by hand ended it.
     *
     * Now the gap is closed from the WAL archive, which holds exactly those
     * pruned segments — byte for byte the primary's own records. Rebuilding this
     * way needs no second `Engine::open` (this process already holds the data
     * directory's lock) and reuses `apply_batch`, so archived records take the
     * same verify → append → sync → publish path a streamed record takes.
     */
    if let Some(divergence) = check_join(last_lsn, primary_lsn(last_lsn, first_lsn), first_lsn) {
        match divergence {
            Divergence::GapBeforeStream {
                replica_lsn,
                first_lsn,
            } => {
                let Some(archive) = config.wal_archive_dir.as_deref() else {
                    bail!(
                        "this replica is at LSN {replica_lsn} but the primary's stream starts at \
                         {first_lsn}; the records in between were pruned on the primary and no \
                         WAL archive is configured here to recover them. Pass \
                         --replica-wal-archive-dir pointing at the primary's archive, or rebuild \
                         this replica from a base backup."
                    )
                };
                eprintln!(
                    "gap detected: local log ends at {replica_lsn}, primary streams from \
                     {first_lsn}; closing the gap from the WAL archive at {}",
                    archive.display()
                );
                let reached =
                    close_gap_from_archive(engine, &config.readers, archive, first_lsn).await?;
                /* The archive has to reach the record directly before the
                 * stream's first, or applying the stream would still leave a
                 * hole. Reported rather than papered over: an archive that is
                 * itself behind is an operator problem (the archiver is not
                 * keeping up, or this replica is pointed at a stale copy), and
                 * continuing would corrupt this replica's log. */
                if reached.saturating_add(1) < first_lsn {
                    bail!(
                        "the WAL archive closed the gap only to LSN {reached}, but the primary's \
                         stream starts at {first_lsn}; the archive is missing the records in \
                         between. Rebuild this replica from a base backup taken after \
                         LSN {reached}."
                    );
                }
                eprintln!("gap closed from the archive through LSN {reached}");
            }
            // The other two are genuinely unrecoverable by streaming, and the
            // primary refuses them before it ever offers a stream; reaching one
            // here means the primary offered something inconsistent with what it
            // was told, which must not be applied.
            other => bail!("refusing the primary's stream: {other}"),
        }
    }

    apply_stream(engine, &config.readers, &mut framed).await
}

/// The primary LSN to validate a join against, given what the primary offered.
///
/// `check_join`'s first test is "is this replica AHEAD of the primary", which the
/// primary itself has already made and refused on. The replica does not learn the
/// primary's LSN from `ReplicaStream` — only where the stream begins — so this
/// supplies a value that cannot trip that test, leaving the gap check as the one
/// this side is actually deciding. Named rather than inlined so the reasoning is
/// attached to it: passing the replica's own LSN here would be a silent way of
/// disabling a check that looks like it is running.
fn primary_lsn(replica_lsn: u64, first_lsn: u64) -> u64 {
    replica_lsn.max(first_lsn)
}

/// Applies archived records from `from_lsn` until the archive is exhausted,
/// returning the highest LSN this replica now holds.
///
/// Batched for the same reason the stream is: one `fdatasync` per batch rather
/// than per record, and bounded so an archive far larger than memory is applied
/// incrementally instead of being read whole.
async fn close_gap_from_archive(
    engine: &Arc<RwLock<Engine>>,
    readers: &Arc<Vec<RwLock<ReadEngine>>>,
    archive: &Path,
    through_at_least: u64,
) -> Result<u64> {
    let mut last = engine
        .read()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?
        .last_lsn();
    loop {
        let from = last.saturating_add(1);
        let directory = archive.to_path_buf();
        let records = tokio::task::spawn_blocking(move || {
            vyrn_core::replication::archived_records_from(
                &directory,
                from,
                ARCHIVE_BATCH_RECORDS,
                ARCHIVE_BATCH_BYTES,
            )
        })
        .await
        .context("archive read task failed")?
        .context("failed to read the WAL archive")?;
        if records.is_empty() {
            return Ok(last);
        }
        // The same apply path a streamed batch takes, so archived records get the
        // same verification, the same durability barrier, and the same publish to
        // the read handles.
        match apply_batch(engine, readers, &records).await? {
            Some(applied) => last = applied,
            /* Every record in the batch was a duplicate and nothing advanced. The
             * archive cannot take this replica further, so stopping here is what
             * prevents an infinite loop asking for the same records forever. */
            None => return Ok(last),
        }
        if last >= through_at_least.saturating_sub(1) {
            return Ok(last);
        }
    }
}

/// Receives records, makes them durable, and acknowledges them.
async fn apply_stream(
    engine: &Arc<RwLock<Engine>>,
    readers: &Arc<Vec<RwLock<ReadEngine>>>,
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
) -> Result<()> {
    while let Some(envelope) = framed.next().await {
        let envelope = envelope?;
        match envelope.message {
            Message::ReplicaRecords { records } => {
                let durable_lsn = apply_batch(engine, readers, &records).await?;
                if let Some(durable_lsn) = durable_lsn {
                    framed
                        .send(Envelope::new(0, Message::ReplicaAck { durable_lsn }))
                        .await?;
                }
            }
            Message::ReplicaDiverged { reason } => {
                bail!(
                    "primary ended the stream: {reason}\n\
                     Reconnecting will resume from this replica's last LSN."
                )
            }
            Message::Error { message, .. } => bail!("primary reported an error: {message}"),
            // A primary should send nothing else on a replication stream; ignore
            // rather than fail, so a future frame type does not break old replicas.
            _ => {}
        }
    }
    Ok(())
}

/// Verifies, applies and syncs one batch, returning the LSN now durable.
///
/// `None` when every record was a duplicate, in which case there is nothing new
/// to acknowledge.
async fn apply_batch(
    engine: &Arc<RwLock<Engine>>,
    readers: &Arc<Vec<RwLock<ReadEngine>>>,
    records: &[Vec<u8>],
) -> Result<Option<u64>> {
    let engine = Arc::clone(engine);
    let readers = Arc::clone(readers);
    let records = records.to_vec();

    /* `spawn_blocking` because appending and `fdatasync` are blocking file I/O.
     * Running them on the async runtime would stall every other task on this
     * thread for the duration of a disk barrier. */
    tokio::task::spawn_blocking(move || -> Result<Option<u64>> {
        let mut engine = engine
            .write()
            .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
        let mut applied = None;

        for record in &records {
            // Verify BEFORE the engine sees it. `apply_replicated_record` trusts
            // the framing, so this is the boundary where a malformed or
            // wrong-version record is turned away.
            let header = verify_record(record).context("rejected a replicated record")?;

            // A reconnect can legitimately resend records this replica already
            // has; skipping them is normal, not an error.
            if header.lsn <= engine.last_lsn() {
                continue;
            }
            applied = Some(engine.apply_replicated_record(record)?);
        }

        // ONE barrier for the whole batch, and the acknowledgement comes after it.
        // Syncing per record would pay a disk barrier per commit and make a
        // replica slower than its primary, which is what group commit exists to
        // avoid on the primary too.
        if let Some(lsn) = applied {
            engine.wal().sync_through(lsn)?;

            /* PUBLISH TO THE READERS, or the record is durable and invisible.
             *
             * Reads are served from separate `ReadEngine` handles, not from the
             * write engine. On a primary `publish_commit` advances them once a
             * batch is durable; a replica has no such path, so it must do it
             * here. Without this a client reading from a replica gets "not
             * found" for a key the replica demonstrably holds — measured, not
             * theorised: that is exactly what the first two-node test did.
             *
             * After the sync, deliberately: a reader must never serve a record
             * that is not yet durable, because a crash would then have shown a
             * client data the replica no longer has.
             */
            let (generation, root, len) = engine.committed_root();
            for reader in readers.iter() {
                match reader.write() {
                    Ok(mut reader) => reader.refresh(generation, root, len)?,
                    // A poisoned reader lock means another thread panicked while
                    // holding it. Failing here surfaces that rather than silently
                    // serving stale reads from that handle forever.
                    Err(_) => bail!("reader lock poisoned while publishing a replicated commit"),
                }
            }
        }
        Ok(applied)
    })
    .await
    .context("replica apply task failed")?
}

async fn connect_tls(
    stream: TcpStream,
    host: &str,
    ca: &Path,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(ca).with_context(|| format!("failed to open CA file {ca:?}"))?,
    ))
    .collect::<std::result::Result<Vec<_>, _>>()
    .context("failed to parse the CA certificate")?;
    if certificates.is_empty() {
        bail!("CA file {ca:?} contains no certificates");
    }
    for certificate in certificates {
        roots
            .add(certificate)
            .context("failed to add a CA certificate")?;
    }
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow::anyhow!("primary host is not a valid TLS server name"))?;
    let tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(server_name, stream),
    )
    .await
    .context("timed out during the TLS handshake")?
    .context("TLS handshake with the primary failed")?;
    Ok(tls)
}

/// Parses `vyrn://user@host:port/database`, with an optional `?tls=disable`.
///
/// Deliberately minimal rather than pulling in a URL crate the server does not
/// otherwise need: this accepts exactly the form the client documents.
fn parse_url(url: &str) -> Result<(String, u16, String, String, bool)> {
    let rest = url
        .strip_prefix("vyrn://")
        .context("primary URL must start with vyrn://")?;
    let (rest, tls_required) = match rest.split_once('?') {
        Some((head, query)) => {
            let disable = query.split('&').any(|pair| pair.trim() == "tls=disable");
            (head, !disable)
        }
        None => (rest, true),
    };
    let (authority, database) = rest
        .split_once('/')
        .context("primary URL must include a database, e.g. vyrn://user@host:7432/default")?;
    let (username, host_port) = authority
        .split_once('@')
        .context("primary URL must include a username, e.g. vyrn://user@host:7432/default")?;
    if username.contains(':') {
        bail!("pass the replica's password with --replica-password-file, not in the URL");
    }
    let (host, port) = host_port
        .rsplit_once(':')
        .context("primary URL must include a port")?;
    let port: u16 = port.parse().context("primary URL has an invalid port")?;
    if host.is_empty() || database.is_empty() {
        bail!("primary URL is missing a host or database");
    }
    Ok((
        host.to_owned(),
        port,
        username.to_owned(),
        database.to_owned(),
        tls_required,
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_url;

    #[test]
    fn parses_a_tls_url() {
        let (host, port, user, database, tls) =
            parse_url("vyrn://repl@primary.internal:7432/app").expect("parse");
        assert_eq!(
            (host.as_str(), port, user.as_str(), database.as_str(), tls),
            ("primary.internal", 7432, "repl", "app", true)
        );
    }

    #[test]
    fn tls_can_be_disabled_explicitly() {
        let (.., tls) = parse_url("vyrn://repl@127.0.0.1:7432/app?tls=disable").expect("parse");
        assert!(!tls, "tls=disable must be honoured");
    }

    #[test]
    fn tls_is_required_by_default() {
        let (.., tls) = parse_url("vyrn://repl@127.0.0.1:7432/app").expect("parse");
        assert!(tls, "TLS must be the default, never opt-in");
    }

    #[test]
    fn a_password_in_the_url_is_refused() {
        // Passwords in URLs reach logs, shell history and process listings.
        assert!(parse_url("vyrn://repl:secret@host:7432/app").is_err());
    }

    #[test]
    fn malformed_urls_are_refused() {
        for url in [
            "http://host:7432/app",
            "vyrn://host:7432/app",
            "vyrn://repl@host/app",
            "vyrn://repl@host:7432",
            "vyrn://repl@host:notaport/app",
        ] {
            assert!(parse_url(url).is_err(), "{url} should be refused");
        }
    }
}
