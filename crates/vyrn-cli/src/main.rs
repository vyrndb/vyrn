use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use std::path::{Path, PathBuf};
use std::time::Instant;
use vyrn_client::Client;
use vyrn_log::{log_debug, log_error, log_info, redact_url};

#[derive(Parser)]
#[command(name = "vyrn", version, about = "Vyrn database command-line client")]
struct Args {
    #[arg(long, env = "VYRN_URL")]
    url: Option<String>,
    #[arg(long, env = "VYRN_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
    #[arg(long, env = "VYRN_TLS_CA_FILE")]
    tls_ca_file: Option<PathBuf>,
    #[arg(long, value_name = "OUTPUT_FILE")]
    hash_password: Option<PathBuf>,
    #[arg(long, requires = "hash_password")]
    password_input: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Backup {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    VerifyBackup {
        archive: PathBuf,
    },
    Restore {
        archive: PathBuf,
        #[arg(long)]
        target: PathBuf,
    },
    Recover {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        archive: Option<PathBuf>,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        until_lsn: Option<u64>,
        #[arg(long)]
        allow_partial: bool,
    },
    VerifyArchive {
        archive: PathBuf,
    },
    /// Write a logical dump that does not depend on the on-disk format.
    ///
    /// Take this with the build that wrote the database. Unlike a backup, which
    /// copies pages and can only be restored by a build speaking the same storage
    /// format, a dump carries only keys and values and so survives format changes.
    Export {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Load a logical dump into a fresh data directory.
    ///
    /// Refuses a directory that already holds data, so an import cannot merge
    /// into an existing database by accident. Secondary indexes are not carried
    /// by a dump and must be recreated afterwards.
    Import {
        dump: PathBuf,
        #[arg(long)]
        target: PathBuf,
    },
    WalPrune {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        through: u64,
    },
    Get {
        key: String,
        #[arg(long)]
        hex: bool,
    },
    Put {
        key: String,
        value: String,
    },
    Delete {
        key: String,
    },
    Scan {
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        end: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}

/// Refuses to treat a sharded data directory's ROOT as a database.
///
/// The root of a `--shards N` directory holds only the SHARDS marker and the
/// shard subdirectories; opening it as an engine would create a fresh empty
/// database there, and an export of that would be silently empty — the worst
/// possible answer for a migration tool. Each `shard-N/` subdirectory is a
/// complete ordinary database, so every offline tool works per shard.
fn refuse_sharded_root(data: &std::path::Path, operation: &str) -> Result<()> {
    if data.join("SHARDS").exists() {
        anyhow::bail!(
            "{} is a sharded data directory; run `{operation}` against each \
             shard-N subdirectory instead (each is a complete database), and \
             keep the SHARDS marker file with them",
            data.display()
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(output) = args.hash_password {
        let input = args
            .password_input
            .context("--password-input is required for non-interactive hash generation")?;
        let password = read_secret_file(&input)?;
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| anyhow::anyhow!("failed to hash password: {error}"))?;
        std::fs::write(&output, format!("{hash}\n"))
            .with_context(|| format!("failed to write {}", output.display()))?;
        // The path only. Neither the password nor the PHC string is logged: the
        // verifier is the thing an offline attacker needs to start guessing
        // against, so it belongs in the file the operator protects and nowhere
        // else.
        log_info!(
            "vyrn-cli",
            "wrote an Argon2id verifier",
            path = output.display(),
        );
        println!("wrote Argon2id verifier to {}", output.display());
        return Ok(());
    }
    let command = args.command.context("a command is required")?;
    match command {
        Command::Backup { data, output } => {
            refuse_sharded_root(&data, "backup")?;
            // Backup and restore are the operations an operator most needs a
            // durable record of: `docs/production.md` asks them to alert on
            // backup age, and a cron entry that redirects stdout to /dev/null
            // otherwise leaves no evidence of when a backup ran, how long it
            // took, or how large it came out. The human-readable line stays on
            // stdout; the record goes to stderr with the numbers.
            let started = Instant::now();
            let outcome = vyrn_core::backup::create_backup(data, &output);
            report_outcome("backup", &output, started, &outcome, archive_bytes(&output));
            outcome?;
            println!("created and synchronized {}", output.display());
            return Ok(());
        }
        Command::VerifyBackup { archive } => {
            let started = Instant::now();
            let outcome = vyrn_core::backup::verify_backup(&archive);
            report_outcome(
                "verify-backup",
                &archive,
                started,
                &outcome,
                archive_bytes(&archive),
            );
            outcome?;
            println!("verified {}", archive.display());
            return Ok(());
        }
        Command::Restore { archive, target } => {
            let started = Instant::now();
            let bytes = archive_bytes(&archive);
            let outcome = vyrn_core::backup::restore_backup(archive, &target);
            report_outcome("restore", &target, started, &outcome, bytes);
            outcome?;
            println!("restored {}", target.display());
            return Ok(());
        }
        Command::Export { data, output } => {
            refuse_sharded_root(&data, "export")?;
            let engine = vyrn_core::Engine::open(&data)?;
            let started = Instant::now();
            let outcome = vyrn_core::portable::export(&engine, &output);
            report_outcome("export", &output, started, &outcome, archive_bytes(&output));
            let pairs = outcome?;
            println!("exported {pairs} pairs to {}", output.display());
            return Ok(());
        }
        Command::Import { dump, target } => {
            // A fresh directory only. Importing into a populated database would
            // silently merge two datasets, and the caller asked to migrate one.
            if target.exists()
                && std::fs::read_dir(&target)
                    .with_context(|| format!("failed to read {}", target.display()))?
                    .next()
                    .is_some()
            {
                anyhow::bail!(
                    "{} is not empty; import requires a fresh directory",
                    target.display()
                );
            }
            std::fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
            let mut engine = vyrn_core::Engine::open(&target)?;
            let started = Instant::now();
            let bytes = archive_bytes(&dump);
            let outcome = vyrn_core::portable::import(&mut engine, &dump);
            report_outcome("import", &target, started, &outcome, bytes);
            let pairs = outcome?;
            println!("imported {pairs} pairs into {}", target.display());
            // Documents arrive without the index entries derived from them, so
            // `find` returns nothing for them until they are rebuilt. That is a
            // wrong answer rather than an error, so it is worth spelling out.
            println!(
                "a dump carries no derived state: declare each collection's indexes, then call \
                 document::rebuild_indexes for it, or indexed lookups will find nothing"
            );
            return Ok(());
        }
        Command::Recover {
            base,
            archive,
            target,
            until_lsn,
            allow_partial,
        } => {
            let started = Instant::now();
            let restored = vyrn_core::backup::restore_backup(base, &target);
            report_outcome(
                "recover-restore-base",
                &target,
                started,
                &restored,
                archive_bytes(&target),
            );
            restored?;
            let rolled_forward = Instant::now();
            let outcome = vyrn_core::recover::recover_to(
                &target,
                archive.as_deref(),
                until_lsn,
                allow_partial,
            );
            // Point-in-time recovery is run under pressure, usually once, and
            // step 6 of the runbook has the operator delete the target and start
            // over on failure — which destroys the evidence. The record of what
            // was attempted and what came back has to outlive the directory.
            report_outcome("recover", &target, rolled_forward, &outcome, None);
            let lsn = outcome.with_context(|| {
                format!(
                    "recovery failed; {} is unusable and must be deleted before retrying",
                    target.display()
                )
            })?;
            log_info!(
                "vyrn-cli.recover",
                "rolled forward to a recovery point",
                target = target.display(),
                lsn = lsn,
                requested_lsn =
                    until_lsn.map_or_else(|| "archive-end".to_owned(), |lsn| lsn.to_string()),
                allow_partial = allow_partial,
            );
            println!("recovered {} to LSN {}", target.display(), lsn);
            println!("give the recovered database a new, empty archive directory before archiving from it");
            return Ok(());
        }
        Command::VerifyArchive { archive } => {
            let started = Instant::now();
            let outcome = vyrn_core::wal_archive::verify_archive(&archive);
            report_outcome("verify-archive", &archive, started, &outcome, None);
            let summary = outcome?;
            log_info!(
                "vyrn-cli.verify-archive",
                "archive verified",
                archive = archive.display(),
                segments = summary.segments,
                first_lsn = summary.first_lsn,
                last_lsn = summary.last_lsn,
            );
            println!(
                "verified {}: {} segments covering LSN {}..={}",
                archive.display(),
                summary.segments,
                summary.first_lsn,
                summary.last_lsn
            );
            return Ok(());
        }
        Command::WalPrune {
            data,
            archive,
            through,
        } => {
            refuse_sharded_root(&data, "wal-prune")?;
            let started = Instant::now();
            let outcome = vyrn_core::wal_archive::prune_wal(&data, &archive, through);
            report_outcome("wal-prune", &data, started, &outcome, None);
            let pruned = outcome?;
            // Pruning fewer segments than asked for is normal — the archive may
            // not provably hold them, or replay may still need them locally —
            // so the requested bound is recorded next to what actually went, or
            // an operator reads the smaller number as a failure.
            log_info!(
                "vyrn-cli.wal-prune",
                "pruned archived WAL segments",
                data = data.display(),
                archive = archive.display(),
                requested_through = through,
                pruned = pruned,
            );
            println!("pruned {pruned} archived segments through id {through}");
            return Ok(());
        }
        _ => {}
    }

    let mut url = args.url.context("--url or VYRN_URL is required")?;
    if let Some(password_file) = args.password_file {
        let password = read_secret_file(&password_file)?;
        url = insert_password(&url, &password)?;
    }
    // Debug, not info: the CLI is interactive and its own stdout already tells
    // the operator what happened. A record per invocation at info level would
    // add noise to the shared stream for something the shell already shows.
    // The URL goes through redaction because `--password-file` has just been
    // spliced into it.
    log_debug!(
        "vyrn-cli",
        "connecting to the database",
        url = redact_url(&url),
        tls_ca_file = args
            .tls_ca_file
            .as_deref()
            .map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
    );
    let mut client = match Client::connect_with_ca(&url, args.tls_ca_file.as_deref()).await {
        Ok(client) => client,
        Err(error) => {
            log_error!(
                "vyrn-cli",
                "connection to the database failed",
                url = redact_url(&url),
                detail = error,
            );
            return Err(error).context("failed to connect to Vyrn");
        }
    };

    match command {
        Command::Get { key, hex: use_hex } => match client.get(key.into_bytes()).await? {
            Some(value) if use_hex => println!("{}", hex::encode(value)),
            Some(value) => println!("{}", String::from_utf8_lossy(&value)),
            None => println!("(not found)"),
        },
        Command::Put { key, value } => {
            client.put(key.into_bytes(), value.into_bytes()).await?;
            println!("OK");
        }
        Command::Delete { key } => {
            let existed = client.delete(key.into_bytes()).await?;
            println!("{}", if existed { "DELETED" } else { "NOT_FOUND" });
        }
        Command::Scan { start, end, limit } => {
            for (key, value) in client
                .scan(
                    start.map(String::into_bytes),
                    end.map(String::into_bytes),
                    Some(limit),
                )
                .await?
            {
                println!(
                    "{}\t{}",
                    String::from_utf8_lossy(&key),
                    String::from_utf8_lossy(&value)
                );
            }
        }
        Command::Backup { .. }
        | Command::VerifyBackup { .. }
        | Command::Restore { .. }
        | Command::Recover { .. }
        | Command::VerifyArchive { .. }
        | Command::WalPrune { .. }
        | Command::Export { .. }
        | Command::Import { .. } => {
            unreachable!("offline commands return before connecting")
        }
    }
    Ok(())
}

/// Logs how a durability-critical operation ended, with its duration.
///
/// Backup, restore, verification, pruning and recovery are the operations an
/// operator is asked to prove they ran. The exit status alone is not enough: a
/// backup that takes ten times longer than last week is the early warning that
/// the disk is failing, and a restore drill with no recorded duration cannot be
/// compared against the recovery-time objective it exists to validate. Duration
/// is always available; bytes only where the caller can name a file to measure.
///
/// Failures are logged as well as returned. `main` propagates the error and
/// anyhow prints it, but that goes to stderr unlevelled and untimestamped,
/// which is not something a log collector can pick out.
fn report_outcome<T, E: std::fmt::Display>(
    operation: &str,
    path: &Path,
    started: Instant,
    outcome: &Result<T, E>,
    bytes: Option<u64>,
) {
    let milliseconds = started.elapsed().as_millis();
    match outcome {
        Ok(_) => match bytes {
            Some(bytes) => log_info!(
                "vyrn-cli",
                "operation completed",
                operation = operation,
                path = path.display(),
                duration_ms = milliseconds,
                bytes = bytes,
            ),
            None => log_info!(
                "vyrn-cli",
                "operation completed",
                operation = operation,
                path = path.display(),
                duration_ms = milliseconds,
            ),
        },
        Err(error) => log_error!(
            "vyrn-cli",
            "operation failed",
            operation = operation,
            path = path.display(),
            duration_ms = milliseconds,
            detail = error,
        ),
    }
}

/// The size of a file, for the `bytes` field of an outcome record.
///
/// `None` when the file cannot be measured — it may not exist yet, or the
/// operation that would have created it may have failed. A missing size is a
/// missing field, never a logged zero: "0 bytes" reads as an empty backup,
/// which is a much more alarming claim than "size unknown".
fn archive_bytes(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
}

fn read_secret_file(path: &PathBuf) -> Result<String> {
    let secret = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let secret = secret.trim_end_matches(['\r', '\n']);
    if secret.is_empty() || secret.contains(['\r', '\n']) {
        anyhow::bail!("secret file must contain exactly one non-empty line");
    }
    Ok(secret.to_owned())
}

fn insert_password(url: &str, password: &str) -> Result<String> {
    let mut parsed = url::Url::parse(url).context("invalid Vyrn URL")?;
    parsed
        .set_password(Some(password))
        .map_err(|_| anyhow::anyhow!("URL cannot contain a password"))?;
    Ok(parsed.into())
}
