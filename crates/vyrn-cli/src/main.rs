use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use std::path::PathBuf;
use vyrn_client::Client;

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
        println!("wrote Argon2id verifier to {}", output.display());
        return Ok(());
    }
    let command = args.command.context("a command is required")?;
    match command {
        Command::Backup { data, output } => {
            vyrn_core::backup::create_backup(data, &output)?;
            println!("created and synchronized {}", output.display());
            return Ok(());
        }
        Command::VerifyBackup { archive } => {
            vyrn_core::backup::verify_backup(&archive)?;
            println!("verified {}", archive.display());
            return Ok(());
        }
        Command::Restore { archive, target } => {
            vyrn_core::backup::restore_backup(archive, &target)?;
            println!("restored {}", target.display());
            return Ok(());
        }
        Command::Export { data, output } => {
            let engine = vyrn_core::Engine::open(&data)?;
            let pairs = vyrn_core::portable::export(&engine, &output)?;
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
            let pairs = vyrn_core::portable::import(&mut engine, &dump)?;
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
            vyrn_core::backup::restore_backup(base, &target)?;
            let lsn = vyrn_core::recover::recover_to(
                &target,
                archive.as_deref(),
                until_lsn,
                allow_partial,
            )
            .with_context(|| {
                format!(
                    "recovery failed; {} is unusable and must be deleted before retrying",
                    target.display()
                )
            })?;
            println!("recovered {} to LSN {}", target.display(), lsn);
            println!("give the recovered database a new, empty archive directory before archiving from it");
            return Ok(());
        }
        Command::VerifyArchive { archive } => {
            let summary = vyrn_core::wal_archive::verify_archive(&archive)?;
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
            let pruned = vyrn_core::wal_archive::prune_wal(&data, &archive, through)?;
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
    let mut client = Client::connect_with_ca(&url, args.tls_ca_file.as_deref())
        .await
        .context("failed to connect to Vyrn")?;

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
