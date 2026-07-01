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
