use clap::Parser;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_postgres::{Client, NoTls};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "POSTGRES_URL")]
    url: String,
    #[arg(long, default_value_t = 8)]
    clients: usize,
    #[arg(long, default_value_t = 1_000)]
    operations: usize,
    #[arg(long, default_value_t = 128)]
    value_size: usize,
    #[arg(long, default_value = "mixed")]
    mode: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());
    validate(&args)?;
    let prepare_client = connect(&args.url).await?;
    prepare_client
        .execute(
            "INSERT INTO kv (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=excluded.value",
            &[&b"load/hot".as_slice(), &vec![7_u8; args.value_size]],
        )
        .await?;
    if args.mode == "index" {
        prepare_client
            .execute(
                "INSERT INTO indexed_rows (id, indexed_value, value) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET indexed_value=excluded.indexed_value, value=excluded.value",
                &[&b"load/indexed".as_slice(), &b"hot".as_slice(), &vec![7_u8; args.value_size]],
            )
            .await?;
    }

    let mut clients = Vec::with_capacity(args.clients);
    for _ in 0..args.clients {
        clients.push(connect(&args.url).await?);
    }

    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.clients);
    for (client_id, mut client) in clients.into_iter().enumerate() {
        let args = Arc::clone(&args);
        tasks.push(tokio::spawn(async move {
            let value = vec![7_u8; args.value_size];
            let mut latencies = Vec::with_capacity(args.operations);
            for operation in 0..args.operations {
                let key = format!("load/{client_id:04}/{operation:012}").into_bytes();
                let begin = Instant::now();
                match args.mode.as_str() {
                    "write" => {
                        client
                            .execute(
                                "INSERT INTO kv (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=excluded.value",
                                &[&key, &value],
                            )
                            .await?;
                    }
                    "read" => {
                        let _ = client
                            .query_opt(
                                "SELECT value FROM kv WHERE key=$1",
                                &[&b"load/hot".as_slice()],
                            )
                            .await?;
                    }
                    "mixed" if operation % 10 < 3 => {
                        client
                            .execute(
                                "INSERT INTO kv (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=excluded.value",
                                &[&key, &value],
                            )
                            .await?;
                    }
                    "mixed" => {
                        let _ = client
                            .query_opt(
                                "SELECT value FROM kv WHERE key=$1",
                                &[&b"load/hot".as_slice()],
                            )
                            .await?;
                    }
                    "transaction" => {
                        let transaction = client.transaction().await?;
                        for item in 0..4_u8 {
                            let mut transaction_key = key.clone();
                            transaction_key.push(item);
                            transaction
                                .execute(
                                    "INSERT INTO kv (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=excluded.value",
                                    &[&transaction_key, &value],
                                )
                                .await?;
                        }
                        transaction.commit().await?;
                    }
                    "index" => {
                        let _ = client
                            .query(
                                "SELECT id FROM indexed_rows WHERE indexed_value=$1 ORDER BY id LIMIT 10",
                                &[&b"hot".as_slice()],
                            )
                            .await?;
                    }
                    _ => unreachable!(),
                }
                latencies.push(begin.elapsed());
            }
            Ok::<_, anyhow::Error>(latencies)
        }));
    }

    report(&args, started, tasks).await
}

fn validate(args: &Args) -> anyhow::Result<()> {
    if args.clients == 0 || args.operations == 0 {
        anyhow::bail!("clients and operations must be greater than zero");
    }
    if !matches!(
        args.mode.as_str(),
        "read" | "write" | "mixed" | "transaction" | "index"
    ) {
        anyhow::bail!("mode must be read, write, mixed, transaction, or index");
    }
    Ok(())
}

async fn connect(url: &str) -> anyhow::Result<Client> {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn report(
    args: &Args,
    started: Instant,
    tasks: Vec<tokio::task::JoinHandle<anyhow::Result<Vec<Duration>>>>,
) -> anyhow::Result<()> {
    let mut latencies = Vec::new();
    for task in tasks {
        latencies.extend(task.await??);
    }
    latencies.sort_unstable();
    let elapsed = started.elapsed();
    let total = latencies.len();
    println!(
        "backend=postgres mode={} clients={} operations_per_client={} value_size={} operations={} elapsed_ms={} ops_per_sec={:.0} p50_us={} p95_us={} p99_us={} p999_us={} max_us={}",
        args.mode,
        args.clients,
        args.operations,
        args.value_size,
        total,
        elapsed.as_millis(),
        total as f64 / elapsed.as_secs_f64(),
        percentile(&latencies, 500).as_micros(),
        percentile(&latencies, 950).as_micros(),
        percentile(&latencies, 990).as_micros(),
        percentile(&latencies, 999).as_micros(),
        latencies.last().copied().unwrap_or(Duration::ZERO).as_micros(),
    );
    Ok(())
}

fn percentile(values: &[Duration], permille: usize) -> Duration {
    if values.is_empty() {
        return Duration::ZERO;
    }
    values[((values.len() - 1) * permille / 1_000).min(values.len() - 1)]
}
