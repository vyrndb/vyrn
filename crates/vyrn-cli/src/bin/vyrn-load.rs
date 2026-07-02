use clap::Parser;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use vyrn_client::Client;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "VYRN_URL")]
    url: String,
    #[arg(long, env = "VYRN_TLS_CA_FILE")]
    ca: Option<std::path::PathBuf>,
    #[arg(long, default_value_t = 8)]
    clients: usize,
    #[arg(long, default_value_t = 1_000)]
    operations: usize,
    #[arg(long, default_value_t = 128)]
    value_size: usize,
    #[arg(long, default_value = "mixed")]
    mode: String,
    #[arg(long, default_value_t = 32)]
    batch_size: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());
    validate(&args)?;
    prepare(&args).await?;

    let mut clients = Vec::with_capacity(args.clients);
    for _ in 0..args.clients {
        clients.push(Client::connect_with_ca(&args.url, args.ca.as_deref()).await?);
    }

    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.clients);
    for (client_id, mut client) in clients.into_iter().enumerate() {
        let args = Arc::clone(&args);
        tasks.push(tokio::spawn(async move {
            let value = vec![7; args.value_size];
            let mut latencies = Vec::with_capacity(args.operations);
            for operation in 0..args.operations {
                let key = format!("load/{client_id:04}/{operation:012}").into_bytes();
                let begin = Instant::now();
                match args.mode.as_str() {
                    "write" => client.put(key, value.clone()).await?,
                    "read" => {
                        let _ = client.get(b"load/hot".to_vec()).await?;
                    }
                    "multi-read" => {
                        let _ = client
                            .multi_get(vec![b"load/hot".to_vec(); args.batch_size])
                            .await?;
                    }
                    "mixed" if operation % 10 < 3 => client.put(key, value.clone()).await?,
                    "mixed" => {
                        let _ = client.get(b"load/hot".to_vec()).await?;
                    }
                    "transaction" => {
                        let mut transaction = client.transaction().await?;
                        for item in 0..4 {
                            transaction
                                .put(
                                    format!("load/{client_id:04}/{operation:012}/{item}")
                                        .into_bytes(),
                                    value.clone(),
                                )
                                .await?;
                        }
                        transaction.commit().await?;
                    }
                    "index" => {
                        let _ = client
                            .lookup_index(b"load-index".to_vec(), b"hot".to_vec(), Some(10))
                            .await?;
                    }
                    _ => unreachable!(),
                }
                latencies.push(begin.elapsed());
            }
            Ok::<_, anyhow::Error>(latencies)
        }));
    }

    report("vyrn", &args, started, tasks).await
}

fn validate(args: &Args) -> anyhow::Result<()> {
    if args.clients == 0 || args.operations == 0 || args.batch_size == 0 {
        anyhow::bail!("clients, operations, and batch size must be greater than zero");
    }
    if !matches!(
        args.mode.as_str(),
        "read" | "multi-read" | "write" | "mixed" | "transaction" | "index"
    ) {
        anyhow::bail!("mode must be read, multi-read, write, mixed, transaction, or index");
    }
    Ok(())
}

async fn prepare(args: &Args) -> anyhow::Result<()> {
    let mut client = Client::connect_with_ca(&args.url, args.ca.as_deref()).await?;
    client
        .put(b"load/hot".to_vec(), vec![7; args.value_size])
        .await?;
    if args.mode == "index" {
        let _ = client.drop_index(b"load-index".to_vec()).await;
        client.create_index(b"load-index".to_vec(), false).await?;
        let mut transaction = client.transaction().await?;
        transaction
            .put(b"load/indexed".to_vec(), vec![7; args.value_size])
            .await?;
        transaction
            .update_index(
                b"load-index".to_vec(),
                b"load/indexed".to_vec(),
                None,
                Some(b"hot".to_vec()),
            )
            .await?;
        transaction.commit().await?;
    }
    Ok(())
}

async fn report(
    backend: &str,
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
    let logical_operations = if args.mode == "multi-read" {
        total * args.batch_size
    } else {
        total
    };
    println!(
        "backend={backend} mode={} clients={} operations_per_client={} value_size={} requests={} logical_operations={} elapsed_ms={} requests_per_sec={:.0} logical_ops_per_sec={:.0} p50_us={} p95_us={} p99_us={} p999_us={} max_us={}",
        args.mode,
        args.clients,
        args.operations,
        args.value_size,
        total,
        logical_operations,
        elapsed.as_millis(),
        total as f64 / elapsed.as_secs_f64(),
        logical_operations as f64 / elapsed.as_secs_f64(),
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
