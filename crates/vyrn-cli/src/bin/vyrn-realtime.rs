use clap::Parser;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use vyrn_client::Client;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "VYRN_URL")]
    url: String,
    #[arg(long, env = "VYRN_TLS_CA_FILE")]
    ca: Option<PathBuf>,
    #[arg(long, default_value_t = 1_000)]
    operations: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let subscriber = Client::connect_with_ca(&args.url, args.ca.as_deref()).await?;
    let mut subscription = subscriber.subscribe(b"realtime/".to_vec()).await?;
    let mut writer = Client::connect_with_ca(&args.url, args.ca.as_deref()).await?;
    let mut latencies = Vec::with_capacity(args.operations);
    for index in 0..args.operations {
        let key = format!("realtime/{index:012}").into_bytes();
        let started = Instant::now();
        writer.put(key.clone(), vec![7; 64]).await?;
        let change = subscription
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("subscription closed"))?;
        if change.key != key || change.value.as_deref() != Some(&[7; 64]) {
            anyhow::bail!("subscription delivered the wrong change");
        }
        latencies.push(started.elapsed());
    }
    latencies.sort_unstable();
    println!(
        "events={} p50_us={} p95_us={} p99_us={} max_us={}",
        latencies.len(),
        percentile(&latencies, 50).as_micros(),
        percentile(&latencies, 95).as_micros(),
        percentile(&latencies, 99).as_micros(),
        latencies
            .last()
            .copied()
            .unwrap_or(Duration::ZERO)
            .as_micros(),
    );
    Ok(())
}

fn percentile(values: &[Duration], percentile: usize) -> Duration {
    values[((values.len() - 1) * percentile / 100).min(values.len() - 1)]
}
