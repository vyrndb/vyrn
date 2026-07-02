use clap::Parser;
use std::{path::PathBuf, time::Instant};
use vyrn_client::Client;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "VYRN_URL")]
    url: String,
    #[arg(long, env = "VYRN_TLS_CA_FILE")]
    ca: Option<PathBuf>,
    #[arg(long)]
    prefix: String,
    #[arg(long, default_value_t = 1)]
    count: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = Client::connect_with_ca(&args.url, args.ca.as_deref()).await?;
    let mut subscription = client.subscribe(args.prefix.into_bytes()).await?;
    println!("subscribed");
    for _ in 0..args.count {
        let started = Instant::now();
        let change = subscription
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("subscription closed"))?;
        println!(
            "change sequence={} key={} value_len={} receive_us={}",
            change.sequence,
            String::from_utf8_lossy(&change.key),
            change.value.as_ref().map_or(0, Vec::len),
            started.elapsed().as_micros()
        );
    }
    Ok(())
}
