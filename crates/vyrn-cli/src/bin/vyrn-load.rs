use clap::Parser;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use vyrn_client::{Client, PipelineOperation};

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
    /// Distinct keys the random/zipf/overwrite modes address.
    ///
    /// This is the number that decides whether the run measures a database or
    /// a cache. The legacy `read`/`mixed` modes hit ONE key forever, so they
    /// answer from the row cache and never descend the tree. Size this so
    /// `keyspace * value_size` comfortably exceeds the server's page + value
    /// cache budget, or the result is the same flattering number with more
    /// steps.
    #[arg(long, default_value_t = 10_000_000)]
    keyspace: u64,
    /// Zipf skew for the `zipf-*` modes. 0 is uniform; ~0.99 is the YCSB
    /// default and produces a realistic hot/cold split.
    #[arg(long, default_value_t = 0.99)]
    zipf_theta: f64,
    /// Seed for the per-client generators, so a run is reproducible.
    #[arg(long, default_value_t = 0x5EED_1234_ABCD_0001)]
    seed: u64,
    /// Skip the prefill pass (the keyspace is already populated).
    #[arg(long, default_value_t = false)]
    skip_prefill: bool,
    /// Concurrent connections used by the prefill pass.
    #[arg(long, default_value_t = 16)]
    prefill_clients: usize,
}

/// The ONE key builder. `prepare` and the worker loop both go through this so
/// the two can never drift apart — they used to generate keys independently,
/// which is how the read modes ended up addressing a key the prefill never
/// wrote.
fn key_at(index: u64) -> Vec<u8> {
    format!("load/{index:012}").into_bytes()
}

/// Deterministic per-client generator (SplitMix64), seeded by `seed ^ client_id`.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        // 53 significant bits, the same construction as rand's Open01.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Zipf sampler over `[0, n)`.
///
/// Rejection-inversion (Hörmann & Derflinger), which needs no precomputed
/// table — a 10M-entry CDF would cost more memory than the values under test.
struct Zipf {
    n: f64,
    theta: f64,
    h_integral_x1: f64,
    h_integral_n: f64,
    s: f64,
}

impl Zipf {
    fn new(n: u64, theta: f64) -> Self {
        let n = n as f64;
        let mut zipf = Self {
            n,
            theta,
            h_integral_x1: 0.0,
            h_integral_n: 0.0,
            s: 0.0,
        };
        zipf.h_integral_x1 = zipf.h_integral(1.5) - 1.0;
        zipf.h_integral_n = zipf.h_integral(n + 0.5);
        zipf.s = 2.0 - zipf.h_integral_inverse(zipf.h_integral(2.5) - zipf.h(2.0));
        zipf
    }

    fn h(&self, x: f64) -> f64 {
        (-self.theta * x.ln()).exp()
    }

    fn h_integral(&self, x: f64) -> f64 {
        let log_x = x.ln();
        helper2((1.0 - self.theta) * log_x) * log_x
    }

    fn h_integral_inverse(&self, x: f64) -> f64 {
        let mut t = x * (1.0 - self.theta);
        if t < -1.0 {
            t = -1.0;
        }
        (helper1(t) * x).exp()
    }

    /// Returns a 0-based index; the caller maps it onto the keyspace.
    fn sample(&self, rng: &mut Rng) -> u64 {
        if self.theta <= 0.0 {
            return rng.next_u64() % (self.n as u64);
        }
        loop {
            let u = self.h_integral_n + rng.next_f64() * (self.h_integral_x1 - self.h_integral_n);
            let x = self.h_integral_inverse(u);
            let mut k = (x + 0.5) as u64;
            if k < 1 {
                k = 1;
            } else if (k as f64) > self.n {
                k = self.n as u64;
            }
            let kf = k as f64;
            if kf - x <= self.s || u >= self.h_integral(kf + 0.5) - self.h(kf) {
                return k - 1;
            }
        }
    }
}

/// `(exp(x) - 1) / x`, accurate near zero.
fn helper1(x: f64) -> f64 {
    if x.abs() > 1e-8 {
        x.ln_1p() / x
    } else {
        1.0 - x * (0.5 - x * (1.0 / 3.0 - 0.25 * x))
    }
}

/// `log(1 + x) / x`, accurate near zero.
fn helper2(x: f64) -> f64 {
    if x.abs() > 1e-8 {
        (x.exp() - 1.0) / x
    } else {
        1.0 + x * 0.5 * (1.0 + x * (1.0 / 3.0) * (1.0 + 0.25 * x))
    }
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
            let mut rng = Rng::new(args.seed ^ (client_id as u64));
            let zipf = Zipf::new(args.keyspace, args.zipf_theta);
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
                    // ── keyspace-addressing modes ───────────────────────────
                    "random-read" => {
                        let index = rng.next_u64() % args.keyspace;
                        let _ = client.get(key_at(index)).await?;
                    }
                    "zipf-read" => {
                        let index = zipf.sample(&mut rng);
                        let _ = client.get(key_at(index)).await?;
                    }
                    "overwrite" => {
                        let index = rng.next_u64() % args.keyspace;
                        client.put(key_at(index), value.clone()).await?;
                    }
                    "zipf-overwrite" => {
                        let index = zipf.sample(&mut rng);
                        client.put(key_at(index), value.clone()).await?;
                    }
                    "zipf-mixed" if operation % 10 < 3 => {
                        let index = zipf.sample(&mut rng);
                        client.put(key_at(index), value.clone()).await?;
                    }
                    "zipf-mixed" => {
                        let index = zipf.sample(&mut rng);
                        let _ = client.get(key_at(index)).await?;
                    }
                    "random-multi-read" => {
                        let keys = (0..args.batch_size)
                            .map(|_| key_at(rng.next_u64() % args.keyspace))
                            .collect();
                        let _ = client.multi_get(keys).await?;
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

/// Modes that address `--keyspace` and therefore need it populated first.
fn needs_keyspace(mode: &str) -> bool {
    matches!(
        mode,
        "random-read"
            | "zipf-read"
            | "overwrite"
            | "zipf-overwrite"
            | "zipf-mixed"
            | "random-multi-read"
    )
}

fn validate(args: &Args) -> anyhow::Result<()> {
    if args.clients == 0 || args.operations == 0 || args.batch_size == 0 {
        anyhow::bail!("clients, operations, and batch size must be greater than zero");
    }
    if !matches!(
        args.mode.as_str(),
        "read"
            | "multi-read"
            | "write"
            | "mixed"
            | "transaction"
            | "index"
            | "random-read"
            | "zipf-read"
            | "overwrite"
            | "zipf-overwrite"
            | "zipf-mixed"
            | "random-multi-read"
    ) {
        anyhow::bail!(
            "mode must be one of: read, multi-read, write, mixed, transaction, index, \
             random-read, zipf-read, overwrite, zipf-overwrite, zipf-mixed, random-multi-read"
        );
    }
    if needs_keyspace(&args.mode) {
        if args.keyspace == 0 {
            anyhow::bail!(
                "--keyspace must be greater than zero for mode {}",
                args.mode
            );
        }
        if args.prefill_clients == 0 {
            anyhow::bail!("--prefill-clients must be greater than zero");
        }
        if args.zipf_theta < 0.0 || args.zipf_theta >= 1.0 {
            anyhow::bail!("--zipf-theta must be in [0, 1)");
        }
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
    if needs_keyspace(&args.mode) && !args.skip_prefill {
        prefill(args).await?;
    }
    Ok(())
}

/// Populate `[0, keyspace)` before the clock starts.
///
/// Runs outside the measured window on purpose: this is fixture cost, and the
/// modes that need it are exactly the ones whose numbers are meaningless if a
/// read can miss. Writes go out through `pipeline()` so a prefill of millions
/// of keys is bounded by the server's batch path rather than by round trips.
async fn prefill(args: &Args) -> anyhow::Result<()> {
    let started = Instant::now();
    let value = vec![7u8; args.value_size];
    let per_client = args.keyspace.div_ceil(args.prefill_clients as u64);

    let mut tasks = Vec::with_capacity(args.prefill_clients);
    for worker in 0..args.prefill_clients {
        let begin = worker as u64 * per_client;
        let end = (begin + per_client).min(args.keyspace);
        if begin >= end {
            continue;
        }
        let url = args.url.clone();
        let ca = args.ca.clone();
        let value = value.clone();
        let batch = args.batch_size.max(1);
        tasks.push(tokio::spawn(async move {
            let mut client = Client::connect_with_ca(&url, ca.as_deref()).await?;
            let mut index = begin;
            while index < end {
                let stop = (index + batch as u64).min(end);
                let operations = (index..stop)
                    .map(|i| PipelineOperation::Put(key_at(i), value.clone()))
                    .collect::<Vec<_>>();
                for outcome in client.pipeline(operations).await? {
                    outcome?;
                }
                index = stop;
            }
            Ok::<_, anyhow::Error>(())
        }));
    }
    for task in tasks {
        task.await??;
    }

    eprintln!(
        "prefill: {} keys x {} B in {:.1}s ({} clients)",
        args.keyspace,
        args.value_size,
        started.elapsed().as_secs_f64(),
        args.prefill_clients,
    );
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
    let logical_operations = if args.mode == "multi-read" || args.mode == "random-multi-read" {
        total * args.batch_size
    } else {
        total
    };
    println!(
        "backend={backend} mode={} clients={} operations_per_client={} value_size={} keyspace={} zipf_theta={} seed={} requests={} logical_operations={} elapsed_ms={} requests_per_sec={:.0} logical_ops_per_sec={:.0} p50_us={} p95_us={} p99_us={} p999_us={} max_us={}",
        args.mode,
        args.clients,
        args.operations,
        args.value_size,
        if needs_keyspace(&args.mode) {
            args.keyspace
        } else {
            1
        },
        if args.mode.starts_with("zipf") {
            args.zipf_theta
        } else {
            0.0
        },
        args.seed,
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
