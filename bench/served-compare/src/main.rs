//! vyrnd vs single-node ScyllaDB, served, same box, same semantics.
//!
//! Durability is the axis served benchmarks quietly cheat on, exactly as the
//! embedded harness found with sled: **Scylla's default `commitlog_sync` is
//! `periodic` at 10 seconds** — an acknowledged write can be lost to a power
//! cut for up to that window. The honest durable comparison runs Scylla with
//! `--commitlog-sync batch` (its group commit, against vyrn's), and this
//! harness REFUSES the durable workloads unless the Scylla node reports
//! batch mode — a number nobody can quote by accident.
//!
//! Latency is reported as p50/p99 per operation alongside throughput:
//! aggregate ops/s across many clients is the number marketing quotes, and
//! per-op latency is the number applications feel.
//!
//! Usage (see bench/served-compare/README.md for the full runbook):
//!   served-compare vyrn  'vyrn://user:pass@127.0.0.1:7432/default?tls=disable' <clients>
//!   served-compare scylla 127.0.0.1:9042 <clients> [--allow-periodic]

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PREFILL_KEYS: u64 = 100_000;
const READ_OPS: u64 = 200_000;
const WRITE_OPS: u64 = 20_000;
const MIXED_OPS: u64 = 100_000;
const VALUE_LEN: usize = 128;

fn key(index: u64) -> Vec<u8> {
    format!("bench/{index:012}").into_bytes()
}

fn value() -> Vec<u8> {
    vec![7u8; VALUE_LEN]
}

/// Deterministic per-task generator, seeded by task id so tasks do not
/// collide on a shared atomic and access patterns are reproducible.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

struct Outcome {
    name: &'static str,
    operations: u64,
    elapsed: Duration,
    latencies_us: Vec<u64>,
}

impl Outcome {
    fn report(mut self) {
        self.latencies_us.sort_unstable();
        let percentile = |p: f64| -> u64 {
            if self.latencies_us.is_empty() {
                return 0;
            }
            let index = ((self.latencies_us.len() as f64 - 1.0) * p) as usize;
            self.latencies_us[index]
        };
        println!(
            "{:<18} {:>12.0} ops/s   p50 {:>7} us   p99 {:>7} us",
            self.name,
            self.operations as f64 / self.elapsed.as_secs_f64(),
            percentile(0.50),
            percentile(0.99),
        );
    }
}

/// One backend: everything a workload needs, boxed per client task.
#[async_trait::async_trait]
trait Backend: Send + Sync + 'static {
    async fn client(&self) -> Result<Box<dyn BackendClient>>;
}

#[async_trait::async_trait]
trait BackendClient: Send {
    async fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
    async fn get(&mut self, key: Vec<u8>) -> Result<Option<Vec<u8>>>;
}

// --- vyrn -------------------------------------------------------------------

struct Vyrn {
    url: String,
}

#[async_trait::async_trait]
impl Backend for Vyrn {
    async fn client(&self) -> Result<Box<dyn BackendClient>> {
        Ok(Box::new(VyrnClient {
            inner: vyrn_client::Client::connect(&self.url)
                .await
                .context("connect to vyrnd")?,
        }))
    }
}

struct VyrnClient {
    inner: vyrn_client::Client,
}

#[async_trait::async_trait]
impl BackendClient for VyrnClient {
    async fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        Ok(self.inner.put(key, value).await?)
    }
    async fn get(&mut self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.get(key).await?)
    }
}

// --- scylla -----------------------------------------------------------------

struct Scylla {
    session: Arc<scylla::client::session::Session>,
    put: scylla::statement::prepared::PreparedStatement,
    get: scylla::statement::prepared::PreparedStatement,
}

impl Scylla {
    async fn connect(node: &str, allow_periodic: bool) -> Result<Self> {
        let session = scylla::client::session_builder::SessionBuilder::new()
            .known_node(node)
            .build()
            .await
            .context("connect to scylla")?;
        /* THE FAIRNESS GATE. Periodic commitlog sync means acknowledged
         * writes can be lost for up to the sync window; comparing that
         * against vyrn's per-op durability is the sled-async mistake with a
         * different logo. Refused unless explicitly waived (for read-only
         * or latency-only investigations). */
        let sync_mode: String = session
            .query_unpaged(
                "SELECT value FROM system.config WHERE name = 'commitlog_sync'",
                (),
            )
            .await
            .ok()
            .and_then(|result| result.into_rows_result().ok())
            .and_then(|rows| rows.single_row::<(String,)>().ok())
            .map(|(mode,)| mode)
            .unwrap_or_else(|| "unknown".to_owned());
        if sync_mode.trim_matches('"') != "batch" && !allow_periodic {
            bail!(
                "scylla reports commitlog_sync={sync_mode}; the durable comparison requires \
                 'batch' (start scylla with --commitlog-sync batch), or pass --allow-periodic \
                 to knowingly measure the non-durable configuration"
            );
        }
        session
            .query_unpaged(
                "CREATE KEYSPACE IF NOT EXISTS bench WITH replication = \
                 {'class': 'NetworkTopologyStrategy', 'replication_factor': 1}",
                (),
            )
            .await?;
        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS bench.kv (k blob PRIMARY KEY, v blob)",
                (),
            )
            .await?;
        let put = session
            .prepare("INSERT INTO bench.kv (k, v) VALUES (?, ?)")
            .await?;
        let get = session.prepare("SELECT v FROM bench.kv WHERE k = ?").await?;
        Ok(Self {
            session: Arc::new(session),
            put,
            get,
        })
    }
}

#[async_trait::async_trait]
impl Backend for Scylla {
    async fn client(&self) -> Result<Box<dyn BackendClient>> {
        // The driver is internally shard-aware and pooled; tasks share it,
        // which is the driver's own recommended concurrency model.
        Ok(Box::new(ScyllaClient {
            session: Arc::clone(&self.session),
            put: self.put.clone(),
            get: self.get.clone(),
        }))
    }
}

struct ScyllaClient {
    session: Arc<scylla::client::session::Session>,
    put: scylla::statement::prepared::PreparedStatement,
    get: scylla::statement::prepared::PreparedStatement,
}

#[async_trait::async_trait]
impl BackendClient for ScyllaClient {
    async fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.session.execute_unpaged(&self.put, (key, value)).await?;
        Ok(())
    }
    async fn get(&mut self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let result = self
            .session
            .execute_unpaged(&self.get, (key,))
            .await?
            .into_rows_result()?;
        Ok(result
            .maybe_first_row::<(Vec<u8>,)>()?
            .map(|(value,)| value))
    }
}

// --- workloads ---------------------------------------------------------------

async fn run_workload<F>(
    name: &'static str,
    backend: &dyn Backend,
    clients: usize,
    total_ops: u64,
    op: F,
) -> Result<Outcome>
where
    F: Fn(u64, &mut Lcg) -> Op + Send + Sync + Copy + 'static,
{
    let per_client = total_ops / clients as u64;
    // Every client exists BEFORE the clock starts: connection setup includes
    // an Argon2 handshake on the vyrn side and a free handle clone on the
    // Scylla side, so timing it both serialized the vyrn setup and billed it
    // to the workload — understating vyrn at high client counts.
    let mut ready = Vec::new();
    for _ in 0..clients {
        ready.push(backend.client().await?);
    }
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (client_index, mut client) in ready.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            let mut rng = Lcg(0xbeef ^ (client_index as u64) << 17);
            let mut latencies = Vec::with_capacity(per_client as usize);
            for op_index in 0..per_client {
                let one = Instant::now();
                match op(client_index as u64 * per_client + op_index, &mut rng) {
                    Op::Put(key, value) => client.put(key, value).await?,
                    Op::Get(key) => {
                        client.get(key).await?;
                    }
                }
                latencies.push(one.elapsed().as_micros() as u64);
            }
            Ok::<Vec<u64>, anyhow::Error>(latencies)
        }));
    }
    let mut latencies_us = Vec::with_capacity(total_ops as usize);
    for task in tasks {
        latencies_us.extend(task.await??);
    }
    Ok(Outcome {
        name,
        operations: per_client * clients as u64,
        elapsed: started.elapsed(),
        latencies_us,
    })
}

enum Op {
    Put(Vec<u8>, Vec<u8>),
    Get(Vec<u8>),
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    let (which, target, clients) = match arguments.as_slice() {
        [_, which, target, clients, ..] => (
            which.clone(),
            target.clone(),
            clients.parse::<usize>().context("clients must be a number")?,
        ),
        _ => bail!(
            "usage: served-compare <vyrn|scylla> <url|node> <clients> [--allow-periodic]"
        ),
    };
    let allow_periodic = arguments.iter().any(|a| a == "--allow-periodic");

    let backend: Box<dyn Backend> = match which.as_str() {
        "vyrn" => Box::new(Vyrn { url: target }),
        "scylla" => Box::new(Scylla::connect(&target, allow_periodic).await?),
        other => bail!("unknown backend {other:?}"),
    };
    let backend: &'static dyn Backend = Box::leak(backend);

    println!("backend={which} clients={clients}");

    // Prefill, concurrently, then a warm pass shape identical for both sides.
    run_workload("prefill", backend, clients, PREFILL_KEYS, |index, _| {
        Op::Put(key(index), value())
    })
    .await?
    .report();

    run_workload("point_get", backend, clients, READ_OPS, |_, rng| {
        Op::Get(key(rng.next() % PREFILL_KEYS))
    })
    .await?
    .report();

    run_workload("durable_put", backend, clients, WRITE_OPS, |index, _| {
        Op::Put(key(PREFILL_KEYS + index), value())
    })
    .await?
    .report();

    run_workload("mixed_70_30", backend, clients, MIXED_OPS, |_, rng| {
        if rng.next() % 10 < 7 {
            Op::Get(key(rng.next() % PREFILL_KEYS))
        } else {
            Op::Put(key(rng.next() % PREFILL_KEYS), value())
        }
    })
    .await?
    .report();

    Ok(())
}
