use std::time::Instant;
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine, IndexUpdate};

fn seed_index(engine: &mut Engine) {
    engine.create_index(b"email".to_vec(), false).unwrap();
    engine
        .write_indexed(
            vec![BatchOperation::Put(b"aaa/row".to_vec(), b"v".to_vec())],
            vec![IndexUpdate {
                index: b"email".to_vec(),
                primary_key: b"aaa/row".to_vec(),
                old_value: None,
                new_value: Some(b"hot".to_vec()),
            }],
        )
        .unwrap();
}

fn time_lookups(engine: &Engine, rounds: usize) -> std::time::Duration {
    let started = Instant::now();
    for _ in 0..rounds {
        let found = engine.lookup_index(b"email", b"hot", 10).unwrap();
        assert_eq!(found.len(), 1);
    }
    started.elapsed()
}

/// A bounded prefix scan must not get slower as unrelated keys accumulate
/// elsewhere in the keyspace.
#[test]
fn prefix_scan_cost_does_not_grow_with_unrelated_keys() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    seed_index(&mut engine);

    let baseline = time_lookups(&engine, 200);

    for batch in 0..40 {
        let operations = (0..100)
            .map(|index| {
                BatchOperation::Put(
                    format!("zzz/{batch:04}/{index:04}").into_bytes(),
                    vec![7; 64],
                )
            })
            .collect();
        engine.write_batch(operations).unwrap();
    }

    let loaded = time_lookups(&engine, 200);
    assert!(
        loaded.as_secs_f64() < baseline.as_secs_f64() * 8.0 + 0.05,
        "prefix scan degraded with unrelated keys: baseline {baseline:?} vs {loaded:?}"
    );
}

/// Reproduces the benchmark ordering: the write mode commits many single-key
/// batches, and index lookups afterwards collapsed from ~42k/s to ~24/s.
#[test]
fn index_lookup_survives_many_individual_commits() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    seed_index(&mut engine);

    let baseline = time_lookups(&engine, 100);

    // One commit per write, as the load generator does.
    for index in 0..3_000 {
        engine
            .put(format!("load/{index:012}").into_bytes(), vec![7; 128])
            .unwrap();
    }

    let loaded = time_lookups(&engine, 100);
    let ratio = loaded.as_secs_f64() / baseline.as_secs_f64().max(1e-9);
    println!("baseline={baseline:?} loaded={loaded:?} ratio={ratio:.1}x");
    assert!(
        loaded.as_secs_f64() < baseline.as_secs_f64() * 10.0 + 0.05,
        "index lookup degraded {ratio:.1}x after individual commits: {baseline:?} -> {loaded:?}"
    );
}
