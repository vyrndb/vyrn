//! Write-back buffering must be invisible in every answer.
//!
//! The buffer changes WHERE a commit's mutations live — an in-memory map every
//! read merges over the tree, instead of a copy-on-write rewrite per commit —
//! and must change nothing about what any read returns, what survives a crash,
//! or what a snapshot sees. The model test drives a write-back engine and a
//! classic engine through the same pseudo-random workload and compares every
//! answer; the rest pin the specific seams: the WAL-only crash story, the
//! checkpoint hand-off, threshold flushes, and MVCC reads over buffered state.

use vyrn_core::{
    BatchOperation, DurabilityMode, Engine, EngineOptions, IndexUpdate, ReadEngine,
};

fn write_back_options(buffer: usize) -> EngineOptions {
    EngineOptions {
        durability: DurabilityMode::Durable,
        write_back_buffer: buffer,
        ..EngineOptions::default()
    }
}

/// A tiny deterministic generator so the model needs no new dependency.
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

/// Every answer a write-back engine gives must match a classic engine fed the
/// identical workload: point reads, range scans, lengths, revision-change
/// checks, and the change log. The key universe is small on purpose, so
/// overwrites and deletes constantly mask tree state behind buffered state,
/// and the buffer is small enough that several threshold flushes land mid-run
/// — the comparison therefore crosses the buffered/absorbed boundary many
/// times.
#[test]
fn a_write_back_engine_answers_identically_to_a_classic_engine() {
    let classic_dir = tempfile::tempdir().unwrap();
    let buffered_dir = tempfile::tempdir().unwrap();
    let mut classic = Engine::open(classic_dir.path()).unwrap();
    let mut buffered =
        Engine::open_with_options(buffered_dir.path(), write_back_options(16 * 1024)).unwrap();

    let key = |index: u64| format!("model/{:04}", index).into_bytes();
    let mut rng = Lcg(0x5eed_cafe_f00d_beef);
    for step in 0..600u64 {
        let operation = match rng.next() % 10 {
            0..=5 => BatchOperation::Put(
                key(rng.next() % 48),
                format!("value-{step}-{}", rng.next() % 1000).into_bytes(),
            ),
            6..=7 => BatchOperation::Delete(key(rng.next() % 48)),
            // A small batch, so multi-key commits and their change records are
            // exercised too.
            _ => {
                let operations = vec![
                    BatchOperation::Put(key(rng.next() % 48), b"batch-a".to_vec()),
                    BatchOperation::Delete(key(rng.next() % 48)),
                    BatchOperation::Put(key(rng.next() % 48), b"batch-b".to_vec()),
                ];
                let a = classic.write_batch(operations.clone()).unwrap();
                let b = buffered.write_batch(operations).unwrap();
                assert_eq!(a, b, "batch results diverged at step {step}");
                continue;
            }
        };
        let a = classic.write_batch(vec![operation.clone()]).unwrap();
        let b = buffered.write_batch(vec![operation]).unwrap();
        assert_eq!(a, b, "results diverged at step {step}");

        if step % 7 == 0 {
            let probe = key(rng.next() % 48);
            assert_eq!(
                classic.get(&probe).unwrap(),
                buffered.get(&probe).unwrap(),
                "get({}) diverged at step {step}",
                String::from_utf8_lossy(&probe)
            );
            // The zero-copy read must answer identically to the copying one,
            // on both engines, whatever mix of buffered and absorbed state
            // the key is in.
            for engine in [&classic, &buffered] {
                assert_eq!(
                    engine.get_shared(&probe).unwrap().map(|value| value.to_vec()),
                    engine.get(&probe).unwrap(),
                    "get_shared diverged from get at step {step}"
                );
            }
            assert_eq!(
                classic.changed_since(&probe, step / 2).unwrap(),
                buffered.changed_since(&probe, step / 2).unwrap(),
                "changed_since diverged at step {step}"
            );
        }
        if step % 13 == 0 {
            let start = key(rng.next() % 48);
            let limit = 1 + (rng.next() % 20) as usize;
            assert_eq!(
                classic.scan(Some(&start), None, limit).unwrap(),
                buffered.scan(Some(&start), None, limit).unwrap(),
                "scan diverged at step {step}"
            );
            // The visitor scan must see the same rows as the copying scan,
            // on both engines: classic exercises the borrowed-slice walk,
            // buffered exercises the merge fallback.
            for engine in [&classic, &buffered] {
                let mut visited = Vec::new();
                engine
                    .scan_each(Some(&start), None, limit, &mut |key, value| {
                        visited.push((key.to_vec(), value.to_vec()));
                    })
                    .unwrap();
                assert_eq!(
                    visited,
                    engine.scan(Some(&start), None, limit).unwrap(),
                    "scan_each diverged from scan at step {step}"
                );
            }
            // The zero-copy scan must return the same rows as the copying
            // one, on both engines, buffered and absorbed state alike.
            for engine in [&classic, &buffered] {
                assert_eq!(
                    engine
                        .scan_shared(Some(&start), None, limit)
                        .unwrap()
                        .into_iter()
                        .map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .collect::<Vec<_>>(),
                    engine.scan(Some(&start), None, limit).unwrap(),
                    "scan_shared diverged from scan at step {step}"
                );
            }
            assert_eq!(classic.len(), buffered.len(), "len diverged at step {step}");
        }
        if step % 97 == 0 {
            let from = vyrn_core::change_log::Cursor::start();
            assert_eq!(
                classic.read_changes(from, 50).unwrap(),
                buffered.read_changes(from, 50).unwrap(),
                "change log diverged at step {step}"
            );
        }
    }
    // The full final state, in one sweep each.
    assert_eq!(
        classic.scan(None, None, usize::MAX).unwrap(),
        buffered.scan(None, None, usize::MAX).unwrap(),
        "final state diverged"
    );
}

/// Kill-without-checkpoint is write-back's whole bet: the buffer dies with the
/// process and the WAL brings every commit back. The buffer is sized so part
/// of the workload was flushed into the tree and part was still buffered at
/// the drop, so reopen exercises both "already in the tree" and "replayed from
/// the log".
#[test]
fn buffered_commits_survive_reopen_through_the_wal_alone() {
    let directory = tempfile::tempdir().unwrap();
    {
        let mut engine =
            Engine::open_with_options(directory.path(), write_back_options(8 * 1024)).unwrap();
        for index in 0..200u32 {
            engine
                .put(
                    format!("crash/{index:04}").into_bytes(),
                    format!("value-{index}").into_bytes(),
                )
                .unwrap();
        }
        engine.delete(b"crash/0007").unwrap();
        // No checkpoint, no flush request: dropped with buffered state.
    }
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.len(), 199);
    assert_eq!(
        engine.get(b"crash/0199").unwrap().as_deref(),
        Some(&b"value-199"[..]),
        "the newest buffered commit must come back from the WAL"
    );
    assert_eq!(
        engine.get(b"crash/0007").unwrap(),
        None,
        "a buffered delete must come back from the WAL too"
    );
}

/// A checkpoint must absorb the buffer before it publishes its manifest,
/// because checkpoint cleanup deletes the WAL segments that were the buffered
/// commits' only other copy.
#[test]
fn a_checkpoint_absorbs_the_buffer_before_naming_its_manifest() {
    let directory = tempfile::tempdir().unwrap();
    {
        let mut engine =
            Engine::open_with_options(directory.path(), write_back_options(1024 * 1024)).unwrap();
        for index in 0..50u32 {
            engine
                .put(format!("cp/{index:04}").into_bytes(), vec![7u8; 64])
                .unwrap();
        }
        engine.checkpoint().unwrap();
        // More commits after the checkpoint, still buffered at drop.
        for index in 50..75u32 {
            engine
                .put(format!("cp/{index:04}").into_bytes(), vec![8u8; 64])
                .unwrap();
        }
    }
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.len(), 75);
    assert_eq!(
        engine.get(b"cp/0074").unwrap().as_deref(),
        Some(&[8u8; 64][..])
    );
    assert_eq!(
        engine.get(b"cp/0049").unwrap().as_deref(),
        Some(&[7u8; 64][..])
    );
}

/// A snapshot opened before buffered overwrites must keep reading the old
/// values: MVCC pre-images are captured from the merged state, so history
/// retention works identically over buffered and absorbed commits.
#[test]
fn snapshot_reads_see_pre_buffer_values() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open_with_options(directory.path(), write_back_options(1024 * 1024)).unwrap();
    engine.put(b"pinned".to_vec(), b"before".to_vec()).unwrap();
    let snapshot = engine.register_snapshot();
    engine.put(b"pinned".to_vec(), b"after".to_vec()).unwrap();
    engine.put(b"pinned".to_vec(), b"newest".to_vec()).unwrap();
    assert_eq!(
        engine.get_at(b"pinned", snapshot).unwrap().as_deref(),
        Some(&b"before"[..]),
        "the snapshot must read the value it pinned, not the buffered one"
    );
    assert_eq!(
        engine.get(b"pinned").unwrap().as_deref(),
        Some(&b"newest"[..])
    );
    engine.release_snapshot(snapshot);
}

/// A read handle fed the publish stream must answer exactly like a classic
/// read handle fed root refreshes — this is the server's whole contract.
///
/// The classic side is the server as it ships today: a `ReadEngine` whose only
/// signal is `refresh(committed_root())` after each commit. The write-back
/// side is the server with a buffer on: the same refresh, plus
/// `publish_write_back(take_write_back_publish())` under the same borrow —
/// precisely what `publish_commit` does per reader. The buffer is small enough
/// that many threshold absorbs land mid-run, so the comparison repeatedly
/// crosses buffered → absorbed → evicted, and a mid-run checkpoint exercises
/// the generation hand-off plus the checkpoint task's evict-by-watermark path.
#[test]
fn a_published_read_handle_answers_identically_to_a_classic_one() {
    let classic_dir = tempfile::tempdir().unwrap();
    let buffered_dir = tempfile::tempdir().unwrap();
    let mut classic = Engine::open(classic_dir.path()).unwrap();
    let mut buffered =
        Engine::open_with_options(buffered_dir.path(), write_back_options(4 * 1024)).unwrap();
    // What the server does after open: read handles are fed from this engine.
    buffered.enable_write_back_publish();
    let mut classic_reader = ReadEngine::open(classic_dir.path()).unwrap();
    let mut buffered_reader = ReadEngine::open_with_write_back(buffered_dir.path()).unwrap();

    // What the server's flush stage does for one reader, per durable commit.
    let publish = |engine: &mut Engine, reader: &mut ReadEngine| {
        let write_back = engine.take_write_back_publish();
        let (generation, root, len) = engine.committed_root();
        reader.refresh(generation, root, len).unwrap();
        reader.publish_write_back(&write_back).unwrap();
    };
    let refresh = |engine: &mut Engine, reader: &mut ReadEngine| {
        let (generation, root, len) = engine.committed_root();
        reader.refresh(generation, root, len).unwrap();
    };

    classic.create_index(b"wb-idx".to_vec(), false).unwrap();
    buffered.create_index(b"wb-idx".to_vec(), false).unwrap();
    refresh(&mut classic, &mut classic_reader);
    publish(&mut buffered, &mut buffered_reader);

    let key = |index: u64| format!("reader/{:04}", index).into_bytes();
    let bucket = |value: u64| format!("bucket-{}", value % 8).into_bytes();
    // `write_indexed` trusts the caller's old_value, so the test tracks each
    // key's current bucket the way a real caller would.
    let mut buckets: std::collections::HashMap<Vec<u8>, Vec<u8>> = Default::default();
    let mut rng = Lcg(0x0ddb_a110_fc0d_e001);
    for step in 0..500u64 {
        // The key this step commits, probed on both readers immediately after
        // the publish: read-your-write is the sharpest probe there is, and it
        // is what catches an eviction running ahead of the absorb watermark —
        // a loss the sampled probes below can miss while the window rotates.
        let touched: Vec<u8>;
        match rng.next() % 10 {
            0..=4 => {
                let (k, b) = (key(rng.next() % 40), bucket(rng.next()));
                touched = k.clone();
                let update = IndexUpdate {
                    index: b"wb-idx".to_vec(),
                    primary_key: k.clone(),
                    old_value: buckets.get(&k).cloned(),
                    new_value: Some(b.clone()),
                };
                let operations =
                    vec![BatchOperation::Put(k.clone(), format!("v{step}").into_bytes())];
                classic
                    .write_indexed(operations.clone(), vec![update.clone()])
                    .unwrap();
                buffered.write_indexed(operations, vec![update]).unwrap();
                buckets.insert(k, b);
            }
            5..=6 => {
                let k = key(rng.next() % 40);
                touched = k.clone();
                let update = buckets.remove(&k).map(|old| IndexUpdate {
                    index: b"wb-idx".to_vec(),
                    primary_key: k.clone(),
                    old_value: Some(old),
                    new_value: None,
                });
                let operations = vec![BatchOperation::Delete(k)];
                classic
                    .write_indexed(operations.clone(), update.clone().into_iter().collect())
                    .unwrap();
                buffered
                    .write_indexed(operations, update.into_iter().collect())
                    .unwrap();
            }
            _ => {
                let first = key(rng.next() % 40);
                touched = first.clone();
                let operations = vec![
                    BatchOperation::Put(first, b"plain-a".to_vec()),
                    BatchOperation::Put(key(rng.next() % 40), b"plain-b".to_vec()),
                ];
                // Plain batch puts leave any indexed bucket stale on both
                // sides equally; the model only requires the two to agree.
                classic.write_batch(operations.clone()).unwrap();
                buffered.write_batch(operations).unwrap();
            }
        }
        refresh(&mut classic, &mut classic_reader);
        publish(&mut buffered, &mut buffered_reader);
        assert_eq!(
            classic_reader.get(&touched).unwrap(),
            buffered_reader.get(&touched).unwrap(),
            "read-your-write diverged at step {step} on {}",
            String::from_utf8_lossy(&touched)
        );

        // The checkpoint task's half of the protocol, mid-run: absorb, bump
        // the generation, refresh, evict by watermark. One more commit lands
        // and reaches the reader BEFORE the checkpoint task's republish does —
        // the race the per-entry watermark exists for: its overlay entry is
        // newer than the watermark and must survive the eviction, or the
        // reader forgets an acknowledged commit its tree does not have yet.
        if step == 250 {
            classic.checkpoint().unwrap();
            buffered.checkpoint().unwrap();
            refresh(&mut classic, &mut classic_reader);
            let raced = b"reader/raced-past-checkpoint".to_vec();
            classic
                .write_batch(vec![BatchOperation::Put(raced.clone(), b"kept".to_vec())])
                .unwrap();
            buffered
                .write_batch(vec![BatchOperation::Put(raced.clone(), b"kept".to_vec())])
                .unwrap();
            refresh(&mut classic, &mut classic_reader);
            publish(&mut buffered, &mut buffered_reader);
            // Now the checkpoint task catches up, with its pre-race watermark.
            let (generation, root, len) = buffered.committed_root();
            buffered_reader.refresh(generation, root, len).unwrap();
            buffered_reader
                .evict_write_back_through(buffered.write_back_absorbed_through().unwrap());
            assert_eq!(
                buffered_reader.get(&raced).unwrap().as_deref(),
                Some(&b"kept"[..]),
                "a commit published after the checkpoint absorbed must survive \
                 the checkpoint task's eviction"
            );
        }

        if step % 5 == 0 {
            let probe = key(rng.next() % 40);
            assert_eq!(
                classic_reader.get(&probe).unwrap(),
                buffered_reader.get(&probe).unwrap(),
                "reader get({}) diverged at step {step}",
                String::from_utf8_lossy(&probe)
            );
        }
        if step % 11 == 0 {
            let start = key(rng.next() % 40);
            let limit = 1 + (rng.next() % 15) as usize;
            assert_eq!(
                classic_reader.scan(Some(&start), None, limit).unwrap(),
                buffered_reader.scan(Some(&start), None, limit).unwrap(),
                "reader scan diverged at step {step}"
            );
            assert_eq!(
                buffered_reader
                    .scan_shared(Some(&start), None, limit)
                    .unwrap()
                    .into_iter()
                    .map(|(key, value)| (key.to_vec(), value.to_vec()))
                    .collect::<Vec<_>>(),
                buffered_reader.scan(Some(&start), None, limit).unwrap(),
                "reader scan_shared diverged from scan at step {step}"
            );
        }
        if step % 17 == 0 {
            let value = bucket(rng.next());
            assert_eq!(
                classic_reader.lookup_index(b"wb-idx", &value, 100).unwrap(),
                buffered_reader
                    .lookup_index(b"wb-idx", &value, 100)
                    .unwrap(),
                "reader index lookup diverged at step {step}"
            );
        }
    }
    assert_eq!(
        classic_reader.scan(None, None, usize::MAX).unwrap(),
        buffered_reader.scan(None, None, usize::MAX).unwrap(),
        "final reader state diverged"
    );
}

/// `get_shared` must agree with `get` for every storage a value can live in:
/// inline in a leaf page, spilled to the value log below and above its
/// copy-versus-seek threshold, buffered in a write-back overlay, deleted,
/// and absent — on the engine and on a read handle alike.
#[test]
fn get_shared_agrees_with_get_everywhere_a_value_can_live() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open_with_options(directory.path(), write_back_options(1024 * 1024)).unwrap();
    engine.enable_write_back_publish();
    let mut reader = ReadEngine::open_with_write_back(directory.path()).unwrap();
    let sizes = [16usize, 1024, 1025, 4096, 40 * 1024, 200 * 1024];
    for (index, size) in sizes.iter().enumerate() {
        let value: Vec<u8> = (0..*size).map(|byte| (byte + index) as u8).collect();
        engine
            .put(format!("shared/{index}").into_bytes(), value)
            .unwrap();
    }
    engine.delete(b"shared/1").unwrap();
    let publish = engine.take_write_back_publish();
    let (generation, root, len) = engine.committed_root();
    reader.refresh(generation, root, len).unwrap();
    reader.publish_write_back(&publish).unwrap();
    // Buffered state first, then the same keys after the tree absorbs them.
    for pass in ["buffered", "absorbed"] {
        for index in 0..sizes.len() {
            let key = format!("shared/{index}").into_bytes();
            let expected = engine.get(&key).unwrap();
            assert_eq!(
                engine.get_shared(&key).unwrap().map(|value| value.to_vec()),
                expected,
                "engine get_shared diverged ({pass}, key {index})"
            );
            assert_eq!(
                reader.get_shared(&key).unwrap().map(|value| value.to_vec()),
                reader.get(&key).unwrap(),
                "reader get_shared diverged ({pass}, key {index})"
            );
        }
        assert!(engine.get_shared(b"shared/none").unwrap().is_none());
        if pass == "buffered" {
            engine.checkpoint().unwrap();
            let (generation, root, len) = engine.committed_root();
            reader.refresh(generation, root, len).unwrap();
            reader.evict_write_back_through(engine.write_back_absorbed_through().unwrap());
        }
    }
}

/// Feeding a write-back commit to a handle opened without write-back replay is
/// a wiring bug, and it must be refused rather than absorbed silently: a
/// handle that drops mutations serves a tree that lags the log forever.
#[test]
fn publishing_to_a_plain_read_handle_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open_with_options(directory.path(), write_back_options(1024 * 1024)).unwrap();
    engine.enable_write_back_publish();
    let mut reader = ReadEngine::open(directory.path()).unwrap();
    engine.put(b"wired-wrong".to_vec(), b"value".to_vec()).unwrap();
    let publish = engine.take_write_back_publish();
    assert!(
        matches!(
            reader.publish_write_back(&publish),
            Err(vyrn_core::Error::WriteBackMismatch { .. })
        ),
        "a plain handle must refuse a write-back publication"
    );
}

/// Dropping an index must delete the entries the buffer holds, not only the
/// absorbed ones. Before the merged-scan fix in `drop_index`, an entry written
/// and still buffered at drop time survived the drop invisibly, and a later
/// index of the same name resurrected it as a stale lookup answer — first
/// straight from the buffer, then permanently once a flush absorbed it.
#[test]
fn dropping_an_index_deletes_buffered_entries_too() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open_with_options(directory.path(), write_back_options(1024 * 1024)).unwrap();
    engine.create_index(b"reborn".to_vec(), false).unwrap();
    engine
        .write_indexed(
            vec![BatchOperation::Put(b"victim".to_vec(), b"row".to_vec())],
            vec![IndexUpdate {
                index: b"reborn".to_vec(),
                primary_key: b"victim".to_vec(),
                old_value: None,
                new_value: Some(b"stale".to_vec()),
            }],
        )
        .unwrap();
    // The entry is still buffered — the buffer is far under its threshold.
    engine.drop_index(b"reborn").unwrap();
    engine.create_index(b"reborn".to_vec(), false).unwrap();
    assert_eq!(
        engine.lookup_index(b"reborn", b"stale", 10).unwrap(),
        Vec::<Vec<u8>>::new(),
        "a recreated index must not resurrect entries buffered at drop time"
    );
    // And not after the tree absorbs the buffer either.
    engine.checkpoint().unwrap();
    assert_eq!(
        engine.lookup_index(b"reborn", b"stale", 10).unwrap(),
        Vec::<Vec<u8>>::new(),
        "absorption must not resurrect entries the drop should have deleted"
    );
}

/// The threshold flush must actually run — and reads must not change across
/// it. A tiny buffer forces a flush every few commits; if the flush stopped
/// firing, the buffer would grow without bound and this test's page count
/// would stay at its starting value.
#[test]
fn threshold_flushes_absorb_the_buffer_without_changing_answers() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open_with_options(directory.path(), write_back_options(2 * 1024)).unwrap();
    let pages_before = engine.stats().unwrap().pages;
    for index in 0..300u32 {
        engine
            .put(
                format!("flush/{index:04}").into_bytes(),
                format!("value-{index}").into_bytes(),
            )
            .unwrap();
    }
    assert!(
        engine.stats().unwrap().pages > pages_before,
        "a 2 KiB buffer over 300 commits must have flushed into the tree"
    );
    for index in (0..300u32).step_by(37) {
        assert_eq!(
            engine
                .get(format!("flush/{index:04}").as_bytes())
                .unwrap()
                .as_deref(),
            Some(format!("value-{index}").as_bytes()),
            "key {index} must read identically whether buffered or absorbed"
        );
    }
}
