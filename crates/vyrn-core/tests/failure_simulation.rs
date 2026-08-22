use proptest::prelude::*;
use std::collections::BTreeMap;
use tempfile::tempdir;
use vyrn_core::{
    BatchOperation, DurabilityMode, Engine, EngineOptions, Error, FailureInjector, FailurePoint,
    IndexUpdate,
};

const COMMIT_POINTS: [FailurePoint; 4] = [
    FailurePoint::BeforePageSync,
    FailurePoint::AfterPageSync,
    FailurePoint::AfterWalWrite,
    FailurePoint::BeforeWalSync,
];

#[test]
fn every_commit_failure_recovers_pre_or_post_transaction_with_indexes() {
    for point in COMMIT_POINTS {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.create_index(b"email".to_vec(), true).unwrap();
            engine
                .write_indexed(
                    vec![BatchOperation::Put(b"user/1".to_vec(), b"old".to_vec())],
                    vec![IndexUpdate {
                        index: b"email".to_vec(),
                        primary_key: b"user/1".to_vec(),
                        old_value: None,
                        new_value: Some(b"old@example.com".to_vec()),
                    }],
                )
                .unwrap();
            engine.set_failure_injector(Some(FailureInjector::once(point)));
            assert!(engine
                .write_indexed(
                    vec![BatchOperation::Put(b"user/1".to_vec(), b"new".to_vec())],
                    vec![IndexUpdate {
                        index: b"email".to_vec(),
                        primary_key: b"user/1".to_vec(),
                        old_value: Some(b"old@example.com".to_vec()),
                        new_value: Some(b"new@example.com".to_vec()),
                    }],
                )
                .is_err());
        }
        let engine = Engine::open(directory.path()).unwrap();
        let row = engine.get(b"user/1").unwrap().unwrap();
        let old = engine
            .lookup_index(b"email", b"old@example.com", 10)
            .unwrap();
        let new = engine
            .lookup_index(b"email", b"new@example.com", 10)
            .unwrap();
        assert!(
            (row == b"old" && old == [b"user/1".to_vec()] && new.is_empty())
                || (row == b"new" && old.is_empty() && new == [b"user/1".to_vec()]),
            "failure at {point:?} recovered a torn primary/index transaction"
        );
    }
}

#[test]
fn checkpoint_failure_selects_one_complete_generation() {
    for point in [
        FailurePoint::BeforeManifestPublish,
        FailurePoint::AfterManifestPublish,
        FailurePoint::AfterTreeAdoption,
    ] {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"a".to_vec(), vec![1; 4096]).unwrap();
            engine.set_failure_injector(Some(FailureInjector::once(point)));
            assert!(engine.checkpoint().is_err(), "failure at {point:?}");
        }
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(
            engine.get(b"a").unwrap(),
            Some(vec![1; 4096]),
            "failure at {point:?}"
        );
    }
}

/// The manifest publish is a checkpoint's commit point: past it the engine lives
/// on the new generation's files whether or not the rest of the checkpoint
/// finished. A checkpoint that fails there must leave the generation counter
/// agreeing with the manifest, because the next checkpoint recomputes its target
/// from that counter — and used to recompute the very generation whose files it
/// then unlinked as stale, deleting what the running engine was writing to (on
/// POSIX; on Windows every later rename over those open files failed instead).
#[test]
fn a_checkpoint_that_fails_after_publishing_leaves_the_next_one_safe() {
    for point in [
        FailurePoint::AfterManifestPublish,
        FailurePoint::AfterTreeAdoption,
    ] {
        let directory = tempdir().unwrap();
        let published_pages = directory.path().join("pages-00000000000000000001.vdb");
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"a".to_vec(), vec![7; 4096]).unwrap();
            engine.set_failure_injector(Some(FailureInjector::once(point)));
            assert!(engine.checkpoint().is_err(), "failure at {point:?}");
            // The manifest names generation 1 and the counter must agree with
            // it, whatever failed after the publish.
            assert_eq!(
                engine.stats().unwrap().checkpoint_generation,
                1,
                "generation {point:?} left the counter behind the manifest"
            );
            assert!(
                published_pages.exists(),
                "the published generation's own files must survive a failed cleanup"
            );
            // The next checkpoint targets generation 2 and must succeed without
            // touching the live generation 1 files.
            engine.checkpoint().expect("second checkpoint after a failed one");
            assert_eq!(engine.stats().unwrap().checkpoint_generation, 2);
            engine.put(b"b".to_vec(), b"later".to_vec()).unwrap();
        }
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.get(b"a").unwrap(), Some(vec![7; 4096]));
        assert_eq!(engine.get(b"b").unwrap(), Some(b"later".to_vec()));
        assert_eq!(engine.stats().unwrap().checkpoint_generation, 2);
    }
}

/// Staging historical values is the one commit step that fails on resources the
/// caller controls, and it used to run after the batch's root was published: an
/// ENOSPC there returned an error for an already-visible write, and the next
/// successful commit encoded the phantom root into its WAL record so a crash
/// made the unacknowledged write permanent. The batch must leave no trace at
/// all — not in the tree, not in the count, not in the change log.
#[test]
fn a_failed_value_preparation_leaves_nothing_visible_or_logged() {
    let directory = tempdir().unwrap();
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"seed".to_vec(), b"value".to_vec()).unwrap();
        // An active snapshot is what makes a batch stage historical values at
        // all, so one must be open for the injected fault to be reachable.
        let snapshot = engine.register_snapshot();
        engine.set_failure_injector(Some(FailureInjector::once(
            FailurePoint::BeforeValuePrepare,
        )));
        let outcome = engine.write_batch(vec![
            BatchOperation::Put(b"ghost".to_vec(), b"uncommitted".to_vec()),
            BatchOperation::Put(b"seed".to_vec(), b"replaced".to_vec()),
        ]);
        assert!(outcome.is_err(), "the injected preparation failure must surface");
        assert_eq!(
            engine.get(b"ghost").unwrap(),
            None,
            "an unacknowledged write must not become visible"
        );
        assert_eq!(
            engine.get(b"seed").unwrap(),
            Some(b"value".to_vec()),
            "the acknowledged value must survive the failed batch untouched"
        );
        assert_eq!(engine.len(), 1, "the failed batch must not move the count");
        assert!(
            engine.last_published().is_empty(),
            "change records for mutations that did not happen must never reach subscribers"
        );
        engine.release_snapshot(snapshot);
        // The engine stays usable, and its next commit is ordinary.
        engine.put(b"after".to_vec(), b"ok".to_vec()).unwrap();
    }
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(
        engine.get(b"ghost").unwrap(),
        None,
        "recovery must not resurrect the failed batch"
    );
    assert_eq!(engine.get(b"seed").unwrap(), Some(b"value".to_vec()));
    assert_eq!(engine.get(b"after").unwrap(), Some(b"ok".to_vec()));
}

/// History maintenance runs after the commit has been fsynced, so a failure
/// there describes data that IS on disk. Returning an ordinary error would make
/// the caller retry and apply the batch twice; the error must say the write is
/// durable while the engine refuses all further work.
#[test]
fn an_error_after_the_commit_reports_the_write_as_durable_and_stops_the_engine() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"key".to_vec(), b"one".to_vec()).unwrap();
    let snapshot = engine.register_snapshot();
    engine.set_failure_injector(Some(FailureInjector::once(
        FailurePoint::BeforeHistoryAppend,
    )));
    let outcome = engine.put(b"key".to_vec(), b"two".to_vec());
    engine.release_snapshot(snapshot);
    let error = outcome.unwrap_err();
    assert!(
        matches!(error, Error::CommittedThenPoisoned { .. }),
        "a post-commit failure must say the write is durable, got {error:?}"
    );
    assert!(
        matches!(engine.put(b"other".to_vec(), b"x".to_vec()), Err(Error::Poisoned)),
        "a poisoned engine must refuse further writes"
    );
    assert!(
        matches!(engine.get(b"key"), Err(Error::Poisoned)),
        "a poisoned engine must refuse reads too"
    );
    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(
        engine.get(b"key").unwrap(),
        Some(b"two".to_vec()),
        "the errored write was fsynced and must be durable"
    );
}

/// Draining the async buffer appends each record with the LSN it was issued at.
/// Every record used to be stamped with `last_lsn` — the newest record's LSN —
/// so the first append alone told concurrent barriers the whole drain was done,
/// while the remaining records had not even been handed to the kernel.
///
/// The full durability-accounting race needs a flush landing between two drain
/// iterations and is not deterministically observable through the public API;
/// this pins the contract that survives it: buffered records carry their own
/// LSNs, drain in order, and replay exactly once after a sync.
#[test]
fn buffered_async_records_are_drained_with_their_own_lsns_and_survive_a_sync() {
    let directory = tempdir().unwrap();
    {
        let mut engine = Engine::open_with_options(
            directory.path(),
            EngineOptions {
                durability: DurabilityMode::Async,
                ..EngineOptions::default()
            },
        )
        .unwrap();
        engine
            .write_batch_deferred(vec![BatchOperation::Put(b"k1".to_vec(), b"one".to_vec())])
            .unwrap();
        engine
            .write_batch_deferred(vec![
                BatchOperation::Put(b"k2".to_vec(), b"two".to_vec()),
                BatchOperation::Delete(b"k1".to_vec()),
            ])
            .unwrap();
        engine
            .write_batch_deferred(vec![BatchOperation::Put(b"k3".to_vec(), b"three".to_vec())])
            .unwrap();
        assert_eq!(engine.sequence(), 3);
        engine.sync().unwrap();
        assert_eq!(engine.sequence(), 3);
    }
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.sequence(), 3, "every buffered record replays exactly once");
    assert_eq!(engine.get(b"k1").unwrap(), None);
    assert_eq!(engine.get(b"k2").unwrap(), Some(b"two".to_vec()));
    assert_eq!(engine.get(b"k3").unwrap(), Some(b"three".to_vec()));
}

/// A flush failure mid-drain strands records that have already left the buffer;
/// they cannot go back. Continuing as a healthy engine would hide the loss, so
/// the failure poisons the engine exactly like a failed commit-path append.
#[test]
fn a_flush_failure_mid_drain_poisons_rather_than_losing_records_quietly() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open_with_options(
        directory.path(),
        EngineOptions {
            durability: DurabilityMode::Async,
            ..EngineOptions::default()
        },
    )
    .unwrap();
    for (key, value) in [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")] {
        engine
            .write_batch_deferred(vec![BatchOperation::Put(
                key.to_vec(),
                value.to_vec(),
            )])
            .unwrap();
    }
    engine.set_failure_injector(Some(FailureInjector::once(
        FailurePoint::BetweenBufferedAppends,
    )));
    assert!(engine.sync().is_err(), "the injected flush failure must surface");
    assert!(
        matches!(engine.write_batch(vec![]), Err(Error::Poisoned)),
        "an engine that lost drained records must refuse further work"
    );
    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(
        engine.get(b"a").unwrap(),
        Some(b"1".to_vec()),
        "the record whose append completed must survive"
    );
    assert_eq!(
        engine.get(b"b").unwrap(),
        None,
        "records drained but never written are gone, and the error said so"
    );
    assert_eq!(engine.get(b"c").unwrap(), None);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn deterministic_failures_match_reference_model(
        operations in prop::collection::vec((0_u8..8, any::<u8>(), any::<bool>()), 1..40),
        failure_step in 0_usize..40,
        point_index in 0_usize..COMMIT_POINTS.len(),
    ) {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        let mut acknowledged = BTreeMap::new();
        let mut ambiguous = None;
        for (step, (key, value, delete)) in operations.into_iter().enumerate() {
            if step == failure_step {
                engine.set_failure_injector(Some(FailureInjector::once(COMMIT_POINTS[point_index])));
            }
            let key = vec![key];
            let operation = if delete {
                BatchOperation::Delete(key.clone())
            } else {
                BatchOperation::Put(key.clone(), vec![value])
            };
            match engine.write_batch(vec![operation]) {
                Ok(_) => {
                    if delete {
                        acknowledged.remove(&key);
                    } else {
                        acknowledged.insert(key, vec![value]);
                    }
                }
                Err(_) => {
                    ambiguous = Some((key, (!delete).then_some(vec![value])));
                    break;
                }
            }
        }
        drop(engine);
        let recovered = Engine::open(directory.path()).unwrap();
        let actual: BTreeMap<_, _> = recovered.scan(None, None, usize::MAX).unwrap().into_iter().collect();
        let mut post = acknowledged.clone();
        if let Some((key, value)) = ambiguous {
            if let Some(value) = value {
                post.insert(key, value);
            } else {
                post.remove(&key);
            }
        }
        prop_assert!(actual == acknowledged || actual == post);
    }
}
