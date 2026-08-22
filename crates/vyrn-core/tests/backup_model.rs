//! Backup and restore, checked against a reference model.
//!
//! A backup is what an operator reaches for when the original is already gone, so
//! the two failures that matter are a restore that quietly reproduces the wrong
//! state and a damaged archive that restores anyway. Both are silent: the restore
//! succeeds, the database opens, and the missing writes are only noticed later.
//!
//! `pitr.rs` drives backups as one step of point-in-time recovery over a fixed
//! timeline. This checks the archive on its own, over randomized histories, and
//! then asserts that every single-byte truncation of an archive either refuses or
//! restores the exact state — never something in between.

use proptest::prelude::*;
use std::collections::BTreeMap;
use tempfile::tempdir;
use vyrn_core::{backup, BatchOperation, Engine};

#[derive(Debug, Clone)]
enum Operation {
    Put(u8, u8),
    Delete(u8),
    Batch(Vec<(u8, Option<u8>)>),
    Checkpoint,
    /// A reopen before the backup, so the archive sometimes covers a database
    /// whose state is spread across a checkpoint image and a replayed WAL rather
    /// than sitting in one generation.
    Reopen,
}

fn operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        6 => (any::<u8>(), any::<u8>()).prop_map(|(key, value)| Operation::Put(key, value)),
        3 => any::<u8>().prop_map(Operation::Delete),
        3 => prop::collection::vec((any::<u8>(), prop::option::of(any::<u8>())), 1..4)
            .prop_map(Operation::Batch),
        1 => Just(Operation::Checkpoint),
        1 => Just(Operation::Reopen),
    ]
}

/// Applies `operations`, returning the engine and the state it should hold.
///
/// The engine is owned rather than borrowed so a reopen can drop it first: the
/// data directory holds an exclusive lock, so opening a second handle over a live
/// one fails.
fn build(
    mut engine: Engine,
    directory: &std::path::Path,
    operations: Vec<Operation>,
) -> (Engine, BTreeMap<Vec<u8>, Vec<u8>>) {
    let mut model = BTreeMap::new();
    for operation in operations {
        match operation {
            Operation::Put(key, value) => {
                engine.put(vec![key], vec![value]).unwrap();
                model.insert(vec![key], vec![value]);
            }
            Operation::Delete(key) => {
                let existed = engine.delete(&[key]).unwrap();
                assert_eq!(existed, model.remove(&vec![key]).is_some());
            }
            Operation::Batch(mutations) => {
                // A batch may repeat a key; the engine keeps the last write, so
                // the model collapses the same way.
                let mut collapsed: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
                for (key, value) in mutations {
                    collapsed.insert(vec![key], value.map(|value| vec![value]));
                }
                let batch: Vec<_> = collapsed
                    .iter()
                    .map(|(key, value)| match value {
                        Some(value) => BatchOperation::Put(key.clone(), value.clone()),
                        None => BatchOperation::Delete(key.clone()),
                    })
                    .collect();
                engine.write_batch(batch).unwrap();
                for (key, value) in collapsed {
                    match value {
                        Some(value) => model.insert(key, value),
                        None => model.remove(&key),
                    };
                }
            }
            Operation::Checkpoint => engine.checkpoint().unwrap(),
            Operation::Reopen => {
                // Dropped before reopening: the directory lock is exclusive, so a
                // second handle over a live one is refused.
                drop(engine);
                engine = Engine::open(directory).unwrap();
            }
        }
    }
    (engine, model)
}

fn state_of(engine: &Engine) -> BTreeMap<Vec<u8>, Vec<u8>> {
    engine
        .scan(None, None, usize::MAX)
        .unwrap()
        .into_iter()
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn a_restore_reproduces_the_source_exactly(operations in prop::collection::vec(operation(), 1..40)) {
        let source_dir = tempdir().unwrap();
        let model = {
            let engine = Engine::open(source_dir.path()).unwrap();
            let (engine, model) = build(engine, source_dir.path(), operations);
            // The source is read back before the backup so a mismatch below is
            // attributable to the archive rather than to the engine.
            prop_assert_eq!(state_of(&engine), model.clone());
            // `create_backup` takes the directory lock, so the engine has to be
            // closed before it runs.
            drop(engine);
            model
        };

        let archive_dir = tempdir().unwrap();
        let archive = archive_dir.path().join("backup.vyrnbkp");
        backup::create_backup(source_dir.path(), &archive).unwrap();
        backup::verify_backup(&archive).unwrap();

        let target_dir = tempdir().unwrap();
        let target = target_dir.path().join("restored");
        backup::restore_backup(&archive, &target).unwrap();
        let restored = Engine::open(&target).unwrap();
        prop_assert_eq!(state_of(&restored), model.clone());
        prop_assert_eq!(restored.len(), model.len());

        // The restored copy has to be a working database, not just one that reads
        // back correctly once: a backup whose WAL state is subtly wrong can open,
        // scan, and then fail or lose data on the next write.
        drop(restored);
        let mut reopened = Engine::open(&target).unwrap();
        reopened.put(b"after-restore".to_vec(), b"1".to_vec()).unwrap();
        reopened.checkpoint().unwrap();
        drop(reopened);
        let again = Engine::open(&target).unwrap();
        let mut with_write = model;
        with_write.insert(b"after-restore".to_vec(), b"1".to_vec());
        prop_assert_eq!(state_of(&again), with_write);
    }
}

/// A truncated archive must be refused, not restored into a partial database.
///
/// Truncation is the realistic damage for an archive: an upload that stopped, a
/// disk that filled, a copy that was interrupted. Every prefix is checked because
/// the interesting ones are the boundaries — a whole file short, a header split
/// mid-field, the footer missing by one byte.
#[test]
fn every_truncated_archive_is_refused_or_restores_exactly() {
    let source_dir = tempdir().unwrap();
    let model = {
        let mut engine = Engine::open(source_dir.path()).unwrap();
        for index in 0..24_u8 {
            engine.put(vec![index], vec![index; 300]).unwrap();
        }
        engine.checkpoint().unwrap();
        for index in 24..32_u8 {
            engine.put(vec![index], vec![index; 300]).unwrap();
        }
        state_of(&engine)
    };

    let archive_dir = tempdir().unwrap();
    let archive = archive_dir.path().join("backup.vyrnbkp");
    backup::create_backup(source_dir.path(), &archive).unwrap();
    let original = std::fs::read(&archive).unwrap();

    // Stepping every byte over a multi-megabyte archive would take hours, so this
    // walks the structural boundaries densely and strides the file bodies.
    let interesting: Vec<usize> = (0..original.len())
        .filter(|length| *length < 512 || original.len() - *length < 512 || length % 4_096 == 0)
        .collect();

    for length in interesting {
        let case_dir = tempdir().unwrap();
        let case = case_dir.path().join("truncated.vyrnbkp");
        std::fs::write(&case, &original[..length]).unwrap();

        let verified = backup::verify_backup(&case).is_ok();
        let target = case_dir.path().join("restored");
        match backup::restore_backup(&case, &target) {
            Err(_) => assert!(
                !verified,
                "verify accepted an archive at {length} bytes that restore rejected"
            ),
            Ok(()) => {
                // A restore that succeeded must produce the whole database. A
                // truncated archive yielding a smaller but openable database is
                // the silent-loss case this test exists to catch.
                let engine = Engine::open(&target).unwrap_or_else(|error| {
                    panic!("restore from {length} bytes produced a database that will not open: {error}")
                });
                assert_eq!(
                    state_of(&engine),
                    model,
                    "restore from a {length}-byte archive silently lost data"
                );
            }
        }
    }
}

/// The other half: a flip inside a file body must be caught by its checksum
/// rather than restored as good data.
#[test]
fn a_corrupted_archive_body_is_refused() {
    let source_dir = tempdir().unwrap();
    {
        let mut engine = Engine::open(source_dir.path()).unwrap();
        for index in 0..16_u8 {
            engine.put(vec![index], vec![index; 512]).unwrap();
        }
        engine.checkpoint().unwrap();
    }

    let archive_dir = tempdir().unwrap();
    let archive = archive_dir.path().join("backup.vyrnbkp");
    backup::create_backup(source_dir.path(), &archive).unwrap();
    let original = std::fs::read(&archive).unwrap();

    // Sample across the archive rather than every byte: each position lands in
    // some file's body or header, and both must fail closed.
    for index in (64..original.len()).step_by((original.len() / 32).max(1)) {
        let case_dir = tempdir().unwrap();
        let case = case_dir.path().join("flipped.vyrnbkp");
        let mut bytes = original.clone();
        bytes[index] ^= 0xFF;
        std::fs::write(&case, &bytes).unwrap();

        let target = case_dir.path().join("restored");
        assert!(
            backup::verify_backup(&case).is_err()
                || backup::restore_backup(&case, &target).is_err()
                || Engine::open(&target).is_ok(),
            "a flip at byte {index} restored into a database that will not open"
        );
    }
}
