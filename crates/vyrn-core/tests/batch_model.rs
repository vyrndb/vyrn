//! Multi-key batch writes checked against a `BTreeMap` model.
//!
//! `write_batch` applies a whole batch in one copy-on-write pass, so a batch that
//! repeats a key, deletes a key it just wrote, or splits a leaf has to produce the
//! same tree a sequence of single-key writes would have. These cases are what a
//! per-key implementation got right for free and a batched one can get wrong.

use proptest::prelude::*;
use std::collections::BTreeMap;
use tempfile::tempdir;
use vyrn_core::{BatchOperation, BatchResult, Engine};

#[derive(Debug, Clone)]
enum Batch {
    Write(Vec<BatchOperation>),
    Reopen,
    Checkpoint,
}

/// Draws keys from a small alphabet so batches collide on the same keys often.
fn key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0_u8..6, 1..4)
}

fn operation() -> impl Strategy<Value = BatchOperation> {
    let value = prop::collection::vec(any::<u8>(), 0..48);
    prop_oneof![
        3 => (key(), value).prop_map(|(key, value)| BatchOperation::Put(key, value)),
        2 => key().prop_map(BatchOperation::Delete),
    ]
}

fn batch() -> impl Strategy<Value = Batch> {
    prop_oneof![
        8 => prop::collection::vec(operation(), 1..24).prop_map(Batch::Write),
        1 => Just(Batch::Reopen),
        1 => Just(Batch::Checkpoint),
    ]
}

/// Applies one operation to the model, returning the result the engine should report.
fn apply(model: &mut BTreeMap<Vec<u8>, Vec<u8>>, operation: &BatchOperation) -> BatchResult {
    match operation {
        BatchOperation::Put(key, value) => {
            model.insert(key.clone(), value.clone());
            BatchResult::Put
        }
        BatchOperation::Delete(key) => BatchResult::Delete {
            existed: model.remove(key).is_some(),
        },
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn batched_writes_match_btree_map(batches in prop::collection::vec(batch(), 1..24)) {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        let mut model = BTreeMap::new();

        for batch in batches {
            match batch {
                Batch::Write(operations) => {
                    let expected: Vec<_> = operations
                        .iter()
                        .map(|operation| apply(&mut model, operation))
                        .collect();
                    let actual = engine.write_batch(operations).unwrap();
                    // Every operation reports a result, in order, and a delete's
                    // hit must reflect earlier operations in the same batch.
                    prop_assert_eq!(actual.len(), expected.len());
                    for (actual, expected) in actual.iter().zip(expected.iter()) {
                        prop_assert_eq!(
                            matches!(actual, BatchResult::Delete { existed: true }),
                            matches!(expected, BatchResult::Delete { existed: true })
                        );
                        prop_assert_eq!(
                            matches!(actual, BatchResult::Put),
                            matches!(expected, BatchResult::Put)
                        );
                    }
                }
                Batch::Reopen => {
                    drop(engine);
                    engine = Engine::open(directory.path()).unwrap();
                }
                Batch::Checkpoint => engine.checkpoint().unwrap(),
            }
            let actual = engine.scan(None, None, usize::MAX).unwrap();
            let expected: Vec<_> = model
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            prop_assert_eq!(actual, expected);
            prop_assert_eq!(engine.len(), model.len());
            // Point reads must agree too: a scan walks leaves in order, while a
            // get descends the internal pages the batch rewrote.
            for (key, value) in &model {
                let stored = engine.get(key).unwrap();
                prop_assert_eq!(stored.as_ref(), Some(value));
            }
        }
    }
}

/// A batch large enough to split leaves and grow the tree, applied in one pass.
#[test]
fn one_batch_can_split_leaves_and_survive_reopen() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let operations: Vec<_> = (0..512_u32)
        .map(|index| BatchOperation::Put(format!("key/{index:06}").into_bytes(), vec![7; 200]))
        .collect();
    engine.write_batch(operations).unwrap();
    assert_eq!(engine.len(), 512);

    // Delete every other key in a single batch, then confirm the survivors.
    let deletes: Vec<_> = (0..512_u32)
        .filter(|index| index % 2 == 0)
        .map(|index| BatchOperation::Delete(format!("key/{index:06}").into_bytes()))
        .collect();
    let results = engine.write_batch(deletes).unwrap();
    assert!(results
        .iter()
        .all(|result| matches!(result, BatchResult::Delete { existed: true })));
    assert_eq!(engine.len(), 256);

    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.len(), 256);
    for index in 0..512_u32 {
        let key = format!("key/{index:06}").into_bytes();
        let expected = (index % 2 == 1).then(|| vec![7; 200]);
        assert_eq!(engine.get(&key).unwrap(), expected, "key {index}");
    }
}

/// A key written and then deleted inside one batch must not survive, and a key
/// deleted then rewritten must.
#[test]
fn later_operations_win_within_one_batch() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"kept".to_vec(), b"original".to_vec()).unwrap();

    let results = engine
        .write_batch(vec![
            BatchOperation::Put(b"transient".to_vec(), b"first".to_vec()),
            BatchOperation::Delete(b"transient".to_vec()),
            BatchOperation::Delete(b"kept".to_vec()),
            BatchOperation::Put(b"kept".to_vec(), b"rewritten".to_vec()),
            BatchOperation::Delete(b"absent".to_vec()),
        ])
        .unwrap();

    // The delete of a key written earlier in the batch is a hit; the delete of a
    // key that never existed is not.
    assert!(matches!(results[1], BatchResult::Delete { existed: true }));
    assert!(matches!(results[2], BatchResult::Delete { existed: true }));
    assert!(matches!(results[4], BatchResult::Delete { existed: false }));
    assert_eq!(engine.get(b"transient").unwrap(), None);
    assert_eq!(engine.get(b"kept").unwrap(), Some(b"rewritten".to_vec()));
    assert_eq!(engine.len(), 1);

    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.get(b"transient").unwrap(), None);
    assert_eq!(engine.get(b"kept").unwrap(), Some(b"rewritten".to_vec()));
    assert_eq!(engine.len(), 1);
}
