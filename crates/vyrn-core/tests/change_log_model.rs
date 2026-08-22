//! The change log, checked against a reference model of what a subscriber must see.
//!
//! A subscriber holds a cursor, asks for what came after it, and advances. The
//! contract is that following that loop delivers every published change exactly
//! once, in commit order, no matter how the reads are chunked or how often the
//! database is reopened underneath. Every way of breaking it is quiet: a skipped
//! change leaves a downstream system permanently missing a write it was never
//! told about, and nothing errors.
//!
//! The existing tests check that contract at specific hand-picked shapes. This
//! one checks it against an independently derived model over randomized commit
//! histories, arbitrary page sizes, and reopens in the middle of the stream —
//! the combination the hand-written cases cannot enumerate.

use proptest::prelude::*;
use serde_json::json;
use std::collections::BTreeMap;
use tempfile::tempdir;
use vyrn_core::{change_log::Cursor, document::IndexDefinition, BatchOperation, Engine};

const KEYS: [&str; 5] = ["a", "b", "c", "d", "e"];
const DOC_IDS: [&str; 3] = ["ada", "alan", "grace"];

/// What a subscriber should be told about one mutation: the key it touched and
/// the value it left, where `None` is a deletion.
type Expected = (Vec<u8>, Option<Vec<u8>>);

#[derive(Debug, Clone)]
enum Operation {
    Put {
        key: usize,
        value: u8,
    },
    Delete(usize),
    /// A multi-key commit. Every mutation in it publishes, and they share a
    /// commit sequence, so this is where an off-by-one in the per-commit index
    /// would drop or duplicate a change.
    Batch(Vec<(usize, Option<u8>)>),
    /// Documents publish through the same log under their own key encoding, so
    /// they belong in the same stream a subscriber consumes.
    PutDocument {
        id: usize,
        email: u8,
    },
    DeleteDocument(usize),
    Reopen,
    Checkpoint,
}

fn operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        6 => (0..KEYS.len(), any::<u8>()).prop_map(|(key, value)| Operation::Put { key, value }),
        3 => (0..KEYS.len()).prop_map(Operation::Delete),
        3 => prop::collection::vec((0..KEYS.len(), prop::option::of(any::<u8>())), 1..4)
            .prop_map(Operation::Batch),
        3 => (0..DOC_IDS.len(), any::<u8>())
            .prop_map(|(id, email)| Operation::PutDocument { id, email }),
        2 => (0..DOC_IDS.len()).prop_map(Operation::DeleteDocument),
        1 => Just(Operation::Reopen),
        1 => Just(Operation::Checkpoint),
    ]
}

fn document_indexes() -> Vec<IndexDefinition> {
    vec![IndexDefinition::new("email", false)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn a_subscriber_sees_every_change_exactly_once(
        operations in prop::collection::vec(operation(), 1..40),
        page_size in 1_usize..5,
    ) {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.collection("users", &document_indexes()).unwrap();

        // The model: every mutation that was acknowledged, in the order it was
        // acknowledged. Built from the return of each write rather than from the
        // log, so it is genuinely independent of what the log reports.
        let mut expected: Vec<Expected> = Vec::new();
        // Documents need their live values tracked, because a delete of a missing
        // document publishes nothing and must not enter the model.
        let mut documents: BTreeMap<String, u8> = BTreeMap::new();

        for operation in operations {
            match operation {
                Operation::Put { key, value } => {
                    let key = KEYS[key].as_bytes().to_vec();
                    engine.put(key.clone(), vec![value]).unwrap();
                    expected.push((key, Some(vec![value])));
                }
                Operation::Delete(key) => {
                    let key = KEYS[key].as_bytes().to_vec();
                    // A delete of an absent key is a no-op commit and publishes
                    // nothing, so only a real deletion joins the model.
                    if engine.delete(&key).unwrap() {
                        expected.push((key, None));
                    }
                }
                Operation::Batch(mutations) => {
                    // A batch may name the same key twice; the engine collapses
                    // that to the last write, so the model has to as well or it
                    // would expect a change the log correctly never published.
                    let mut collapsed: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
                    for (key, value) in &mutations {
                        collapsed.insert(
                            KEYS[*key].as_bytes().to_vec(),
                            value.map(|value| vec![value]),
                        );
                    }
                    let operations: Vec<_> = collapsed
                        .iter()
                        .map(|(key, value)| match value {
                            Some(value) => BatchOperation::Put(key.clone(), value.clone()),
                            None => BatchOperation::Delete(key.clone()),
                        })
                        .collect();
                    let results = engine.write_batch(operations).unwrap();
                    // Deletes that hit nothing publish nothing, so the model
                    // follows what the batch reported rather than what it asked
                    // for. Results are positional over the same ordered keys.
                    for ((key, value), result) in collapsed.into_iter().zip(results) {
                        let published = match result {
                            vyrn_core::BatchResult::Delete { existed } => existed,
                            _ => true,
                        };
                        if published {
                            expected.push((key, value));
                        }
                    }
                }
                Operation::PutDocument { id, email } => {
                    let id = DOC_IDS[id];
                    let mut users = engine.collection("users", &document_indexes()).unwrap();
                    users.put(id, &json!({"email": email})).unwrap();
                    drop(users);
                    documents.insert(id.to_string(), email);
                    let key = vyrn_core::document::document_change_key("users", id).unwrap();
                    let value = serde_json::to_vec(&json!({"email": email})).unwrap();
                    expected.push((key, Some(value)));
                }
                Operation::DeleteDocument(id) => {
                    let id = DOC_IDS[id];
                    let mut users = engine.collection("users", &document_indexes()).unwrap();
                    let existed = users.delete(id).unwrap();
                    drop(users);
                    prop_assert_eq!(existed, documents.remove(id).is_some());
                    if existed {
                        let key = vyrn_core::document::document_change_key("users", id).unwrap();
                        expected.push((key, None));
                    }
                }
                Operation::Reopen => {
                    drop(engine);
                    engine = Engine::open(directory.path()).unwrap();
                }
                Operation::Checkpoint => {
                    engine.checkpoint().unwrap();
                }
            }

            // Drain the whole log from the beginning in pages, the way a fresh
            // subscriber would. `page_size` is small and varies so that commit
            // boundaries fall inside pages, which is where a resume that is off
            // by one drops or repeats the change at the seam.
            let mut drained: Vec<Expected> = Vec::new();
            let mut cursor = Cursor::start();
            let mut cursors: Vec<Cursor> = Vec::new();
            loop {
                let page = engine.read_changes(cursor, page_size).unwrap();
                if page.is_empty() {
                    break;
                }
                prop_assert!(
                    page.len() <= page_size,
                    "a page of {} exceeded the requested limit {}",
                    page.len(),
                    page_size
                );
                for change in &page {
                    cursors.push(change.cursor());
                    drained.push((change.key.clone(), change.value.clone()));
                }
                cursor = page.last().unwrap().cursor();
            }

            prop_assert_eq!(
                &drained,
                &expected,
                "the change stream did not match the acknowledged writes"
            );
            // Strictly increasing cursors are what let a subscriber persist its
            // position and resume; a repeat or a regression would make the resume
            // above silently lossy even though the drain matched.
            for pair in cursors.windows(2) {
                prop_assert!(
                    pair[0] < pair[1],
                    "cursors did not strictly increase: {:?} then {:?}",
                    pair[0],
                    pair[1]
                );
            }

            // Resuming from each cursor in turn must yield exactly the remaining
            // suffix. This is the operation a real subscriber performs after a
            // restart, and the one that has to not skip anything.
            for (index, resume) in cursors.iter().enumerate() {
                let rest = engine.read_changes(*resume, usize::MAX).unwrap();
                let actual: Vec<Expected> = rest
                    .into_iter()
                    .map(|change| (change.key, change.value))
                    .collect();
                prop_assert_eq!(
                    &actual,
                    &expected[index + 1..].to_vec(),
                    "resuming from cursor {} delivered the wrong suffix",
                    index
                );
            }
        }
    }
}
