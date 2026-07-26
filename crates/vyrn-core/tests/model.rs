use proptest::prelude::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use vyrn_core::Engine;

#[derive(Debug, Clone)]
enum Operation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    Reopen,
    /// A crash-shaped reopen: drop the engine, throw away every page appended
    /// since the last checkpoint image, and recover from the WAL. The commit
    /// path syncs only the WAL, so this is a loss the engine explicitly
    /// promises to survive at any point in the history.
    CrashReopen,
    Checkpoint,
}

fn operation() -> impl Strategy<Value = Operation> {
    let key = prop::collection::vec(any::<u8>(), 1..24);
    let value = prop::collection::vec(any::<u8>(), 0..128);
    prop_oneof![
        6 => (key.clone(), value).prop_map(|(key, value)| Operation::Put(key, value)),
        3 => key.prop_map(Operation::Delete),
        1 => Just(Operation::Reopen),
        1 => Just(Operation::CrashReopen),
        1 => Just(Operation::Checkpoint),
    ]
}

/// The newest page file is the one the manifest's checkpoint generation points
/// at (checkpoint deletes the old generation), so every post-checkpoint page
/// sits in its tail.
fn newest_page_file(directory: &Path) -> PathBuf {
    std::fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            path.extension()
                .is_some_and(|extension| extension == "vdb")
                .then_some(path)
        })
        .max()
        .expect("a page file should exist")
}

fn page_file_len(directory: &Path) -> u64 {
    std::fs::metadata(newest_page_file(directory))
        .unwrap()
        .len()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn engine_matches_btree_map(operations in prop::collection::vec(operation(), 1..180)) {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        let mut model = BTreeMap::new();
        // Bytes of the page file that belong to the durable checkpoint image.
        // A simulated crash may drop anything appended after this point, but
        // never the image itself: recovery deliberately refuses to open when
        // pre-checkpoint pages are gone, because no redo can rebuild them.
        let mut checkpointed_len = page_file_len(directory.path());

        for operation in operations {
            match operation {
                Operation::Put(key, value) => {
                    engine.put(key.clone(), value.clone()).unwrap();
                    model.insert(key, value);
                }
                Operation::Delete(key) => {
                    let actual = engine.delete(&key).unwrap();
                    let expected = model.remove(&key).is_some();
                    prop_assert_eq!(actual, expected);
                }
                Operation::Reopen => {
                    drop(engine);
                    engine = Engine::open(directory.path()).unwrap();
                }
                Operation::CrashReopen => {
                    drop(engine);
                    let pages = newest_page_file(directory.path());
                    let current = std::fs::metadata(&pages).unwrap().len();
                    if current > checkpointed_len {
                        let file = std::fs::OpenOptions::new()
                            .write(true)
                            .open(&pages)
                            .unwrap();
                        file.set_len(checkpointed_len).unwrap();
                        file.sync_all().unwrap();
                    }
                    engine = Engine::open(directory.path()).unwrap();
                }
                Operation::Checkpoint => {
                    engine.checkpoint().unwrap();
                    checkpointed_len = page_file_len(directory.path());
                }
            }
            let actual = engine.scan(None, None, usize::MAX).unwrap();
            let expected: Vec<_> = model.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
            prop_assert_eq!(actual, expected);
            prop_assert_eq!(engine.len(), model.len());
            // Value equality alone cannot see a lost revision: a key whose
            // revision vanished still reads back correctly but breaks
            // changed_since watchers. Asserting presence here makes
            // tombstone/revision loss visible to the model after any crash.
            for key in model.keys() {
                prop_assert!(
                    engine.revision(key).unwrap().is_some(),
                    "live key {:?} lost its revision",
                    key
                );
            }
        }
    }
}
