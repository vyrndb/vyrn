use proptest::prelude::*;
use std::collections::BTreeMap;
use tempfile::tempdir;
use vyrn_core::Engine;

#[derive(Debug, Clone)]
enum Operation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    Reopen,
    Checkpoint,
}

fn operation() -> impl Strategy<Value = Operation> {
    let key = prop::collection::vec(any::<u8>(), 1..24);
    let value = prop::collection::vec(any::<u8>(), 0..128);
    prop_oneof![
        6 => (key.clone(), value).prop_map(|(key, value)| Operation::Put(key, value)),
        3 => key.prop_map(Operation::Delete),
        1 => Just(Operation::Reopen),
        1 => Just(Operation::Checkpoint),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn engine_matches_btree_map(operations in prop::collection::vec(operation(), 1..180)) {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        let mut model = BTreeMap::new();

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
                Operation::Checkpoint => engine.checkpoint().unwrap(),
            }
            let actual = engine.scan(None, None, usize::MAX).unwrap();
            let expected: Vec<_> = model.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
            prop_assert_eq!(actual, expected);
            prop_assert_eq!(engine.len(), model.len());
        }
    }
}
