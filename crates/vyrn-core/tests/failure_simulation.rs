use proptest::prelude::*;
use std::collections::BTreeMap;
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine, FailureInjector, FailurePoint, IndexUpdate};

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
    ] {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"a".to_vec(), vec![1; 4096]).unwrap();
            engine.set_failure_injector(Some(FailureInjector::once(point)));
            assert!(engine.checkpoint().is_err());
        }
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.get(b"a").unwrap(), Some(vec![1; 4096]));
    }
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
