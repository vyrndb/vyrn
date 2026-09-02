//! Unit tests for the server crate root.

use super::*;
use crate::metrics::Histogram;
use crate::write::{has_conflict, reject_conflicts};
use proptest::prelude::*;
use tempfile::tempdir;

/// A transaction check that has read `read_keys` and writes `writes`.
///
/// `snapshot_sequence` is irrelevant to these tests: they pass an
/// `against_engine` that always answers false, isolating the batch-local half
/// of validation, which is the half the grouping bugs were in.
fn check(
    index: usize,
    read_keys: &[&[u8]],
    writes: &[&[u8]],
    index_reads: &[(&[u8], &[u8])],
    index_updates: Vec<IndexUpdate>,
) -> BatchEntry {
    BatchEntry::Transaction(TransactionCheck {
        index,
        snapshot_sequence: 0,
        read_keys: read_keys.iter().map(|key| key.to_vec()).collect(),
        read_ranges: Vec::new(),
        index_reads: index_reads
            .iter()
            .map(|(index, value)| (index.to_vec(), value.to_vec()))
            .collect(),
        operations: writes
            .iter()
            .map(|key| BatchOperation::Put(key.to_vec(), b"v".to_vec()))
            .collect(),
        index_updates,
    })
}

/// Validation with the engine check stubbed out to "nothing committed".
fn rejected(entries: &[BatchEntry]) -> Vec<usize> {
    reject_conflicts(entries, |_| Ok(false)).expect("validation should not fail")
}

/* THE HOLE THIS CLOSES: a bare `Put`/`Delete` batched with a transaction that
 * had READ that key was invisible to validation. The transaction validated
 * clean against its snapshot — the put is in this very batch, not yet
 * committed — and the put has no reads of its own, so neither was rejected.
 * Both committed, and the transaction's write was decided from a value the
 * same commit overwrote: write skew created purely by grouping.
 *
 * A unit test rather than two racing clients: whether two requests land in one
 * batch is a timing property of an idle server's accumulation window, so an
 * integration test would have to win a race to reach this code at all — and
 * would pass, quietly, whenever it lost. */
#[test]
fn a_plain_write_earlier_in_the_batch_conflicts_with_a_transaction_that_read_it() {
    let entries = vec![
        BatchEntry::Plain {
            key: b"balance".to_vec(),
        },
        check(1, &[b"balance"], &[b"withdrawal"], &[], Vec::new()),
    ];
    assert_eq!(
        rejected(&entries),
        vec![1],
        "a transaction that read a key a plain write earlier in its own batch \
         overwrites must be rejected; admitting both is write skew that only \
         grouping created"
    );
}

/// The mirror case, which is what stops the fix from being "reject everything":
/// a plain write ORDERED AFTER the transaction invalidates nothing, because the
/// transaction legitimately precedes it in the batch's serial order.
#[test]
fn a_plain_write_later_in_the_batch_does_not_conflict() {
    let entries = vec![
        check(0, &[b"balance"], &[b"withdrawal"], &[], Vec::new()),
        BatchEntry::Plain {
            key: b"balance".to_vec(),
        },
    ];
    assert!(
        rejected(&entries).is_empty(),
        "a transaction serialized BEFORE a plain write in the same batch is legal; \
         rejecting it would fail commits that have no conflict"
    );
}

/* THE SECOND HOLE: index claims. A client's own uniqueness check is "look up
 * who holds this value, then write based on the answer", and two transactions
 * doing that concurrently must not both commit. Index reads were checked
 * against the engine but not against the index entries earlier members of the
 * same batch add or remove, so grouped they both passed. */
#[test]
fn an_index_claim_earlier_in_the_batch_conflicts_with_a_lookup_of_that_value() {
    let claim = IndexUpdate {
        index: b"email".to_vec(),
        primary_key: b"users/first".to_vec(),
        old_value: None,
        new_value: Some(b"a@example.com".to_vec()),
    };
    let entries = vec![
        check(0, &[], &[b"users/first"], &[], vec![claim]),
        check(
            1,
            &[],
            &[b"users/second"],
            &[(b"email", b"a@example.com")],
            Vec::new(),
        ),
    ];
    assert_eq!(
        rejected(&entries),
        vec![1],
        "a transaction that looked up an index value another member of its batch \
         claims must be rejected, or the uniqueness it verified is violated by the \
         pair of them"
    );
}

/// Both sides of a move, because removing a primary key from one index value
/// changes the answer to a lookup of THAT value just as much as adding it
/// changes the answer for the new one.
#[test]
fn vacating_an_index_value_conflicts_with_a_lookup_of_the_old_value() {
    let move_away = IndexUpdate {
        index: b"email".to_vec(),
        primary_key: b"users/first".to_vec(),
        old_value: Some(b"old@example.com".to_vec()),
        new_value: Some(b"new@example.com".to_vec()),
    };
    let entries = vec![
        check(0, &[], &[b"users/first"], &[], vec![move_away]),
        check(
            1,
            &[],
            &[b"audit"],
            &[(b"email", b"old@example.com")],
            Vec::new(),
        ),
    ];
    assert_eq!(
        rejected(&entries),
        vec![1],
        "a lookup of the index value an earlier batch member VACATED is stale too; \
         only checking the new value would miss half of every move"
    );
}

/// An index read of an untouched value must still pass, or the check would
/// reject every transaction that consults any index at all.
#[test]
fn an_index_lookup_of_an_untouched_value_does_not_conflict() {
    let claim = IndexUpdate {
        index: b"email".to_vec(),
        primary_key: b"users/first".to_vec(),
        old_value: None,
        new_value: Some(b"a@example.com".to_vec()),
    };
    let entries = vec![
        check(0, &[], &[b"users/first"], &[], vec![claim]),
        check(
            1,
            &[],
            &[b"audit"],
            &[(b"email", b"someone-else@example.com")],
            Vec::new(),
        ),
    ];
    assert!(
        rejected(&entries).is_empty(),
        "an index lookup of a value nothing in the batch touched is not a conflict"
    );
}

/// A rejected transaction must not invalidate the ones after it: it does not
/// commit, so its writes never happen and cannot have been read.
#[test]
fn a_rejected_transaction_does_not_reject_the_ones_after_it() {
    let entries = vec![
        BatchEntry::Plain {
            key: b"balance".to_vec(),
        },
        // Rejected: read a key the plain write above overwrites.
        check(1, &[b"balance"], &[b"doomed"], &[], Vec::new()),
        // Reads only what the rejected transaction would have written.
        check(2, &[b"doomed"], &[b"fine"], &[], Vec::new()),
    ];
    assert_eq!(
        rejected(&entries),
        vec![1],
        "a transaction reading a key that only a REJECTED transaction would have \
         written must commit: that write never happened"
    );
}

/// A scanned range is checked against the batch's own writes, because a key
/// appearing inside it is a phantom whether the write that created it is
/// already committed or merely earlier in the same batch.
#[test]
fn a_batch_write_inside_a_scanned_range_is_a_phantom() {
    let mut inside = check(1, &[], &[b"audit"], &[], Vec::new());
    if let BatchEntry::Transaction(check) = &mut inside {
        check.read_ranges = vec![(Some(b"users/".to_vec()), Some(b"users0".to_vec()))];
    }
    let entries = vec![
        BatchEntry::Plain {
            key: b"users/new".to_vec(),
        },
        inside,
    ];
    assert_eq!(
        rejected(&entries),
        vec![1],
        "a key written earlier in the batch inside a range this transaction \
         scanned is a phantom and must be caught"
    );

    // And a write OUTSIDE the range is not.
    let mut outside = check(1, &[], &[b"audit"], &[], Vec::new());
    if let BatchEntry::Transaction(check) = &mut outside {
        check.read_ranges = vec![(Some(b"users/".to_vec()), Some(b"users0".to_vec()))];
    }
    let entries = vec![
        BatchEntry::Plain {
            key: b"accounts/new".to_vec(),
        },
        outside,
    ];
    assert!(
        rejected(&entries).is_empty(),
        "a write outside every scanned range is not a phantom"
    );
}

/// The quantile is only worth reading if the bucket it names actually holds
/// the value, so index and lower bound have to agree in both directions.
#[test]
fn histogram_buckets_contain_the_values_indexed_into_them() {
    for nanoseconds in (0..64).chain((6..40).map(|shift| (1_u64 << shift) + 12_345)) {
        let index = Histogram::index(nanoseconds);
        assert!(
            Histogram::lower_bound(index) <= nanoseconds,
            "{nanoseconds} below the bound of bucket {index}"
        );
        assert!(
            index + 1 == Histogram::BUCKETS || nanoseconds < Histogram::lower_bound(index + 1),
            "{nanoseconds} above the bound of bucket {index}"
        );
    }
}

/// Four buckets per octave is the accuracy the stage budget is read at.
#[test]
fn histogram_quantiles_land_within_a_quarter_octave() {
    let histogram = Histogram::default();
    for micros in 1..=1_000_u64 {
        histogram.record(Duration::from_micros(micros));
    }
    for (permille, expected) in [(500_u64, 500_000_u64), (990, 990_000)] {
        let measured = histogram.quantile(permille);
        let error = measured.abs_diff(expected) as f64 / expected as f64;
        assert!(
            error < 0.10,
            "p{permille} measured {measured} against {expected}"
        );
    }
}

/// An empty stage must report zero rather than the bottom bucket, or an
/// unused path reads as a fast one.
#[test]
fn histogram_without_observations_reports_zero() {
    assert_eq!(Histogram::default().quantile(500), 0);
}

/// A one-shard server state around an already-open engine, enough for the
/// transaction path. The write channel's receiver is dropped — these tests
/// never commit through the queue.
fn transaction_test_state(engine: Engine) -> Arc<ServerState> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let (writes, _closed) = mpsc::channel(1);
    let salt = SaltString::from_b64("dGVzdHNhbHQ").unwrap();
    let hash = argon2::Argon2::default()
        .hash_password(b"pw", &salt)
        .unwrap()
        .serialize();
    Arc::new(ServerState {
        shards: vec![Shard {
            writes,
            changes: Arc::new(ChangeRing::new(4)),
            read_queues: Vec::new(),
            readers: Arc::new(Vec::new()),
            next_reader: AtomicU64::new(0),
            engine: Arc::new(RwLock::new(engine)),
            wal_directory: PathBuf::new(),
        }],
        auth: Arc::new(auth::Authenticator::single("vyrn".into(), hash)),
        audit: None,
        database: "default".into(),
        auth_limit: Arc::new(Semaphore::new(1)),
        auth_throttle: Arc::new(AuthThrottle::new()),
        write_budget: Arc::new(Semaphore::new(WRITE_QUEUE_MAX_BYTES)),
        transaction_timeout: Duration::from_secs(30),
        metrics: Arc::new(Metrics::default()),
        replication: replication::Replication::new(0, Duration::from_secs(1)),
        read_only: false,
        failover: None,
    })
}

#[tokio::test]
async fn transaction_reads_persisted_snapshot_and_its_writes() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"a".to_vec(), b"old".to_vec()).unwrap();
    engine.put(b"b".to_vec(), b"two".to_vec()).unwrap();
    let sequence = engine.register_snapshot();
    engine.put(b"a".to_vec(), b"current".to_vec()).unwrap();
    let state = transaction_test_state(engine);
    let mut transaction = ConnectionTransaction {
        sequences: vec![sequence],
        shard: None,
        started: tokio::time::Instant::now(),
        read_keys: BTreeMap::new(),
        read_ranges: Vec::new(),
        index_reads: Vec::new(),
        writes: BTreeMap::new(),
        index_updates: Vec::new(),
    };
    assert_eq!(
        execute_transaction(
            &state,
            &mut transaction,
            Message::Get { key: b"a".to_vec() }
        )
        .await,
        Message::Value {
            value: Some(b"old".to_vec())
        }
    );
    assert_eq!(
        execute_transaction(
            &state,
            &mut transaction,
            Message::Put {
                key: b"a".to_vec(),
                value: b"new".to_vec()
            }
        )
        .await,
        Message::Written
    );
    assert_eq!(
        execute_transaction(
            &state,
            &mut transaction,
            Message::Get { key: b"a".to_vec() }
        )
        .await,
        Message::Value {
            value: Some(b"new".to_vec())
        }
    );
    assert_eq!(
        execute_transaction(
            &state,
            &mut transaction,
            Message::Delete { key: b"b".to_vec() }
        )
        .await,
        Message::Deleted { existed: true }
    );
    assert_eq!(
        execute_transaction(
            &state,
            &mut transaction,
            Message::Get { key: b"b".to_vec() }
        )
        .await,
        Message::Value { value: None }
    );
    assert_eq!(
        execute_transaction(
            &state,
            &mut transaction,
            Message::Scan {
                start: None,
                end: None,
                limit: 10
            }
        )
        .await,
        Message::Rows {
            rows: vec![(b"a".to_vec(), b"new".to_vec())]
        }
    );
}

#[test]
fn conflict_detection_only_rejects_keys_changed_after_snapshot() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"b".to_vec(), b"old".to_vec()).unwrap();
    let snapshot = engine.sequence();
    engine.put(b"a".to_vec(), b"new".to_vec()).unwrap();
    assert!(has_conflict(
        &engine,
        snapshot,
        &[],
        &[],
        &[],
        &[BatchOperation::Put(b"a".to_vec(), b"new".to_vec())],
        &[]
    )
    .unwrap());
    assert!(!has_conflict(
        &engine,
        snapshot,
        &[],
        &[],
        &[],
        &[BatchOperation::Delete(b"b".to_vec())],
        &[]
    )
    .unwrap());
    assert!(!has_conflict(
        &engine,
        snapshot,
        &[],
        &[],
        &[],
        &[BatchOperation::Put(b"c".to_vec(), b"new".to_vec())],
        &[]
    )
    .unwrap());
}

#[test]
fn serializable_conflicts_cover_reads_and_phantoms() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.create_index(b"tag".to_vec(), false).unwrap();
    let snapshot = engine.sequence();
    engine
        .write_indexed(
            vec![
                BatchOperation::Put(b"account/a".to_vec(), b"1".to_vec()),
                BatchOperation::Put(b"users/new".to_vec(), b"1".to_vec()),
            ],
            vec![IndexUpdate {
                index: b"tag".to_vec(),
                primary_key: b"users/new".to_vec(),
                old_value: None,
                new_value: Some(b"admin".to_vec()),
            }],
        )
        .unwrap();
    assert!(has_conflict(
        &engine,
        snapshot,
        &[b"account/a".to_vec()],
        &[],
        &[],
        &[BatchOperation::Put(b"account/b".to_vec(), b"1".to_vec())],
        &[]
    )
    .unwrap());
    assert!(has_conflict(
        &engine,
        snapshot,
        &[],
        &[(Some(b"users/".to_vec()), Some(b"users0".to_vec()))],
        &[],
        &[BatchOperation::Put(b"audit".to_vec(), b"1".to_vec())],
        &[]
    )
    .unwrap());
    assert!(has_conflict(
        &engine,
        snapshot,
        &[],
        &[],
        &[(b"tag".to_vec(), b"admin".to_vec())],
        &[BatchOperation::Put(b"audit".to_vec(), b"1".to_vec())],
        &[]
    )
    .unwrap());
    assert!(!has_conflict(
        &engine,
        engine.sequence(),
        &[b"account/a".to_vec()],
        &[(Some(b"users/".to_vec()), Some(b"users0".to_vec()))],
        &[(b"tag".to_vec(), b"admin".to_vec())],
        &[BatchOperation::Put(b"audit".to_vec(), b"1".to_vec())],
        &[]
    )
    .unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn generated_serializable_histories_detect_stale_reads_and_phantoms(
        suffix in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        let snapshot = engine.sequence();
        let mut point_key = b"point/".to_vec();
        point_key.extend_from_slice(&suffix);
        let mut range_key = b"range/".to_vec();
        range_key.extend_from_slice(&suffix);
        engine.put(point_key.clone(), b"point".to_vec()).unwrap();
        engine.put(range_key, b"range".to_vec()).unwrap();
        prop_assert!(has_conflict(
            &engine,
            snapshot,
            std::slice::from_ref(&point_key),
            &[],
            &[],
            &[BatchOperation::Put(b"other".to_vec(), b"value".to_vec())],
            &[],
        ).unwrap());
        prop_assert!(has_conflict(
            &engine,
            snapshot,
            &[],
            &[(Some(b"range/".to_vec()), Some(b"range0".to_vec()))],
            &[],
            &[BatchOperation::Put(b"other".to_vec(), b"value".to_vec())],
            &[],
        ).unwrap());
        prop_assert!(!has_conflict(
            &engine,
            engine.sequence(),
            std::slice::from_ref(&point_key),
            &[(Some(b"range/".to_vec()), Some(b"range0".to_vec()))],
            &[],
            &[BatchOperation::Put(b"other".to_vec(), b"value".to_vec())],
            &[],
        ).unwrap());
    }
}
