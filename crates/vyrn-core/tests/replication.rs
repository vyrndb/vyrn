//! Replica-side record validation.
//!
//! No sockets: these feed bytes straight into the validation path, which is
//! where the correctness of replication actually lives. If a malformed record
//! can reach a replica's WAL, no amount of network testing saves it — the
//! replica's own recovery would later refuse to open its log, turning a
//! detectable stream fault into an undetectable corrupt replica.
//!
//! The records here are produced by a real `Engine`, not hand-assembled, so the
//! bytes under test are exactly what a primary would send.

use std::sync::{Arc, Mutex};
use vyrn_core::replication::{check_contiguous, check_join, verify_record, Divergence};
use vyrn_core::{Engine, EngineOptions, Error, RecordSink};

/// Captures records as the engine appends them, standing in for the primary's
/// replication fan-out.
#[derive(Debug, Default)]
struct Captured {
    records: Mutex<Vec<(u64, Vec<u8>)>>,
}

impl RecordSink for Captured {
    fn record(&self, lsn: u64, record: &[u8]) {
        self.records
            .const_lock()
            .push((lsn, record.to_vec()));
    }
}

impl Captured {
    fn take(&self) -> Vec<(u64, Vec<u8>)> {
        std::mem::take(&mut *self.records.const_lock())
    }
}

/// Small helper so a poisoned mutex fails the test rather than being unwrapped
/// in four places.
trait ConstLock<T> {
    fn const_lock(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> ConstLock<T> for Mutex<T> {
    fn const_lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().expect("capture mutex poisoned")
    }
}

/// Opens an engine whose records are captured, and writes `count` keys.
fn records_from_writes(count: usize) -> Vec<(u64, Vec<u8>)> {
    let directory = tempfile::tempdir().expect("tempdir");
    let captured = Arc::new(Captured::default());
    let mut engine = Engine::open_with_options(
        directory.path(),
        EngineOptions {
            record_sink: Some(captured.clone()),
            ..EngineOptions::default()
        },
    )
    .expect("open engine");

    for index in 0..count {
        engine
            .put(
                format!("users/{index}").into_bytes(),
                format!("value-{index}").into_bytes(),
            )
            .expect("put");
    }
    captured.take()
}

#[test]
fn the_sink_observes_every_commit_in_order() {
    let records = records_from_writes(5);
    assert_eq!(records.len(), 5, "one record per commit");

    // LSNs must be contiguous and ascending from 1: a replica joins by LSN, so a
    // gap or a repeat here would be unrecoverable downstream.
    let lsns: Vec<u64> = records.iter().map(|(lsn, _)| *lsn).collect();
    assert_eq!(lsns, vec![1, 2, 3, 4, 5], "LSNs are contiguous from 1");
}

#[test]
fn a_real_record_passes_validation_and_reports_its_lsn() {
    for (lsn, record) in records_from_writes(3) {
        let header = verify_record(&record).expect("engine-produced record must validate");
        assert_eq!(header.lsn, lsn, "header LSN matches the sink's LSN");
        assert_eq!(
            header.total_len,
            record.len(),
            "declared length covers the whole record"
        );
        assert!(header.operation_count >= 1);
    }
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let (_, record) = records_from_writes(1).remove(0);

    // Exhaustive over the framed region rather than sampled: the checksum covers
    // specific fields, and a flip in a byte that is read but not checksummed
    // (a length, the footer) would slip through a spot check. This is the whole
    // point of validating on the replica.
    let mut accepted = Vec::new();
    for index in 0..record.len() {
        for bit in 0..8 {
            let mut damaged = record.clone();
            damaged[index] ^= 1 << bit;
            if damaged == record {
                continue;
            }
            if verify_record(&damaged).is_ok() {
                accepted.push((index, bit));
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "these single-bit flips were accepted as valid records: {accepted:?}"
    );
}

#[test]
fn a_version_mismatch_is_not_reported_as_corruption() {
    let (_, mut record) = records_from_writes(1).remove(0);
    // Byte 4 is the format version. A record from another build is intact data
    // this build cannot read; calling that corruption would invite an operator to
    // "repair" a healthy stream.
    record[4] = record[4].wrapping_add(1);

    match verify_record(&record) {
        Err(Error::FormatVersion { structure, .. }) => {
            assert_eq!(structure, "replicated WAL record");
        }
        other => panic!("expected FormatVersion, got {other:?}"),
    }
}

#[test]
fn truncation_at_every_length_is_rejected() {
    let (_, record) = records_from_writes(1).remove(0);
    for length in 0..record.len() {
        assert!(
            verify_record(&record[..length]).is_err(),
            "a record truncated to {length} of {} bytes was accepted",
            record.len()
        );
    }
    // The untruncated record is the one case that must pass, which also proves
    // the loop above is not vacuously true.
    assert!(verify_record(&record).is_ok());
}

#[test]
fn trailing_bytes_are_rejected() {
    let (_, record) = records_from_writes(1).remove(0);
    let mut padded = record.clone();
    padded.push(0);
    assert!(
        verify_record(&padded).is_err(),
        "a record with a trailing byte must not be accepted; appending it would \
         write bytes the sender did not intend as one record"
    );
}

#[test]
fn a_replica_ahead_of_its_primary_is_refused() {
    // Streaming cannot reconcile this: the primary has nothing to send that would
    // explain the replica's extra records.
    assert_eq!(
        check_join(50, 10, 11),
        Some(Divergence::ReplicaAhead {
            replica_lsn: 50,
            primary_lsn: 10
        })
    );
}

#[test]
fn a_gap_before_the_stream_is_refused() {
    // The primary starts at 100 but this replica ends at 10, so records 11..=99
    // are missing and must come from the archive first.
    assert_eq!(
        check_join(10, 200, 100),
        Some(Divergence::GapBeforeStream {
            replica_lsn: 10,
            first_lsn: 100
        })
    );
}

#[test]
fn an_abutting_stream_is_accepted() {
    assert_eq!(check_join(10, 200, 11), None, "starts at the next record");
    assert_eq!(check_join(0, 200, 1), None, "empty replica joins at LSN 1");
    // Overlap is fine — a reconnecting primary may resend what the replica has.
    assert_eq!(check_join(10, 200, 5), None, "resends are not a divergence");
}

#[test]
fn duplicate_records_are_skipped_rather_than_failing() {
    // A reconnect can legitimately resend records the replica already has.
    // Treating those as an error would make reconnection impossible.
    assert_eq!(check_contiguous(10, 11), Ok(true), "the next record applies");
    assert_eq!(check_contiguous(10, 10), Ok(false), "a duplicate is skipped");
    assert_eq!(check_contiguous(10, 1), Ok(false), "an old record is skipped");
    assert_eq!(
        check_contiguous(10, 12),
        Err(Divergence::NonContiguous {
            expected: 11,
            received: 12
        }),
        "a gap is a hard error, not something to apply over"
    );
}

#[test]
fn an_empty_or_header_only_record_is_rejected() {
    assert!(verify_record(&[]).is_err());
    assert!(verify_record(&[0; 44]).is_err());
    assert!(verify_record(&[0; 45]).is_err(), "zeroed header is not valid");
}

/// The property the whole design rests on: a replica that applies a primary's
/// records ends up with the same data AND the same LSN, so it is a usable
/// substitute after a promotion.
#[test]
fn a_replica_applying_records_matches_its_primary() {
    // Primary: a mix of puts and a delete, so tombstone handling is exercised
    // rather than just the happy insert path.
    let primary_dir = tempfile::tempdir().expect("tempdir");
    let captured = Arc::new(Captured::default());
    let mut primary = Engine::open_with_options(
        primary_dir.path(),
        EngineOptions {
            record_sink: Some(captured.clone()),
            ..EngineOptions::default()
        },
    )
    .expect("open primary");

    primary.put(b"a".to_vec(), b"1".to_vec()).expect("put a");
    primary.put(b"b".to_vec(), b"2".to_vec()).expect("put b");
    primary.delete(b"a").expect("delete a");
    primary.put(b"c".to_vec(), b"3".to_vec()).expect("put c");
    // Overwrite, which must clear the tombstone left by the delete above.
    primary.put(b"a".to_vec(), b"4".to_vec()).expect("re-put a");

    let records = captured.take();
    assert_eq!(records.len(), 5);

    // Replica: apply the same records in order.
    let replica_dir = tempfile::tempdir().expect("tempdir");
    let mut replica = Engine::open(replica_dir.path()).expect("open replica");
    for (_, record) in &records {
        verify_record(record).expect("record validates");
        replica
            .apply_replicated_record(record)
            .expect("record applies");
    }

    assert_eq!(
        replica.last_lsn(),
        primary.last_lsn(),
        "replica must adopt the primary's LSN, not generate its own"
    );
    for key in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
        assert_eq!(
            replica.get(key).expect("replica get"),
            primary.get(key).expect("primary get"),
            "value for {:?} differs between primary and replica",
            String::from_utf8_lossy(key)
        );
    }
    assert_eq!(
        replica.len(),
        primary.len(),
        "entry counts differ, so the tombstone bookkeeping diverged"
    );
}

#[test]
fn applying_a_record_out_of_order_is_refused() {
    let records = records_from_writes(3);
    let replica_dir = tempfile::tempdir().expect("tempdir");
    let mut replica = Engine::open(replica_dir.path()).expect("open replica");

    // Skipping LSN 1 must fail rather than leave a hole: a WAL with a gap is one
    // its own recovery refuses to open.
    let (_, second) = &records[1];
    let error = replica
        .apply_replicated_record(second)
        .expect_err("a gap must be refused");
    match error {
        Error::InvalidReplicatedRecord { reason } => {
            assert!(
                reason.contains("does not follow"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected InvalidReplicatedRecord, got {other:?}"),
    }

    // In order, it applies.
    let (_, first) = &records[0];
    replica
        .apply_replicated_record(first)
        .expect("the first record applies");
}

#[test]
fn the_sink_is_absent_by_default() {
    // The default path must be untouched when replication is off: no sink means
    // the commit path is exactly what it was before this feature existed.
    let options = EngineOptions::default();
    assert!(
        options.record_sink.is_none(),
        "replication must be opt-in, or every existing deployment changes behaviour"
    );
}
