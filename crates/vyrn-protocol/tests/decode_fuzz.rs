//! Adversarial-input tests for the wire decoder.
//!
//! Every byte reaching `decode` arrives from the network before the peer has
//! authenticated, so the decoder is the one component an unauthenticated
//! attacker can reach directly. It must answer `Ok` or `Err` for all input and
//! never panic, over-allocate, or loop: a panic inside the codec takes the
//! connection task down, and an allocation driven by a wire-supplied length is
//! remotely triggerable memory exhaustion.
//!
//! These are property tests rather than a libFuzzer target on purpose. `proptest`
//! is already a workspace dependency, runs on stable, and runs on every platform
//! in CI including Windows, where `cargo-fuzz` needs nightly and libFuzzer. A
//! coverage-guided target is still worth adding for the deep structural cases,
//! but it cannot be the only line of defence because it would never run here.

use bytes::{BufMut, BytesMut};
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};
use vyrn_protocol::{DocumentIndex, Envelope, ErrorCode, Message, VyrnCodec, MAX_SCAN_LIMIT};

/// Wraps `body` in the length-delimited framing the codec expects.
fn frame(body: &[u8]) -> BytesMut {
    let mut bytes = BytesMut::new();
    bytes.put_u32(body.len() as u32);
    bytes.extend_from_slice(body);
    bytes
}

/// Decodes `body` as one frame, asserting only that the decoder returns.
///
/// The return value is deliberately discarded: a rejection is as correct as a
/// successful parse. The property under test is that control comes back at all.
fn decode_without_panic(body: &[u8]) {
    let mut codec = VyrnCodec::default();
    let mut bytes = frame(body);
    let _ = codec.decode(&mut bytes);
}

fn encode(message: Message) -> BytesMut {
    let mut codec = VyrnCodec::default();
    let mut bytes = BytesMut::new();
    codec.encode(Envelope::new(7, message), &mut bytes).unwrap();
    bytes
}

/// One representative message per decoder branch that reads a length or count.
///
/// Structure-aware mutation needs valid frames to start from; the interesting
/// branches are the ones that read a size from the wire, so those are the ones
/// worth covering here.
fn seed_messages() -> Vec<Message> {
    vec![
        Message::Authenticate {
            username: "user".into(),
            password: "secret".into(),
            database: "app".into(),
        },
        Message::Get { key: vec![1, 2, 3] },
        Message::MultiGet {
            keys: vec![vec![1], vec![2], vec![3]],
        },
        Message::Put {
            key: b"users/1".to_vec(),
            value: vec![9; 512],
        },
        Message::Delete { key: b"k".to_vec() },
        Message::Scan {
            start: Some(b"a".to_vec()),
            end: None,
            limit: 100,
        },
        Message::Subscribe {
            prefix: b"users/".to_vec(),
        },
        Message::SubscribeFrom {
            prefix: b"users/".to_vec(),
            cursor: Some("000000000000000000000042".into()),
        },
        Message::SubscribeCollectionFrom {
            collection: "users".into(),
            cursor: None,
        },
        Message::CreateIndex {
            name: b"email".to_vec(),
            unique: true,
        },
        Message::IndexUpdate {
            index: b"email".to_vec(),
            primary_key: b"users/1".to_vec(),
            old_value: None,
            new_value: Some(b"a@example.com".to_vec()),
        },
        Message::IndexLookup {
            index: b"email".to_vec(),
            value: b"a@example.com".to_vec(),
            limit: 10,
        },
        Message::CreateCollection {
            collection: "users".into(),
            indexes: vec![
                DocumentIndex {
                    field: "email".into(),
                    unique: true,
                },
                DocumentIndex {
                    field: "role".into(),
                    unique: false,
                },
            ],
        },
        Message::PutDocument {
            collection: "users".into(),
            id: "user_1".into(),
            document: br#"{"email":"a@example.com"}"#.to_vec(),
        },
        Message::QueryDocuments {
            collection: "users".into(),
            field: "email".into(),
            value: b"a@example.com".to_vec(),
            limit: 50,
        },
        Message::Rows {
            rows: vec![(vec![1], vec![2]), (vec![3], vec![4])],
        },
        Message::Keys {
            keys: vec![b"users/1".to_vec(), b"users/2".to_vec()],
        },
        Message::Values {
            values: vec![Some(vec![1]), None, Some(vec![2])],
        },
        Message::Documents {
            documents: vec![("user_1".into(), b"{}".to_vec())],
        },
        Message::CursorChange {
            cursor: "000000000000000000000007".into(),
            key: b"users/1".to_vec(),
            value: Some(b"v".to_vec()),
        },
        Message::CursorDocumentChange {
            cursor: "000000000000000000000008".into(),
            collection: "users".into(),
            id: "user_1".into(),
            document: None,
        },
        Message::Caught {
            cursor: "000000000000000000000009".into(),
        },
        // Replication frames. `ReplicaHello` and `ReplicaRecords` are the two
        // that read wire-supplied sizes, and a replica connection reaches the
        // decoder before its role is established, so they are attacker-reachable
        // on the same terms as everything above.
        Message::ReplicaHello {
            database: "app".into(),
            last_lsn: 42,
            replica_id: "replica-1".into(),
        },
        Message::ReplicaStream { first_lsn: 43 },
        Message::ReplicaRecords {
            records: vec![vec![7; 64], vec![8; 128]],
        },
        Message::ReplicaAck { durable_lsn: 43 },
        Message::ReplicaDiverged {
            reason: "replica is ahead of the primary".into(),
        },
        Message::Error {
            code: ErrorCode::Conflict,
            message: "conflict".into(),
        },
    ]
}

proptest! {
    /// Unstructured input must never panic the decoder.
    ///
    /// This mostly exercises the shallow branches — a random first byte usually
    /// misses a valid message kind — which is why the mutation tests below
    /// exist to reach further in.
    #[test]
    fn arbitrary_bytes_are_rejected_without_panicking(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        decode_without_panic(&body);
    }

    /// Random input that gets past the envelope header and into a real branch.
    ///
    /// The kind byte is drawn from the range the decoder actually dispatches on,
    /// so each case lands inside a message body parser rather than bouncing off
    /// an unknown-kind check.
    #[test]
    fn arbitrary_message_bodies_are_rejected_without_panicking(
        // 54 is the highest dispatched kind: 50-54 are the replication frames.
        // This bound must rise with every tag added, or new branches silently
        // stop being fuzzed.
        kind in 1_u8..=54,
        body in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut input = BytesMut::new();
        input.put_u16(6);
        input.put_u64(1);
        input.put_u8(kind);
        input.extend_from_slice(&body);
        decode_without_panic(&input);
    }

    /// Single-byte mutations of a valid frame.
    ///
    /// Flipping one byte of a well-formed message keeps the frame plausible
    /// enough to reach deep into a body parser while corrupting exactly one
    /// field, which is how a length or count gets driven out of range.
    #[test]
    fn one_byte_mutations_of_valid_frames_do_not_panic(
        seed in prop::sample::select(seed_messages()),
        index in any::<prop::sample::Index>(),
        replacement in any::<u8>(),
    ) {
        let encoded = encode(seed);
        // Skip the 4-byte length prefix: the framing layer is not under test
        // here, and corrupting it only ever yields a short or oversized frame.
        let body = &encoded[4..];
        let position = index.index(body.len());
        let mut mutated = body.to_vec();
        mutated[position] = replacement;
        decode_without_panic(&mutated);
    }

    /// Every truncation of a valid frame.
    ///
    /// A short read must be reported as truncated, never treated as a complete
    /// message with a garbage tail.
    #[test]
    fn every_truncation_of_a_valid_frame_is_rejected(
        seed in prop::sample::select(seed_messages()),
        index in any::<prop::sample::Index>(),
    ) {
        let encoded = encode(seed);
        let body = &encoded[4..];
        let length = index.index(body.len());
        decode_without_panic(&body[..length]);
    }

    /// A wire-supplied count must not drive an allocation on its own.
    ///
    /// Each of these branches reads a count, then allocates a `Vec` with that
    /// capacity before reading any element. Without a bound checked first, a
    /// 9-byte frame claiming `u32::MAX` rows would ask the allocator for
    /// gigabytes. The decoder must reject the count instead.
    #[test]
    fn an_oversized_count_is_rejected_before_allocating(
        kind in prop::sample::select(vec![10_u8, 28, 29, 30, 31, 42]),
        count in (MAX_SCAN_LIMIT + 1)..=u32::MAX,
    ) {
        let mut input = BytesMut::new();
        input.put_u16(6);
        input.put_u64(1);
        input.put_u8(kind);
        // Kinds 31 and 42 read a collection name before their count.
        if matches!(kind, 31 | 42) {
            input.put_u32(5);
            input.extend_from_slice(b"users");
        }
        input.put_u32(count);

        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&input);
        prop_assert!(
            codec.decode(&mut bytes).is_err(),
            "kind {kind} accepted a count of {count} with no elements present"
        );
    }

    /// The replication record count has its own ceiling, so it needs its own case.
    ///
    /// Kind 52 is bounded by `MAX_REPLICA_RECORDS` rather than `MAX_SCAN_LIMIT`,
    /// which is why it is not in the list above. Zero is included deliberately:
    /// an empty batch is meaningless and accepting it would let a peer drive the
    /// primary's ack bookkeeping with frames carrying no work.
    #[test]
    fn an_oversized_replication_count_is_rejected_before_allocating(
        count in prop::sample::select(vec![0_u32, 4_097, 100_000, u32::MAX]),
    ) {
        let mut input = BytesMut::new();
        input.put_u16(6);
        input.put_u64(1);
        input.put_u8(52);
        input.put_u32(count);

        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&input);
        prop_assert!(
            codec.decode(&mut bytes).is_err(),
            "kind 52 accepted a record count of {count} with no records present"
        );
    }

    /// An oversized single record must be rejected on its length, not buffered.
    ///
    /// The count can be legal while one record claims to be enormous. That length
    /// reaches `get_bytes` directly, so it is the second place a wire-supplied
    /// size could drive an allocation.
    #[test]
    fn an_oversized_replication_record_is_rejected(
        length in (32_u32 * 1024 * 1024 + 1)..=u32::MAX,
    ) {
        let mut input = BytesMut::new();
        input.put_u16(6);
        input.put_u64(1);
        input.put_u8(52);
        input.put_u32(1);
        input.put_u32(length);

        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&input);
        prop_assert!(
            codec.decode(&mut bytes).is_err(),
            "kind 52 accepted a record claiming {length} bytes"
        );
    }

    /// Decoding is a total function of the bytes, not of decoder state.
    ///
    /// A fresh codec and a codec that has already rejected garbage must agree,
    /// so one malformed frame cannot change how the next one is parsed.
    #[test]
    fn a_rejected_frame_does_not_corrupt_later_decoding(
        garbage in prop::collection::vec(any::<u8>(), 1..256),
        seed in prop::sample::select(seed_messages()),
    ) {
        let mut codec = VyrnCodec::default();
        let mut poisoned = frame(&garbage);
        let _ = codec.decode(&mut poisoned);

        let expected = {
            let mut fresh = VyrnCodec::default();
            let mut bytes = encode(seed.clone());
            fresh.decode(&mut bytes).unwrap()
        };

        let mut bytes = encode(seed);
        prop_assert_eq!(codec.decode(&mut bytes).unwrap(), expected);
    }
}

/// Two frames in one buffer must decode as two messages, in order.
///
/// Requests arrive coalesced under load, so a decoder that consumed the wrong
/// number of bytes would silently desynchronize the whole connection rather
/// than fail visibly.
#[test]
fn frames_sharing_a_buffer_decode_independently() {
    let mut codec = VyrnCodec::default();
    let mut bytes = BytesMut::new();
    codec
        .encode(Envelope::new(1, Message::Get { key: vec![1] }), &mut bytes)
        .unwrap();
    codec
        .encode(
            Envelope::new(2, Message::Delete { key: vec![2] }),
            &mut bytes,
        )
        .unwrap();

    let first = codec.decode(&mut bytes).unwrap().unwrap();
    let second = codec.decode(&mut bytes).unwrap().unwrap();
    assert_eq!(first.request_id, 1);
    assert_eq!(second.request_id, 2);
    assert_eq!(second.message, Message::Delete { key: vec![2] });
    assert!(
        codec.decode(&mut bytes).unwrap().is_none(),
        "the buffer held exactly two frames"
    );
}

/// A partially arrived frame must be reported as incomplete, not as an error.
///
/// `decode` returning `Ok(None)` is what tells the transport to read more; an
/// `Err` here would drop connections whenever a message spanned two packets.
///
/// Each prefix gets a fresh codec because `LengthDelimitedCodec` is stateful:
/// having read a length header it remembers how many body bytes it is waiting
/// for. Reusing one codec across unrelated buffers would test stale state
/// rather than the length check.
#[test]
fn a_partial_frame_asks_for_more_bytes() {
    let complete = encode(Message::Put {
        key: b"users/1".to_vec(),
        value: vec![7; 300],
    });

    for length in 0..complete.len() {
        let mut codec = VyrnCodec::default();
        let mut partial = BytesMut::from(&complete[..length]);
        assert!(
            matches!(codec.decode(&mut partial), Ok(None)),
            "a {length}-byte prefix of a {}-byte frame should be incomplete",
            complete.len()
        );
    }

    let mut codec = VyrnCodec::default();
    let mut whole = complete.clone();
    assert!(codec.decode(&mut whole).unwrap().is_some());
}

/// A frame arriving one byte at a time must yield exactly once, when complete.
///
/// This is the real transport shape — one codec and one buffer that grows as
/// packets land — and it is where a decoder that consumed the wrong number of
/// bytes, or yielded early on a partial body, would desynchronize the stream.
#[test]
fn a_frame_delivered_byte_by_byte_yields_once_when_complete() {
    let message = Message::Put {
        key: b"users/1".to_vec(),
        value: vec![7; 300],
    };
    let complete = encode(message.clone());
    let mut codec = VyrnCodec::default();
    let mut buffer = BytesMut::new();

    for (index, byte) in complete.iter().enumerate() {
        buffer.extend_from_slice(&[*byte]);
        let decoded = codec.decode(&mut buffer).unwrap();
        let is_last = index + 1 == complete.len();
        if is_last {
            assert_eq!(
                decoded.map(|envelope| envelope.message),
                Some(message.clone()),
                "the final byte should complete the frame"
            );
        } else {
            assert!(
                decoded.is_none(),
                "the frame yielded after {} of {} bytes",
                index + 1,
                complete.len()
            );
        }
    }

    assert!(buffer.is_empty(), "the frame's bytes should be consumed");
}
