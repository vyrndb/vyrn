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
use vyrn_protocol::{
    CodecError, DocumentIndex, Envelope, ErrorCode, Message, VyrnCodec, MAX_SCAN_LIMIT,
    PROTOCOL_VERSION,
};

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
        // The remaining document kinds also read names, ids or counts from the
        // wire; without seeds here the mutation and truncation tests below
        // would never reach those branches.
        Message::GetDocument {
            collection: "users".into(),
            id: "user_1".into(),
        },
        Message::DeleteDocument {
            collection: "users".into(),
            id: "user_1".into(),
        },
        Message::ListDocuments {
            collection: "users".into(),
            limit: 25,
        },
        Message::SubscribeCollection {
            collection: "users".into(),
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
        Message::DocumentChange {
            sequence: 9,
            id: "user_1".into(),
            document: Some(b"{}".to_vec()),
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
        input.put_u16(PROTOCOL_VERSION);
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
        // Skip the 2 version bytes too: the decoder refuses a foreign version
        // outright before looking at the body (the dedicated tests cover that),
        // so mutating them proves nothing about the parsers underneath.
        let body = &encoded[4 + 2..];
        let position = index.index(body.len());
        let mut mutated = body.to_vec();
        mutated[position] = replacement;
        decode_without_panic(&mutated);
    }

    /// Every truncation of a valid frame must be reported as truncated.
    ///
    /// A short read must never be treated as a complete message with a garbage
    /// tail. The slice is reframed with a matching length prefix, so the framing
    /// layer sees a whole frame and the rejection must come from the body
    /// parser catching the mid-field cut. All seeds are ASCII, which keeps the
    /// assertion exact: a cut can never land inside a multi-byte character and
    /// masquerade as invalid UTF-8 instead of truncation.
    #[test]
    fn every_truncation_of_a_valid_frame_is_rejected(
        seed in prop::sample::select(seed_messages()),
        index in any::<prop::sample::Index>(),
    ) {
        let encoded = encode(seed.clone());
        let body = &encoded[4..];
        let length = index.index(body.len());
        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&body[..length]);
        let result = codec.decode(&mut bytes);
        prop_assert!(
            matches!(
                result,
                Err(CodecError::Malformed("truncated message"))
            ),
            "a {length}-byte prefix of a {}-byte {seed:?} decoded as {result:?}",
            body.len()
        );
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
        // The first branch pins the smallest rejected value: a range alone would
        // generate it with probability zero, yet that exact boundary is the one
        // an off-by-one in the decoder's check would let through.
        count in prop_oneof![
            Just(MAX_SCAN_LIMIT + 1),
            (MAX_SCAN_LIMIT + 1)..=u32::MAX,
        ],
    ) {
        let mut input = BytesMut::new();
        input.put_u16(PROTOCOL_VERSION);
        input.put_u64(1);
        input.put_u8(kind);
        // Only CreateCollection (31) reads a collection name before its count;
        // Documents (42) goes straight to the count despite carrying names per
        // element.
        if kind == 31 {
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

/// A frame carrying bytes beyond the message it declares must be refused.
///
/// After a message parses, the decoder must have consumed the frame exactly.
/// Leftovers mean the sender's framing disagrees with ours about where the
/// message ends; ignoring them would let one connection desynchronize silently
/// instead of failing visibly. The extra byte is placed inside the frame (the
/// length prefix counts it), which is the only placement that exercises this.
#[test]
fn trailing_bytes_after_a_complete_message_are_rejected() {
    let encoded = encode(Message::Get { key: vec![1] });
    let body = &encoded[4..];
    let mut padded = Vec::with_capacity(body.len() + 1);
    padded.extend_from_slice(body);
    padded.push(0);

    let mut codec = VyrnCodec::default();
    let mut bytes = frame(&padded);
    assert!(matches!(
        codec.decode(&mut bytes),
        Err(CodecError::Malformed("trailing bytes"))
    ));
}

/// Builds one envelope body for `kind` declaring `count` elements.
///
/// `element` is the shortest legal encoding of one element (`None` skips them
/// entirely, which is enough for the rejected cases: the count is checked
/// before any element is read). Only kind 31 reads a collection name ahead of
/// its count; Documents (42) carries no name, and feeding it one would shift
/// every later field rather than exercise the count check.
fn counted_body(kind: u8, count: u32, element: Option<&[u8]>) -> BytesMut {
    let mut input = BytesMut::new();
    input.put_u16(PROTOCOL_VERSION);
    input.put_u64(1);
    input.put_u8(kind);
    if kind == 31 {
        input.put_u32(5);
        input.extend_from_slice(b"users");
    }
    input.put_u32(count);
    for _ in 0..count {
        input.extend_from_slice(element.unwrap_or(&[]));
    }
    input
}

/// The shortest legal element for each count-bearing kind.
fn smallest_element(kind: u8) -> &'static [u8] {
    match kind {
        // A row is a key and a value; a document is an id and a body.
        10 | 42 => &[0, 0, 0, 0, 0, 0, 0, 0],
        // An optional value carries only its presence byte when absent.
        30 => &[0],
        // Keys are single length-prefixed fields.
        _ => &[0, 0, 0, 0],
    }
}

/// Zero is a legal count for every collection kind.
///
/// An empty result answers itself and must not cost the sender its connection;
/// multi-get (29) is included deliberately, because the decoder used to be the
/// one branch that refused emptiness even though the encoder allowed it.
#[test]
fn counts_of_zero_are_accepted_for_every_collection_kind() {
    for (kind, empty) in [
        (10_u8, Message::Rows { rows: Vec::new() }),
        (28, Message::Keys { keys: Vec::new() }),
        (29, Message::MultiGet { keys: Vec::new() }),
        (30, Message::Values { values: Vec::new() }),
        (
            42,
            Message::Documents {
                documents: Vec::new(),
            },
        ),
    ] {
        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&counted_body(kind, 0, None));
        let decoded = codec
            .decode(&mut bytes)
            .unwrap_or_else(|error| panic!("kind {kind} rejected an empty collection: {error}"))
            .expect("the frame was complete");
        assert_eq!(decoded.message, empty, "kind {kind}");
    }
}

/// Counts sit exactly on their ceiling in both directions.
///
/// `MAX_SCAN_LIMIT` itself is legal — this is where a scan limit of exactly
/// [`MAX_SCAN_LIMIT`] must still work — and one more than it must be refused
/// before any element is read. The boundary value deserves its own case: a
/// range starting just above it never actually generates it.
#[test]
fn counts_exactly_at_the_scan_limit_are_accepted_and_one_more_is_not() {
    let kinds = [10_u8, 28, 29, 30, 42];

    for kind in kinds {
        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&counted_body(
            kind,
            MAX_SCAN_LIMIT,
            Some(smallest_element(kind)),
        ));
        let decoded = codec
            .decode(&mut bytes)
            .unwrap_or_else(|error| panic!("kind {kind} rejected the exact scan limit: {error}"))
            .expect("the frame was complete");
        let accepted = match decoded.message {
            Message::Rows { rows } => rows.len(),
            Message::Keys { keys } => keys.len(),
            Message::MultiGet { keys } => keys.len(),
            Message::Values { values } => values.len(),
            Message::Documents { documents } => documents.len(),
            other => panic!("kind {kind} decoded as {other:?}"),
        };
        assert_eq!(accepted, MAX_SCAN_LIMIT as usize, "kind {kind}");
    }

    for kind in kinds {
        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&counted_body(kind, MAX_SCAN_LIMIT + 1, None));
        assert!(
            codec.decode(&mut bytes).is_err(),
            "kind {kind} accepted a count one past the scan limit"
        );
    }
}

/// Cursors are bounded at exactly 64 bytes.
///
/// 64 bytes still round-trips through the encoder; 65 must be refused by the
/// decoder, and is built by hand because the encoder now rejects it locally.
#[test]
fn cursors_are_bounded_at_sixty_four_bytes() {
    let cursor = "c".repeat(64);
    let message = Message::SubscribeFrom {
        prefix: b"k".to_vec(),
        cursor: Some(cursor.clone()),
    };
    let mut codec = VyrnCodec::default();
    let mut bytes = encode(message.clone());
    assert_eq!(codec.decode(&mut bytes).unwrap().unwrap().message, message);

    let mut input = BytesMut::new();
    input.put_u16(PROTOCOL_VERSION);
    input.put_u64(1);
    input.put_u8(45); // SubscribeFrom
    input.put_u32(1);
    input.extend_from_slice(b"k");
    input.put_u8(1); // cursor present
    input.put_u32(65);
    input.extend_from_slice(&[b'c'; 65]);
    let mut codec = VyrnCodec::default();
    let mut bytes = frame(&input);
    assert!(
        matches!(
            codec.decode(&mut bytes),
            Err(CodecError::Malformed("byte field exceeds limit"))
        ),
        "a 65-byte cursor must be refused"
    );
}

/// Authentication fields are bounded at exactly 4 KiB.
#[test]
fn authentication_fields_are_bounded_at_four_kib() {
    let username = "u".repeat(4096);
    let message = Message::Authenticate {
        username: username.clone(),
        password: String::new(),
        database: String::new(),
    };
    let mut codec = VyrnCodec::default();
    let mut bytes = encode(message.clone());
    assert_eq!(codec.decode(&mut bytes).unwrap().unwrap().message, message);

    let mut input = BytesMut::new();
    input.put_u16(PROTOCOL_VERSION);
    input.put_u64(1);
    input.put_u8(1); // Authenticate, username first
    input.put_u32(4097);
    input.extend_from_slice(&[b'u'; 4097]);
    let mut codec = VyrnCodec::default();
    let mut bytes = frame(&input);
    assert!(
        matches!(
            codec.decode(&mut bytes),
            Err(CodecError::Malformed("byte field exceeds limit"))
        ),
        "a 4097-byte username must be refused"
    );
}

/// Collection names are bounded at exactly 4 KiB.
#[test]
fn document_names_are_bounded_at_four_kib() {
    let collection = "c".repeat(4096);
    let message = Message::SubscribeCollection {
        collection: collection.clone(),
    };
    let mut codec = VyrnCodec::default();
    let mut bytes = encode(message.clone());
    assert_eq!(codec.decode(&mut bytes).unwrap().unwrap().message, message);

    let mut input = BytesMut::new();
    input.put_u16(PROTOCOL_VERSION);
    input.put_u64(1);
    input.put_u8(32); // GetDocument, collection name first
    input.put_u32(4097);
    input.extend_from_slice(&[b'c'; 4097]);
    let mut codec = VyrnCodec::default();
    let mut bytes = frame(&input);
    assert!(
        matches!(
            codec.decode(&mut bytes),
            Err(CodecError::Malformed("byte field exceeds limit"))
        ),
        "a 4097-byte collection name must be refused"
    );
}

/// Error messages are bounded at exactly 64 KiB.
#[test]
fn error_messages_are_bounded_at_sixtyfour_kib() {
    let text = "m".repeat(64 * 1024);
    let message = Message::Error {
        code: ErrorCode::Internal,
        message: text.clone(),
    };
    let mut codec = VyrnCodec::default();
    let mut bytes = encode(message.clone());
    assert_eq!(codec.decode(&mut bytes).unwrap().unwrap().message, message);

    let mut input = BytesMut::new();
    input.put_u16(PROTOCOL_VERSION);
    input.put_u64(1);
    input.put_u8(11); // Error
    input.put_u8(5); // Internal
    input.put_u32((64 * 1024 + 1) as u32);
    input.extend_from_slice(&[b'm'; 64 * 1024 + 1]);
    let mut codec = VyrnCodec::default();
    let mut bytes = frame(&input);
    assert!(
        matches!(
            codec.decode(&mut bytes),
            Err(CodecError::Malformed("byte field exceeds limit"))
        ),
        "an error message one byte over 64 KiB must be refused"
    );
}

/// Invalid UTF-8 in every string-bearing kind must be named as such.
///
/// Random mutation almost never produces a well-formed frame whose only defect
/// is a broken character, so each string-bearing kind is targeted directly: one
/// byte of a known string field is replaced with `0xff`, leaving every length
/// prefix intact so the UTF-8 check is the only check that can fire.
#[test]
fn invalid_utf8_in_each_string_field_is_rejected() {
    for (seed, sentinel) in [
        (
            Message::Authenticate {
                username: "suser".into(),
                password: "spass".into(),
                database: "sdb".into(),
            },
            "suser",
        ),
        (
            Message::Error {
                code: ErrorCode::InvalidRequest,
                message: "smessage".into(),
            },
            "smessage",
        ),
        (
            Message::CreateCollection {
                collection: "scollection".into(),
                indexes: vec![DocumentIndex {
                    field: "sfield".into(),
                    unique: false,
                }],
            },
            "scollection",
        ),
        (
            Message::GetDocument {
                collection: "scollection".into(),
                id: "sid7".into(),
            },
            "scollection",
        ),
        (
            Message::PutDocument {
                collection: "scollection".into(),
                id: "sid7".into(),
                document: b"k".to_vec(),
            },
            "scollection",
        ),
        (
            Message::DeleteDocument {
                collection: "scollection".into(),
                id: "sid7".into(),
            },
            "scollection",
        ),
        (
            Message::ListDocuments {
                collection: "scollection".into(),
                limit: 5,
            },
            "scollection",
        ),
        (
            Message::QueryDocuments {
                collection: "scollection".into(),
                field: "sfield".into(),
                value: b"k".to_vec(),
                limit: 5,
            },
            "scollection",
        ),
        (
            Message::SubscribeCollection {
                collection: "scollection".into(),
            },
            "scollection",
        ),
        (
            Message::Documents {
                documents: vec![("sdocid".into(), b"k".to_vec())],
            },
            "sdocid",
        ),
        (
            Message::DocumentChange {
                sequence: 1,
                id: "sid7".into(),
                document: None,
            },
            "sid7",
        ),
        (
            Message::SubscribeFrom {
                prefix: b"k".to_vec(),
                cursor: Some("scursor7".into()),
            },
            "scursor7",
        ),
        (
            Message::SubscribeCollectionFrom {
                collection: "scollection".into(),
                cursor: Some("scursor7".into()),
            },
            "scollection",
        ),
        (
            Message::CursorChange {
                cursor: "scursor7".into(),
                key: b"k".to_vec(),
                value: None,
            },
            "scursor7",
        ),
        (
            Message::CursorDocumentChange {
                cursor: "scursor7".into(),
                collection: "scollection".into(),
                id: "sid7".into(),
                document: None,
            },
            "scursor7",
        ),
        (
            Message::Caught {
                cursor: "scursor7".into(),
            },
            "scursor7",
        ),
        (
            Message::ReplicaHello {
                database: "sdatabase".into(),
                last_lsn: 1,
                replica_id: "sreplica7".into(),
            },
            "sdatabase",
        ),
        (
            Message::ReplicaDiverged {
                reason: "sreason".into(),
            },
            "sreason",
        ),
    ] {
        let encoded = encode(seed);
        let body = &encoded[4..];
        let position = body
            .windows(sentinel.len())
            .position(|window| window == sentinel.as_bytes())
            .unwrap_or_else(|| panic!("{sentinel:?} missing from its own encoding"));
        let mut corrupted = body.to_vec();
        corrupted[position] = 0xff;

        let kind = corrupted[2 + 8];
        let mut codec = VyrnCodec::default();
        let mut bytes = frame(&corrupted);
        match codec.decode(&mut bytes) {
            Err(CodecError::Malformed("string is not UTF-8")) => {}
            other => panic!("kind {kind}: expected a UTF-8 rejection, got {other:?}"),
        }
    }
}

/// The pre-auth frame ceiling is configurable without touching the default.
///
/// An unauthenticated peer can make a server buffer up to the frame ceiling per
/// connection before presenting any credential, so a server wants a smaller
/// ceiling for the handshake. Exactly at the reduced limit is accepted; one
/// byte over is refused in both directions; the default codec is unaffected.
#[test]
fn a_reduced_frame_limit_is_enforced_in_both_directions() {
    // 11 header + 4 length prefix + 49 key = a 64-byte frame body.
    let exact = Envelope::new(1, Message::Get { key: vec![7; 49] });
    let over = Envelope::new(2, Message::Get { key: vec![7; 50] });

    let mut restricted = VyrnCodec::builder().max_frame_length(64).build();

    let mut bytes = BytesMut::new();
    restricted.encode(exact.clone(), &mut bytes).unwrap();
    assert_eq!(restricted.decode(&mut bytes).unwrap(), Some(exact));

    // One byte over is refused before anything is buffered, on send...
    let mut bytes = BytesMut::new();
    assert!(
        restricted.encode(over.clone(), &mut bytes).is_err(),
        "encoding past the reduced ceiling must fail locally"
    );

    // ...and on receive.
    let mut incoming = encode(Message::Get { key: vec![7; 50] });
    assert!(restricted.decode(&mut incoming).is_err());

    // The default ceiling is untouched: the same frame decodes fine there.
    let mut unrestricted = VyrnCodec::default();
    let mut incoming = encode(Message::Get { key: vec![7; 50] });
    assert!(unrestricted.decode(&mut incoming).unwrap().is_some());
}
