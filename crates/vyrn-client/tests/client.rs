//! Behaviour tests against an in-process mock server speaking the native
//! protocol — no live Vyrn server required.
//!
//! Each test binds an ephemeral loopback listener, connects a real [`Client`]
//! with `tls=disable`, and drives the server end of that single connection by
//! hand, so request/response ordering is explicit.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use vyrn_client::{Client, Error, StreamEvent};
use vyrn_protocol::{Envelope, ErrorCode, Message, VyrnCodec, PROTOCOL_VERSION};

type ServerEnd = Framed<TcpStream, VyrnCodec>;

/// Binds an ephemeral loopback listener and returns it with the plaintext
/// connection URL pointing at it.
async fn spawn_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback bind succeeds");
    let address = listener.local_addr().expect("local address");
    (listener, format!("vyrn://user:pass@{address}/app?tls=disable"))
}

async fn accept(listener: &TcpListener) -> ServerEnd {
    let (stream, _) = listener.accept().await.expect("client connects");
    Framed::new(stream, VyrnCodec::default())
}

/// Accepts the client, answers the authentication handshake, and returns both
/// ends of the connection.
async fn connect_pair(listener: &TcpListener, url: &str) -> (Client, ServerEnd) {
    let owned = url.to_owned();
    let connecting = tokio::spawn(async move { Client::connect_with_ca(&owned, None).await });
    let mut server = accept(listener).await;
    let handshake = server
        .next()
        .await
        .expect("server stream open")
        .expect("authentication frame decodes");
    assert!(matches!(handshake.message, Message::Authenticate { .. }));
    server
        .send(Envelope::new(handshake.request_id, Message::Authenticated))
        .await
        .expect("handshake reply sends");
    let client = connecting
        .await
        .expect("connect task joins")
        .expect("connect succeeds");
    (client, server)
}

/// Requests received by the mock server after authentication.
#[derive(Clone, Default)]
struct Received(Arc<Mutex<Vec<Message>>>);

impl Received {
    fn push(&self, message: &Message) {
        self.0.lock().expect("lock is not poisoned").push(message.clone());
    }

    fn snapshot(&self) -> Vec<Message> {
        self.0.lock().expect("lock is not poisoned").clone()
    }
}

#[tokio::test]
async fn requests_round_trip_against_the_mock() {
    let (listener, url) = spawn_listener().await;
    let (mut client, mut server) = connect_pair(&listener, &url).await;

    let (written, put) = tokio::join!(
        client.put(b"k".to_vec(), b"v".to_vec()),
        async {
            let request = server.next().await.expect("open").expect("decodes");
            server
                .send(Envelope::new(request.request_id, Message::Written))
                .await
                .expect("reply sends");
            request.message
        }
    );
    written.expect("put succeeds");
    assert_eq!(
        put,
        Message::Put {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        }
    );

    let (value, get) = tokio::join!(
        client.get(b"k".to_vec()),
        async {
            let request = server.next().await.expect("open").expect("decodes");
            server
                .send(Envelope::new(
                    request.request_id,
                    Message::Value {
                        value: Some(b"v".to_vec()),
                    },
                ))
                .await
                .expect("reply sends");
            request.message
        }
    );
    assert_eq!(value.expect("get succeeds"), Some(b"v".to_vec()));
    assert_eq!(get, Message::Get { key: b"k".to_vec() });
}

/// A request that never gets an answer must time out AND retire the
/// connection: a late reply would otherwise be read as the answer to the next
/// request, shifting every further exchange by one response.
///
/// The 30-second request timeout runs on tokio's paused clock, so the test
/// advances past it instantly instead of waiting.
#[tokio::test]
async fn timed_out_request_retires_the_connection() {
    let (listener, url) = spawn_listener().await;
    let received = Received::default();
    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel::<()>();

    let (mut client, mut server) = connect_pair(&listener, &url).await;
    let recorder = received.clone();
    // Answer nothing and hold the stream open, so the client sees silence
    // rather than an EOF. Signal once the first request is on the wire, so
    // the test advances the clock only after the client parked on its
    // response timeout.
    let driver = tokio::spawn(async move {
        let mut first_seen_tx = Some(first_seen_tx);
        while let Some(Ok(envelope)) = server.next().await {
            recorder.push(&envelope.message);
            if let Some(sender) = first_seen_tx.take() {
                let _ = sender.send(());
            }
        }
    });

    tokio::time::pause();
    let outcomes = tokio::spawn(async move {
        let first = client.get(b"k".to_vec()).await.unwrap_err();
        // The second call must fail fast instead of reading the first
        // request's late reply as its own answer.
        let second = client.get(b"k2".to_vec()).await.unwrap_err();
        (first, second)
    });

    first_seen_rx.await.expect("first request reaches the mock");

    // Keep virtual time moving so a regression cannot park the second request
    // forever: any timeout it arms will fire too.
    tokio::spawn(async {
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(30)).await;
        }
    });

    let (first, second) = outcomes.await.expect("outcomes join");
    assert!(matches!(first, Error::Timeout), "first call: {first:?}");
    assert!(
        matches!(second, Error::UnusableConnection),
        "second call: {second:?}"
    );

    driver.await.expect("driver joins");
    assert_eq!(
        received.snapshot(),
        vec![Message::Get {
            key: b"k".to_vec()
        }],
        "a retired connection must refuse to send further requests"
    );
}

/// A commit lost in transit leaves the server holding the transaction, so the
/// session must stay marked in-transaction and the next top-level request must
/// attempt the rollback rather than run inside the abandoned transaction.
#[tokio::test]
async fn commit_lost_in_transit_keeps_the_transaction_active() {
    let (listener, url) = spawn_listener().await;
    let received = Received::default();

    let (mut client, mut server) = connect_pair(&listener, &url).await;
    let recorder = received.clone();
    let driver = tokio::spawn(async move {
        while let Some(Ok(envelope)) = server.next().await {
            recorder.push(&envelope.message);
            match envelope.message {
                Message::Begin => {
                    server
                        .send(Envelope::new(envelope.request_id, Message::Begun))
                        .await
                        .expect("reply sends");
                }
                Message::Commit => {
                    // Lose the commit: answer nothing and half-close, so the
                    // client sees an EOF while the socket stays readable for
                    // the rollback it should still attempt.
                    server.get_mut().shutdown().await.expect("half-close");
                }
                Message::Rollback => break,
                other => panic!("unexpected request after lost commit: {other:?}"),
            }
        }
    });

    let transaction = client.transaction().await.expect("begin succeeds");
    let error = transaction.commit().await.unwrap_err();
    assert!(
        matches!(error, Error::ConnectionClosed),
        "commit: {error:?}"
    );

    let error = client.get(b"k".to_vec()).await.unwrap_err();
    assert!(matches!(error, Error::ConnectionClosed), "get: {error:?}");

    drop(client);
    driver.await.expect("driver joins");
    assert_eq!(
        received.snapshot(),
        vec![Message::Begin, Message::Commit, Message::Rollback],
    );
}

/// The same contract as [`commit_lost_in_transit_keeps_the_transaction_active`],
/// for an explicit rollback lost in transit.
#[tokio::test]
async fn rollback_lost_in_transit_keeps_the_transaction_active() {
    let (listener, url) = spawn_listener().await;
    let received = Received::default();

    let (mut client, mut server) = connect_pair(&listener, &url).await;
    let recorder = received.clone();
    let driver = tokio::spawn(async move {
        let mut rollbacks_seen = 0;
        while let Some(Ok(envelope)) = server.next().await {
            recorder.push(&envelope.message);
            match envelope.message {
                Message::Begin => {
                    server
                        .send(Envelope::new(envelope.request_id, Message::Begun))
                        .await
                        .expect("reply sends");
                }
                Message::Rollback => {
                    rollbacks_seen += 1;
                    if rollbacks_seen == 1 {
                        server.get_mut().shutdown().await.expect("half-close");
                    } else {
                        break;
                    }
                }
                other => panic!("unexpected request after lost rollback: {other:?}"),
            }
        }
    });

    let transaction = client.transaction().await.expect("begin succeeds");
    let error = transaction.rollback().await.unwrap_err();
    assert!(
        matches!(error, Error::ConnectionClosed),
        "rollback: {error:?}"
    );

    let error = client.get(b"k".to_vec()).await.unwrap_err();
    assert!(matches!(error, Error::ConnectionClosed), "get: {error:?}");

    drop(client);
    driver.await.expect("driver joins");
    assert_eq!(
        received.snapshot(),
        vec![Message::Begin, Message::Rollback, Message::Rollback],
    );
}

/// A definite server answer — here a rejection — proves the server released
/// the transaction, so the follow-up request must run directly, without a
/// rollback attempt in front of it.
#[tokio::test]
async fn commit_rejected_by_the_server_clears_the_transaction() {
    let (listener, url) = spawn_listener().await;
    let received = Received::default();

    let (mut client, mut server) = connect_pair(&listener, &url).await;
    let recorder = received.clone();
    let driver = tokio::spawn(async move {
        while let Some(Ok(envelope)) = server.next().await {
            recorder.push(&envelope.message);
            let reply = match envelope.message {
                Message::Begin => Message::Begun,
                Message::Commit => Message::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "invalid transaction state".into(),
                },
                Message::Get { .. } => Message::Value { value: None },
                other => panic!("unexpected request: {other:?}"),
            };
            server
                .send(Envelope::new(envelope.request_id, reply))
                .await
                .expect("reply sends");
        }
    });

    let transaction = client.transaction().await.expect("begin succeeds");
    let error = transaction.commit().await.unwrap_err();
    assert!(
        matches!(error, Error::Server { code: ErrorCode::InvalidRequest, .. }),
        "commit: {error:?}"
    );

    let value = client.get(b"k".to_vec()).await.expect("get succeeds");
    assert_eq!(value, None);

    drop(client);
    driver.await.expect("driver joins");
    assert_eq!(
        received.snapshot(),
        vec![
            Message::Begin,
            Message::Commit,
            Message::Get {
                key: b"k".to_vec()
            },
        ],
        "no rollback may follow a definite server answer"
    );
}

/// An abandoned `Transaction` (dropped without commit or rollback) still rolls
/// back before the next top-level request.
#[tokio::test]
async fn new_request_after_an_open_transaction_rolls_back_first() {
    let (listener, url) = spawn_listener().await;
    let received = Received::default();

    let (mut client, mut server) = connect_pair(&listener, &url).await;
    let recorder = received.clone();
    let driver = tokio::spawn(async move {
        while let Some(Ok(envelope)) = server.next().await {
            recorder.push(&envelope.message);
            let reply = match envelope.message {
                Message::Begin => Message::Begun,
                Message::Rollback => Message::RolledBack,
                Message::Get { .. } => Message::Value { value: None },
                other => panic!("unexpected request: {other:?}"),
            };
            server
                .send(Envelope::new(envelope.request_id, reply))
                .await
                .expect("reply sends");
        }
    });

    // Abandoned without commit or rollback: the borrow ends here, and the
    // next request must roll the transaction back first.
    let _transaction = client.transaction().await.expect("begin succeeds");
    let value = client.get(b"k".to_vec()).await.expect("get succeeds");
    assert_eq!(value, None);

    drop(client);
    driver.await.expect("driver joins");
    assert_eq!(
        received.snapshot(),
        vec![
            Message::Begin,
            Message::Rollback,
            Message::Get {
                key: b"k".to_vec()
            },
        ],
    );
}

fn key_change(version: u16, sequence: u64) -> Envelope {
    Envelope {
        version,
        request_id: 0,
        message: Message::Change {
            sequence,
            key: b"users/a".to_vec(),
            value: Some(b"1".to_vec()),
        },
    }
}

#[tokio::test]
async fn subscription_rejects_a_foreign_protocol_version() {
    let (listener, url) = spawn_listener().await;
    let (client, mut server) = connect_pair(&listener, &url).await;

    let subscribed = tokio::join!(
        client.subscribe(b"users/".to_vec()),
        async {
            let request = server.next().await.expect("open").expect("decodes");
            assert_eq!(
                request.message,
                Message::Subscribe {
                    prefix: b"users/".to_vec(),
                }
            );
            server
                .send(Envelope::new(request.request_id, Message::Subscribed))
                .await
                .expect("reply sends");
        }
    );
    let mut subscription = subscribed.0.expect("subscribe succeeds");

    server
        .send(key_change(PROTOCOL_VERSION, 1))
        .await
        .expect("event sends");
    let change = subscription
        .next()
        .await
        .expect("stream read succeeds")
        .expect("stream stays open");
    assert_eq!(change.sequence, 1);
    assert_eq!(change.key, b"users/a".to_vec());

    server
        .send(key_change(PROTOCOL_VERSION + 1, 2))
        .await
        .expect("event sends");
    let outcome = subscription.next().await;
    // The codec rejects a mis-versioned frame before the subscription loop
    // decodes it; the loop's own check is defence in depth, so either layer
    // failing the stream is correct.
    let text = match &outcome {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a mis-versioned event must fail the stream"),
    };
    assert!(text.contains("version"), "unexpected failure: {text}");
}

#[tokio::test]
async fn cursor_subscription_rejects_a_foreign_protocol_version() {
    let (listener, url) = spawn_listener().await;
    let (client, mut server) = connect_pair(&listener, &url).await;

    let cursor_event = |version| Envelope {
        version,
        request_id: 0,
        message: Message::CursorChange {
            cursor: "0000000000000001-00000000".into(),
            key: b"users/a".to_vec(),
            value: Some(b"1".to_vec()),
        },
    };

    let subscribed = tokio::join!(
        client.subscribe_from(b"users/".to_vec(), None),
        async {
            let request = server.next().await.expect("open").expect("decodes");
            assert!(matches!(request.message, Message::SubscribeFrom { .. }));
            server
                .send(Envelope::new(request.request_id, Message::Subscribed))
                .await
                .expect("reply sends");
        }
    );
    let mut subscription = subscribed.0.expect("subscribe succeeds");

    server
        .send(cursor_event(PROTOCOL_VERSION))
        .await
        .expect("event sends");
    let event = subscription
        .next()
        .await
        .expect("stream read succeeds")
        .expect("stream stays open");
    assert!(matches!(event, StreamEvent::Change { .. }));

    server
        .send(cursor_event(PROTOCOL_VERSION + 1))
        .await
        .expect("event sends");
    let outcome = subscription.next().await;
    // Either the codec or the subscription loop's own defence-in-depth check
    // may reject the frame.
    assert!(
        matches!(&outcome, Err(error) if error.to_string().contains("version")),
        "a mis-versioned event must fail the stream"
    );
}

#[tokio::test]
async fn document_subscription_rejects_a_foreign_protocol_version() {
    let (listener, url) = spawn_listener().await;
    let (client, mut server) = connect_pair(&listener, &url).await;

    let document_event = |version| Envelope {
        version,
        request_id: 0,
        message: Message::DocumentChange {
            sequence: 7,
            id: "user_1".into(),
            document: Some(br#"{"name":"a"}"#.to_vec()),
        },
    };

    let subscribed = tokio::join!(
        client.subscribe_collection("users"),
        async {
            let request = server.next().await.expect("open").expect("decodes");
            assert_eq!(
                request.message,
                Message::SubscribeCollection {
                    collection: "users".into(),
                }
            );
            server
                .send(Envelope::new(request.request_id, Message::CollectionSubscribed))
                .await
                .expect("reply sends");
        }
    );
    let mut subscription = subscribed.0.expect("subscribe succeeds");

    server
        .send(document_event(PROTOCOL_VERSION))
        .await
        .expect("event sends");
    let change = subscription
        .next()
        .await
        .expect("stream read succeeds")
        .expect("stream stays open");
    assert_eq!(change.id, "user_1");

    server
        .send(document_event(PROTOCOL_VERSION + 1))
        .await
        .expect("event sends");
    let outcome = subscription.next().await;
    // Either the codec or the subscription loop's own defence-in-depth check
    // may reject the frame.
    assert!(
        matches!(&outcome, Err(error) if error.to_string().contains("version")),
        "a mis-versioned event must fail the stream"
    );
}

/// The CA file is read before the TLS handshake, so a missing file surfaces as
/// a TLS error even though nothing on the far end speaks TLS yet.
#[tokio::test]
async fn missing_ca_file_reports_a_tls_error() {
    let (listener, _) = spawn_listener().await;
    let address = listener.local_addr().expect("local address");
    let url = format!("vyrn://user:pass@{address}/app");
    let missing = std::env::temp_dir().join(format!("vyrn-missing-ca-{}.pem", std::process::id()));
    let _ = std::fs::remove_file(&missing);

    let outcome = Client::connect_with_ca(&url, Some(missing.as_path())).await;
    assert!(matches!(outcome, Err(Error::Tls(_))), "expected a TLS error");
}
