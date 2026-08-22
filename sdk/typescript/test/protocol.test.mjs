import assert from "node:assert/strict";
import test from "node:test";
import {
  FrameDecoder,
  PROTOCOL_VERSION,
  ProtocolError,
  encodeEnvelope,
} from "../dist/protocol.js";
import { parseConnectionUrl } from "../dist/connection.js";
import { serverFrame } from "./fake-server.mjs";

const utf8 = (value) => new TextEncoder().encode(value);

test("encodes requests with a length-delimited frame header", () => {
  const frame = encodeEnvelope({
    version: PROTOCOL_VERSION,
    requestId: 7,
    message: { type: "get", key: utf8("users/1") },
  });
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  assert.equal(view.getUint32(0, false), frame.length - 4);
  assert.equal(view.getUint16(4, false), PROTOCOL_VERSION);
  assert.equal(Number(view.getBigUint64(6, false)), 7);
  assert.equal(view.getUint8(14), 2, "get is message type 2");
  assert.equal(view.getUint32(15, false), 7, "key length prefix");
});

/**
 * The server-frame encoder lives in fake-server.mjs, where the pool and
 * subscription tests reuse it against a real socket.
 */

test("round-trips every server response through the frame decoder", () => {
  const responses = [
    { type: "authenticated" },
    { type: "value", value: utf8("v") },
    { type: "value", value: null },
    { type: "values", values: [utf8("a"), null] },
    { type: "written" },
    { type: "deleted", existed: true },
    { type: "rows", rows: [[utf8("k"), utf8("v")]] },
    { type: "subscribed" },
    { type: "begun" },
    { type: "committed" },
    { type: "rolledBack" },
    { type: "indexCreated" },
    { type: "indexDropped" },
    { type: "indexUpdated" },
    { type: "keys", keys: [utf8("users/1")] },
    { type: "collectionCreated" },
    { type: "documentValue", document: utf8("{}") },
    { type: "documentValue", document: null },
    { type: "documentWritten" },
    { type: "documentDeleted", existed: false },
    { type: "documents", documents: [["user_1", utf8('{"a":1}')]] },
    { type: "collectionSubscribed" },
    { type: "documentChange", sequence: 42, id: "user_1", document: utf8("{}") },
    { type: "change", sequence: 9, key: utf8("k"), value: null },
    { type: "cursorChange", cursor: "c1", key: utf8("k"), value: utf8("v") },
    {
      type: "cursorDocumentChange",
      cursor: "c2",
      collection: "users",
      id: "user_1",
      document: null,
    },
    { type: "caught", cursor: "c2" },
    { type: "error", code: "conflict", message: "conflicted" },
  ];

  const decoder = new FrameDecoder();
  for (const message of responses) {
    decoder.push(serverFrame(message));
  }
  for (const expected of responses) {
    const envelope = decoder.next();
    assert.ok(envelope, `expected an envelope for ${expected.type}`);
    assert.deepEqual(envelope.message, expected);
  }
  assert.equal(decoder.next(), null);
});

test("reassembles frames split across chunks and ignores partial frames", () => {
  const frame = serverFrame({ type: "documents", documents: [["a", utf8('{"n":1}')]] });
  const decoder = new FrameDecoder();
  for (let index = 0; index < frame.length - 1; index += 1) {
    decoder.push(frame.subarray(index, index + 1));
    assert.equal(decoder.next(), null, "must not decode an incomplete frame");
  }
  decoder.push(frame.subarray(frame.length - 1));
  const envelope = decoder.next();
  assert.deepEqual(envelope.message.documents[0][0], "a");
});

test("rejects unknown message types and truncated payloads", () => {
  const badType = new Uint8Array([0, 0, 0, 11, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1, 250]);
  const decoder = new FrameDecoder();
  decoder.push(badType);
  assert.throws(() => decoder.next(), ProtocolError);

  const truncated = new Uint8Array([0, 0, 0, 9, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1]);
  const second = new FrameDecoder();
  second.push(truncated);
  assert.throws(() => second.next(), ProtocolError);
});

test("refuses to encode server-only messages", () => {
  assert.throws(
    () => encodeEnvelope({ version: PROTOCOL_VERSION, requestId: 1, message: { type: "committed" } }),
    ProtocolError,
  );
});

test("parses vyrn URLs and enforces TLS defaults", () => {
  const parsed = parseConnectionUrl("vyrn://alica:secret@localhost:7432/app");
  assert.deepEqual(parsed, {
    host: "localhost",
    port: 7432,
    username: "alica",
    password: "secret",
    database: "app",
    tlsRequired: true,
  });

  assert.equal(parseConnectionUrl("vyrn://u:p@host/app").port, 7432);
  assert.equal(parseConnectionUrl("vyrn://u:p@host/app?tls=disable").tlsRequired, false);
  assert.equal(parseConnectionUrl("vyrn://u@host/app", "from-file").password, "from-file");

  for (const invalid of [
    "postgres://u:p@host/app",
    "vyrn://host/app",
    "vyrn://u:p@host",
    "vyrn://u:p@host/a/b",
    "vyrn://u:p@host/app?tls=maybe",
    "vyrn://u:p@host/app?other=1",
  ]) {
    assert.throws(() => parseConnectionUrl(invalid), /invalid connection string/, invalid);
  }
});
