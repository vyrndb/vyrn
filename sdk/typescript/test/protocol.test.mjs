import assert from "node:assert/strict";
import test from "node:test";
import {
  FrameDecoder,
  PROTOCOL_VERSION,
  ProtocolError,
  encodeEnvelope,
} from "../dist/protocol.js";
import { parseConnectionUrl } from "../dist/connection.js";

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
 * Encodes a server response the way vyrnd does, so the decoder can be tested
 * without a live server. Mirrors encode_message in crates/vyrn-protocol.
 */
function serverFrame(message) {
  const parts = [];
  const u8 = (value) => parts.push(Uint8Array.of(value));
  const u32 = (value) => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    parts.push(bytes);
  };
  const u64 = (value) => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
    parts.push(bytes);
  };
  const raw = (value) => {
    u32(value.length);
    parts.push(value);
  };
  const str = (value) => raw(utf8(value));
  const optional = (value) => {
    if (value === null) {
      u8(0);
      return;
    }
    u8(1);
    raw(value);
  };

  const version = new Uint8Array(2);
  new DataView(version.buffer).setUint16(0, PROTOCOL_VERSION, false);
  parts.push(version);
  u64(1);

  switch (message.type) {
    case "authenticated": u8(6); break;
    case "value": u8(7); optional(message.value); break;
    case "written": u8(8); break;
    case "deleted": u8(9); u8(message.existed ? 1 : 0); break;
    case "rows":
      u8(10);
      u32(message.rows.length);
      for (const [key, value] of message.rows) { raw(key); raw(value); }
      break;
    case "error": {
      const codes = { authentication_failed: 1, invalid_request: 2, unsupported_version: 3, storage: 4, internal: 5, conflict: 6 };
      u8(11); u8(codes[message.code]); str(message.message);
      break;
    }
    case "subscribed": u8(13); break;
    case "change": u8(14); u64(message.sequence); raw(message.key); optional(message.value); break;
    case "begun": u8(18); break;
    case "committed": u8(19); break;
    case "rolledBack": u8(20); break;
    case "indexCreated": u8(25); break;
    case "indexDropped": u8(26); break;
    case "indexUpdated": u8(27); break;
    case "keys":
      u8(28);
      u32(message.keys.length);
      for (const key of message.keys) raw(key);
      break;
    case "values":
      u8(30);
      u32(message.values.length);
      for (const value of message.values) optional(value);
      break;
    case "collectionCreated": u8(38); break;
    case "documentValue": u8(39); optional(message.document); break;
    case "documentWritten": u8(40); break;
    case "documentDeleted": u8(41); u8(message.existed ? 1 : 0); break;
    case "documents":
      u8(42);
      u32(message.documents.length);
      for (const [id, document] of message.documents) { str(id); raw(document); }
      break;
    case "collectionSubscribed": u8(43); break;
    case "documentChange":
      u8(44); u64(message.sequence); str(message.id); optional(message.document);
      break;
    default:
      throw new Error(`test encoder missing ${message.type}`);
  }

  const payloadLength = parts.reduce((total, part) => total + part.length, 0);
  const frame = new Uint8Array(4 + payloadLength);
  new DataView(frame.buffer).setUint32(0, payloadLength, false);
  let offset = 4;
  for (const part of parts) {
    frame.set(part, offset);
    offset += part.length;
  }
  return frame;
}

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
