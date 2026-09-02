import net from "node:net";

const utf8 = (value) => new TextEncoder().encode(value);

/**
 * Encodes a server response the way vyrnd does, so clients can be tested
 * without a live server. Mirrors encode_message in crates/vyrn-protocol.
 * `requestId` is echoed back so the client accepts the frame.
 */
export function serverFrame(message, requestId = 1) {
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
  new DataView(version.buffer).setUint16(0, 6, false);
  parts.push(version);
  u64(requestId);

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
    case "cursorChange": u8(47); str(message.cursor); raw(message.key); optional(message.value); break;
    case "cursorDocumentChange":
      u8(48); str(message.cursor); str(message.collection); str(message.id); optional(message.document);
      break;
    case "caught": u8(49); str(message.cursor); break;
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

/** Concatenates response frames so the client receives them in one read. */
export function coalescedFrames(requestId, ...messages) {
  return Buffer.concat(messages.map((message) => Buffer.from(serverFrame(message, requestId))));
}

const REQUEST_NAMES = {
  1: "authenticate",
  2: "get",
  3: "put",
  4: "delete",
  5: "scan",
  12: "subscribe",
  15: "begin",
  16: "commit",
  17: "rollback",
  21: "createIndex",
  22: "dropIndex",
  23: "indexUpdate",
  24: "indexLookup",
  29: "multiGet",
  31: "createCollection",
  32: "getDocument",
  33: "putDocument",
  34: "deleteDocument",
  35: "listDocuments",
  36: "queryDocuments",
  37: "subscribeCollection",
  45: "subscribeFrom",
  46: "subscribeCollectionFrom",
};

const DEFAULT_RESPONSES = {
  authenticate: { type: "authenticated" },
  get: { type: "value", value: utf8("value") },
  multiGet: { type: "values", values: [utf8("value")] },
  put: { type: "written" },
  delete: { type: "deleted", existed: false },
  scan: { type: "rows", rows: [] },
  subscribe: { type: "subscribed" },
  begin: { type: "begun" },
  commit: { type: "committed" },
  rollback: { type: "rolledBack" },
  createIndex: { type: "indexCreated" },
  dropIndex: { type: "indexDropped" },
  indexUpdate: { type: "indexUpdated" },
  indexLookup: { type: "keys", keys: [] },
  createCollection: { type: "collectionCreated" },
  getDocument: { type: "documentValue", document: null },
  putDocument: { type: "documentWritten" },
  deleteDocument: { type: "documentDeleted", existed: false },
  listDocuments: { type: "documents", documents: [] },
  queryDocuments: { type: "documents", documents: [] },
  subscribeCollection: { type: "collectionSubscribed" },
  subscribeFrom: { type: "subscribed" },
  subscribeCollectionFrom: { type: "collectionSubscribed" },
};

/**
 * Minimal in-process vyrnd: answers every request with a canned response so
 * pool, transaction, and subscription state machines can be exercised over
 * real sockets. Route functions replace individual canned responses.
 */
export class FakeVyrnServer {
  #server = null;
  #sockets = new Set();
  #routes;
  #disconnectWaiters = [];
  #closed = false;
  port = 0;

  /** Every request kind received, in arrival order, across all connections. */
  requests = [];

  constructor(routes = {}) {
    this.#routes = routes;
  }

  async listen() {
    this.#server = net.createServer((socket) => this.#onConnection(socket));
    this.#server.unref();
    await new Promise((resolve) => this.#server.listen(0, "127.0.0.1", resolve));
    this.port = this.#server.address().port;
  }

  get url() {
    return `vyrn://user:password@127.0.0.1:${this.port}/app?tls=disable`;
  }

  options(extra = {}) {
    return { url: this.url, requestTimeoutMs: 5000, ...extra };
  }

  /** Resolves when the client side of the next established connection ends. */
  nextDisconnect() {
    return new Promise((resolve) => this.#disconnectWaiters.push(resolve));
  }

  /** Drops every established connection, the way a backend restart does. */
  killConnections() {
    const sockets = [...this.#sockets];
    if (sockets.length === 0) return Promise.resolve();
    return new Promise((resolve) => {
      let remaining = sockets.length;
      for (const socket of sockets) {
        socket.once("close", () => {
          remaining -= 1;
          if (remaining === 0) resolve();
        });
        socket.destroy();
      }
    });
  }

  /** Stops accepting new connections; established ones stay open. */
  stopListening() {
    this.#server?.close();
  }

  async close() {
    if (this.#closed) return;
    this.#closed = true;
    this.killConnections();
    await new Promise((resolve) => this.#server.close(resolve));
  }

  #onConnection(socket) {
    this.#sockets.add(socket);
    socket.setNoDelay(true);
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (buffer.length < 4 + length) break;
        this.#onFrame(socket, buffer.subarray(4, 4 + length));
        buffer = buffer.subarray(4 + length);
      }
    });
    socket.on("close", () => {
      this.#sockets.delete(socket);
      this.#disconnectWaiters.shift()?.();
    });
    socket.on("error", () => {});
  }

  #onFrame(socket, payload) {
    if (payload.length < 11) return;
    const requestId = Number(payload.readBigUInt64BE(2));
    const name = REQUEST_NAMES[payload.readUInt8(10)] ?? "unknown";
    this.requests.push(name);
    const route = this.#routes[name];
    if (route) {
      route({
        socket,
        requestId,
        payload,
        reply: (message) => this.send(socket, message, requestId),
      });
      return;
    }
    const canned = DEFAULT_RESPONSES[name];
    if (canned) this.send(socket, canned, requestId);
  }

  send(socket, message, requestId) {
    if (!socket.destroyed) socket.write(Buffer.from(serverFrame(message, requestId)));
  }
}
