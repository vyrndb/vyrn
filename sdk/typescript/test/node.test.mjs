import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_STREAM_BUFFER,
  VyrnClient,
  VyrnConnectionError,
  VyrnServerError,
  subscribeFrom,
  text,
} from "../dist/node.js";
import { FakeVyrnServer, coalescedFrames, serverFrame } from "./fake-server.mjs";

const utf8 = (value) => new TextEncoder().encode(value);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Retries a read a couple of times to absorb the brief window between the
 * backend dropping a connection and the client socket observing it. A genuine
 * pool wedge never reaches the retries: the first call never settles.
 */
async function tolerantGet(client, key, attempts = 3) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return text(await client.get(key));
    } catch (error) {
      lastError = error;
      await delay(25);
    }
  }
  throw lastError;
}

test("pool reclaims capacity when the backend restarts", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer();
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url, maxConnections: 1 });
  t.after(() => db.close());

  await db.put("a", "1"); // opens the pool's only session
  await server.killConnections(); // backend restart
  await delay(25); // let the client observe the dropped sockets

  // Discarding the dead session used to leave its slot counted, so open ===
  // max and this call queued forever behind phantom capacity.
  assert.equal(await tolerantGet(db, "a"), "value");
  assert.equal(text(await db.get("b")), "value");
});

test("concurrent callers still complete after every pooled session dies", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer();
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url, maxConnections: 2 });
  t.after(() => db.close());

  await Promise.all([db.put("a", "1"), db.put("b", "2")]); // two pooled sessions
  await server.killConnections();
  await delay(25);

  // More concurrent callers than reclaimed slots: all must settle.
  const results = await Promise.all([
    tolerantGet(db, "a"),
    tolerantGet(db, "b"),
    tolerantGet(db, "c"),
  ]);
  assert.deepEqual(results, ["value", "value", "value"]);
});

test("queued callers are rejected when reconnecting fails", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer();
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url, maxConnections: 1 });
  t.after(() => db.close());

  let resume;
  const gate = new Promise((resolve) => {
    resume = resolve;
  });
  const lease = db.use(() => gate); // holds the pool's only session
  const queued = db.get("k"); // queues behind it
  await delay(25);

  server.stopListening(); // refuse future connections...
  await server.killConnections(); // ...and drop the leased one
  await delay(25);
  resume();

  // Refilling used to abandon the shifted waiter on connect failure, hanging
  // it forever; it must instead be settled with the connection error.
  await assert.rejects(queued, VyrnConnectionError);
  await lease;
});

test("close settles queued callers instead of leaving them waiting", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer();
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url, maxConnections: 1 });
  t.after(() => db.close());

  let resume;
  const gate = new Promise((resolve) => {
    resume = resolve;
  });
  const lease = db.use(() => gate);
  const queued = db.get("k");
  await delay(25);

  await db.close();
  await assert.rejects(queued, /client is closed/);
  resume();
  await lease;
});

test("rolls back a transaction abandoned by its lessee", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer();
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url });
  t.after(() => db.close());

  await db.use(async (session) => {
    const tx = await session.begin();
    await tx.put("k", "v");
    // No commit, no rollback: the session goes back with the transaction open.
  });

  // The next lessee must not run inside the stale snapshot.
  assert.equal(text(await db.get("k")), "value");
  assert.deepEqual(server.requests.slice(-4), ["begin", "put", "rollback", "get"]);
});

test("begin refuses while another transaction is active", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer();
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url });
  t.after(() => db.close());

  await db.use(async (session) => {
    const tx = await session.begin();
    const beginsBefore = server.requests.filter((name) => name === "begin").length;
    await assert.rejects(session.begin(), /already active/);
    assert.equal(
      server.requests.filter((name) => name === "begin").length,
      beginsBefore,
      "the refused begin must not reach the server",
    );
    await tx.rollback();
    assert.equal(session.transactionActive, false);
    const second = await session.begin(); // allowed once the first finished
    await second.rollback();
  });
});

test("attaches to backlog delivered in the same read as the ack", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer({
    subscribeFrom: ({ requestId, socket }) => {
      // vyrnd writes the ack and the replayed backlog back-to-back; a single
      // write makes them land in one client read, which is the race.
      socket.write(
        coalescedFrames(
          requestId,
          { type: "subscribed" },
          { type: "cursorChange", cursor: "c1", key: utf8("users/1"), value: utf8("a") },
          { type: "cursorChange", cursor: "c2", key: utf8("users/2"), value: null },
          { type: "caught", cursor: "c2" },
        ),
      );
    },
  });
  await server.listen();
  t.after(() => server.close());

  const events = [];
  const controller = new AbortController();
  t.after(() => controller.abort());
  for await (const event of subscribeFrom(server.options(), "users/", {}, controller.signal)) {
    events.push(event);
    if (event.type === "caught") break;
  }

  // Without a handler installed before the Subscribe message is sent, the
  // coalesced backlog frames arrive as "unsolicited messages" and destroy the
  // socket before the generator can attach.
  assert.deepEqual(events, [
    { type: "change", cursor: "c1", key: utf8("users/1"), value: utf8("a") },
    { type: "change", cursor: "c2", key: utf8("users/2"), value: null },
    { type: "caught", cursor: "c2" },
  ]);
});

test("fails a subscriber that falls too far behind instead of buffering without bound", { timeout: 20_000 }, async (t) => {
  const total = MAX_STREAM_BUFFER + 50;
  let flood;
  const server = new FakeVyrnServer({
    subscribeFrom: ({ requestId, reply, socket }) => {
      // One event so the consumer can start, then bursts larger than the
      // buffer limit, repeated until the client hangs up.
      reply({ type: "subscribed" });
      socket.write(
        Buffer.from(
          serverFrame({ type: "cursorChange", cursor: "first", key: utf8("k"), value: null }, requestId),
        ),
      );
      const burst = [];
      for (let index = 0; index < total; index += 1) {
        burst.push(
          Buffer.from(
            serverFrame({ type: "cursorChange", cursor: `c${index}`, key: utf8("k"), value: null }, requestId),
          ),
        );
      }
      const blob = Buffer.concat(burst);
      flood = setInterval(() => {
        if (!socket.destroyed) socket.write(blob);
      }, 20);
    },
  });
  await server.listen();
  t.after(() => {
    clearInterval(flood);
    return server.close();
  });

  const generator = subscribeFrom(server.options(), "users/", {});
  const first = await generator.next();
  assert.equal(first.value.cursor, "first");

  // The consumer stalls here on purpose: it pulls nothing while the bursts
  // pile up. Draining afterwards must terminate in a clear error rather than
  // an unbounded queue.
  await delay(250);
  await assert.rejects(
    async () => {
      for (;;) await generator.next();
    },
    /fell more than \d+ events behind/,
  );
});

/**
 * Request payload layout: u16 version, u64 requestId, u8 kind, then the
 * fields. For get/put/delete the key starts at offset 11 as u32 length + bytes.
 */
function keyOf(payload) {
  const length = payload.readUInt32BE(11);
  return payload.subarray(15, 15 + length).toString();
}

function putOf(payload) {
  const keyLength = payload.readUInt32BE(11);
  const key = payload.subarray(15, 15 + keyLength).toString();
  const valueLength = payload.readUInt32BE(15 + keyLength);
  const value = payload.subarray(19 + keyLength, 19 + keyLength + valueLength).toString();
  return { key, value };
}

test("a pipelined burst answers every operation in order in one round trip", { timeout: 10_000 }, async (t) => {
  // A stateful fake: the put→get→delete→get chain on one key only comes out
  // right if the operations execute in submission order. Replies are withheld
  // until the whole burst has arrived, so a client that read an answer between
  // writes would deadlock into its request timeout — the single-round-trip
  // property is pinned, not hoped for.
  const BURST = 4;
  const store = new Map();
  const held = [];
  const hold = (run) => {
    held.push(run);
    if (held.length === BURST) for (const answer of held.splice(0)) answer();
  };
  const server = new FakeVyrnServer({
    put: ({ payload, reply }) =>
      hold(() => {
        const { key, value } = putOf(payload);
        store.set(key, value);
        reply({ type: "written" });
      }),
    get: ({ payload, reply }) =>
      hold(() => {
        const key = keyOf(payload);
        reply({ type: "value", value: store.has(key) ? utf8(store.get(key)) : null });
      }),
    delete: ({ payload, reply }) =>
      hold(() => reply({ type: "deleted", existed: store.delete(keyOf(payload)) })),
  });
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url, requestTimeoutMs: 2000 });
  t.after(() => db.close());

  const results = await db.pipeline([
    { type: "put", key: "pipe/k", value: "v1" },
    { type: "get", key: "pipe/k" },
    { type: "delete", key: "pipe/k" },
    { type: "get", key: "pipe/k" },
  ]);
  assert.deepEqual(results, [
    { type: "written" },
    { type: "value", value: utf8("v1") },
    { type: "deleted", existed: true },
    { type: "value", value: null },
  ]);
  assert.deepEqual(server.requests, ["authenticate", "put", "get", "delete", "get"]);
});

test("a refused operation consumes its own slot without derailing the burst", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer({
    get: ({ payload, reply }) =>
      keyOf(payload).length === 0
        ? reply({ type: "error", code: "invalid_request", message: "key must not be empty" })
        : reply({ type: "value", value: utf8("value") }),
  });
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url });
  t.after(() => db.close());

  const results = await db.pipeline([
    { type: "put", key: "a", value: "1" },
    { type: "get", key: "" }, // refused: empty key
    { type: "get", key: "a" },
    { type: "delete", key: "never-existed" },
  ]);
  assert.equal(results.length, 4, "one answer per operation, no more, no fewer");
  assert.deepEqual(results[0], { type: "written" });
  assert.equal(results[1].type, "error", "the empty key must be refused in its own slot");
  assert.ok(results[1].error instanceof VyrnServerError);
  assert.equal(results[1].error.code, "invalid_request");
  assert.deepEqual(
    results[2],
    { type: "value", value: utf8("value") },
    "the get behind the refusal must still receive its own answer",
  );
  assert.deepEqual(results[3], { type: "deleted", existed: false });
  // The refused slot must not poison the connection for ordinary requests.
  assert.equal(text(await db.get("a")), "value");
});

test("pipeline refuses while a transaction is active on the session", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer();
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url });
  t.after(() => db.close());

  await db.use(async (session) => {
    const tx = await session.begin();
    const before = server.requests.length;
    await assert.rejects(session.pipeline([{ type: "get", key: "k" }]), /transaction is active/);
    assert.equal(server.requests.length, before, "the refused pipeline must not reach the server");
    await tx.rollback();
    const results = await session.pipeline([{ type: "get", key: "k" }]);
    assert.deepEqual(results, [{ type: "value", value: utf8("value") }]);
  });
});

test("destroys the socket when a request times out", { timeout: 10_000 }, async (t) => {
  const server = new FakeVyrnServer({
    get: () => {}, // never answers
  });
  await server.listen();
  t.after(() => server.close());
  const db = new VyrnClient({ url: server.url, requestTimeoutMs: 50 });
  t.after(() => db.close());

  const disconnected = server.nextDisconnect();
  await assert.rejects(db.get("k"), /timed out/);
  assert.notEqual(
    await Promise.race([disconnected, delay(2000).then(() => null)]),
    null,
    "the client must destroy the socket after a request timeout",
  );
});
