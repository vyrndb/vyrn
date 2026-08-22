import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_STREAM_BUFFER,
  VyrnClient,
  VyrnConnectionError,
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
