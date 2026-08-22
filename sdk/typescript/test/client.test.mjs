import assert from "node:assert/strict";
import test from "node:test";
import { VyrnClient, VyrnError, text } from "../dist/index.js";

const response = (body, status = 200) => new Response(body === undefined ? null : JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

test("encodes CRUD requests and decodes values", async () => {
  const calls = [];
  const client = new VyrnClient({
    url: "https://db.example/",
    token: "secret",
    fetch: async (url, init) => {
      calls.push([url, init]);
      if (url.endsWith("/v1/get")) return response({ value: Buffer.from("value").toString("base64") });
      return response(undefined, 204);
    },
  });
  assert.equal(text(await client.get("key")), "value");
  await client.put("key", "value");
  assert.equal(calls[0][0], "https://db.example/v1/get");
  assert.equal(calls[0][1].headers.authorization, "Bearer secret");
  assert.deepEqual(JSON.parse(calls[1][1].body), {
    key: Buffer.from("key").toString("base64"),
    value: Buffer.from("value").toString("base64"),
  });
});

test("surfaces structured gateway errors", async () => {
  const client = new VyrnClient({
    url: "https://db.example",
    token: "bad",
    fetch: async () => response({ error: { code: "authentication_failed", message: "invalid" } }, 401),
  });
  await assert.rejects(client.get("key"), (error) =>
    error instanceof VyrnError && error.status === 401 && error.code === "authentication_failed");
});

test("encodes document requests and returns parsed JSON", async () => {
  const calls = [];
  const client = new VyrnClient({
    url: "https://db.example",
    token: "secret",
    fetch: async (url, init) => {
      calls.push([url, JSON.parse(init.body)]);
      if (url.endsWith("/v1/documents/get")) return response({ document: { email: "a@example.com" } });
      if (url.endsWith("/v1/documents/query")) {
        return response({ documents: [{ id: "user_1", document: { role: "admin" } }] });
      }
      if (url.endsWith("/v1/documents/delete")) return response({ existed: true });
      return response(undefined, 204);
    },
  });

  await client.createCollection("users", [{ field: "email", unique: true }]);
  assert.deepEqual(calls[0][1], {
    collection: "users",
    indexes: [{ field: "email", unique: true }],
  });

  await client.putDocument("users", "user_1", { email: "a@example.com" });
  assert.deepEqual(calls[1][1], {
    collection: "users",
    id: "user_1",
    document: { email: "a@example.com" },
  });

  assert.deepEqual(await client.getDocument("users", "user_1"), { email: "a@example.com" });

  const admins = await client.queryDocuments("users", "role", "admin", { limit: 10 });
  assert.deepEqual(admins, [{ id: "user_1", document: { role: "admin" } }]);
  assert.equal(calls[3][1].limit, 10);

  assert.equal(await client.deleteDocument("users", "user_1"), true);
});

test("streams document changes and surfaces stream errors", async () => {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('data: {"sequence":3,"id":"user_1","document":{"role":"admin"}}\n\n'));
      controller.enqueue(encoder.encode('data: {"sequence":4,"id":"user_1","document":null}\n\n'));
      controller.close();
    },
  });
  const client = new VyrnClient({
    url: "https://db.example",
    token: "secret",
    fetch: async (url) => {
      assert.ok(url.includes("collection=users"));
      return new Response(stream, { headers: { "content-type": "text/event-stream" } });
    },
  });
  const changes = [];
  for await (const change of client.subscribeCollection("users")) changes.push(change);
  assert.deepEqual(changes, [
    { sequence: 3, id: "user_1", document: { role: "admin" } },
    { sequence: 4, id: "user_1", document: null },
  ]);

  const failing = new VyrnClient({
    url: "https://db.example",
    token: "secret",
    fetch: async () =>
      new Response(
        `event: error\ndata: {"error":{"code":"subscription_closed","message":"lagged"}}\n\n`,
        { headers: { "content-type": "text/event-stream" } },
      ),
  });
  await assert.rejects(
    (async () => {
      for await (const _ of failing.subscribeCollection("users")) break;
    })(),
    (error) => error instanceof VyrnError && error.code === "subscription_closed",
  );
});

test("parses fragmented SSE changes", async () => {
  const encoder = new TextEncoder();
  const payload = `data: {"sequence":7,"key":"${Buffer.from("users/1").toString("base64")}","value":null}\n\n`;
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(payload.slice(0, 12)));
      controller.enqueue(encoder.encode(payload.slice(12)));
      controller.close();
    },
  });
  const client = new VyrnClient({
    url: "https://db.example",
    token: "secret",
    fetch: async () => new Response(stream, { headers: { "content-type": "text/event-stream" } }),
  });
  const changes = [];
  for await (const change of client.subscribe("users/")) changes.push(change);
  assert.equal(changes[0].sequence, 7);
  assert.equal(text(changes[0].key), "users/1");
  assert.equal(changes[0].value, null);
});

test("rejects malformed base64 instead of decoding garbage", async () => {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      // Buffer.from(value, "base64") silently ignores invalid characters, so
      // this used to surface as corrupted bytes rather than an error.
      controller.enqueue(encoder.encode('data: {"sequence":1,"key":"!! not base64 !!","value":null}\n\n'));
      controller.close();
    },
  });
  const client = new VyrnClient({
    url: "https://db.example",
    token: "secret",
    fetch: async () => new Response(stream, { headers: { "content-type": "text/event-stream" } }),
  });
  await assert.rejects(
    (async () => {
      for await (const change of client.subscribe("users/")) change;
    })(),
    (error) => error instanceof VyrnError && error.code === "invalid_response",
  );
});

test("parses SSE data lines with and without the optional leading space", async () => {
  const encoder = new TextEncoder();
  const key = Buffer.from("users/1").toString("base64");
  const block = (data) => `data:${data}\n\n`;
  const stream = new ReadableStream({
    start(controller) {
      // No space after the colon.
      controller.enqueue(encoder.encode(block(`{"sequence":1,"key":"${key}","value":null}`)));
      // Exactly one space (the spec-optional form).
      controller.enqueue(encoder.encode(block(` {"sequence":2,"key":"${key}","value":null}`)));
      // A tab is not stripped: only a single leading space is, per spec.
      controller.enqueue(encoder.encode(block(`\t{"sequence":3,"key":"${key}","value":null}`)));
      // Multi-line data joins with newlines.
      controller.enqueue(encoder.encode(block(' {"sequence":\ndata: 4,"key":"' + key + '","value":null}')));
      controller.close();
    },
  });
  const client = new VyrnClient({
    url: "https://db.example",
    token: "secret",
    fetch: async () => new Response(stream, { headers: { "content-type": "text/event-stream" } }),
  });
  const changes = [];
  for await (const change of client.subscribe("users/")) changes.push(change);
  assert.deepEqual(changes.map((change) => change.sequence), [1, 2, 3, 4]);
});
