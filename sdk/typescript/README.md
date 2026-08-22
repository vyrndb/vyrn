# @vyrn/client

Dependency-free TypeScript client for Vyrn, with two entry points:

| Import | Transport | Use from |
| --- | --- | --- |
| `@vyrn/client/node` | Native `vyrn://` protocol over TCP/TLS 1.3 | Node.js backend servers |
| `@vyrn/client` | HTTP + SSE via `vyrn-http` | Browsers and edge runtimes |

> **ESM only.** This package ships ECMAScript modules exclusively — there is no CommonJS build, so `require("@vyrn/client")` fails even though the package declares `engines: node >= 20`. Consume it with `import` from ESM, or with dynamic `import()` from CommonJS. Bundlers must handle ESM output (all modern ones do). The `"type": "module"` field makes this explicit to Node rather than leaving it to file-extension accident.

Use the native entry point for backend servers: it skips the gateway hop and is the only one that supports interactive transactions. It needs Node.js 20+ and cannot run in a browser, since browsers cannot open raw TCP sockets.

## Backend servers (native protocol)

```ts
import { VyrnClient, text } from "@vyrn/client/node";

const db = new VyrnClient({
  url: "vyrn://app:password@localhost:7432/app",
  caFile: "./ca.crt.pem",
  maxConnections: 10,
});

await db.connect();

await db.createCollection("users", [
  { field: "email", unique: true },
  { field: "role" },
]);

await db.putDocument("users", "user_1", { email: "alica@example.com", role: "admin" });
const user = await db.getDocument("users", "user_1");
const admins = await db.queryDocuments("users", "role", "admin", { limit: 100 });

await db.put("sessions/abc", "user_1");
const session = await db.get("sessions/abc");
```

Keep the password out of the URL where it would reach logs or shell history by passing it separately:

```ts
const db = new VyrnClient({
  url: "vyrn://app@localhost:7432/app",
  password: process.env.VYRN_PASSWORD!,
  caFile: process.env.VYRN_TLS_CA_FILE!,
});
```

TLS is required unless the URL carries `?tls=disable`, which only works against a server started with `--allow-plaintext` and is meant for isolated local testing. Without a CA certificate the client refuses to connect rather than downgrading.

### Interactive transactions

`transaction` pins one connection for the whole transaction, rolls back if the body throws, and retries serializable conflicts (three attempts by default):

```ts
await db.transaction(async (tx) => {
  const balance = Number(text((await tx.get("balance/a"))!));
  if (balance < 25) throw new Error("insufficient funds");
  await tx.put("balance/a", String(balance - 25));
  await tx.put("balance/b", "25");
});
```

Reads see the snapshot taken at begin plus the transaction's own writes. On commit the server rejects the transaction if another commit touched a written key, a point read, or a scanned range after that snapshot, surfaced as `VyrnServerError` with `code === "conflict"`. Throwing inside the body rolls back. A session refuses `begin` while it already has an active transaction.

For manual control use `db.use`, which leases a single connection:

```ts
await db.use(async (session) => {
  const tx = await session.begin();
  await tx.put("audit/1", "checked");
  await tx.rollback();
});
```

Forgetting `commit` or `rollback` cannot poison the pool: when a session with an open transaction is returned, the client rolls the transaction back before leasing the session again (and retires the session entirely if that rollback fails).

### Pooling

Each native connection handles one request at a time, so every call leases a connection and concurrent calls use separate ones, up to `maxConnections` (default 10). Additional callers queue until a connection is returned. Dead connections are discarded rather than reused, and their capacity is reclaimed immediately: after a backend restart the pool reconnects on demand instead of silently shrinking, and callers queued while every pooled connection was dead receive the connection error rather than waiting forever. Closing the client rejects queued callers the same way.

### Subscriptions

```ts
const controller = new AbortController();
for await (const change of db.subscribeCollection("users", controller.signal)) {
  console.log(change.sequence, change.id, change.document);
}
```

Each subscription uses its own dedicated connection. Delivery starts once the subscription is established and there is no durable cursor, so a subscriber that connects late or reconnects misses the gap and must resynchronize with `listDocuments` (or `scan` for `subscribe`).

The client buffers up to `MAX_STREAM_BUFFER` (10,000) undelivered events per subscription. A consumer that falls further behind than that has its subscription closed with a `VyrnConnectionError` saying so — memory stays bounded, and a slow consumer of a large retained log should resume from its last cursor instead of expecting the client to hold the whole replay. Backlog events coalesced into the same read as the subscribe ack are still delivered in order.

## Browsers and edge (HTTP gateway)

Requires `fetch`, streams, `TextEncoder`, and `TextDecoder`.

```ts
import { VyrnClient, text } from "@vyrn/client";

const db = new VyrnClient({
  url: "https://db.example.com",
  token: process.env.VYRN_HTTP_TOKEN!,
});

await db.put("users/1", JSON.stringify({ name: "Alica" }));
const value = await db.get("users/1");
if (value) console.log(JSON.parse(text(value)));

await db.transaction([
  { type: "put", key: "users/2", value: "active" },
  { type: "delete", key: "users/old" },
]);

for await (const change of db.subscribe("users/")) {
  console.log(change.sequence, text(change.key));
}
```

Document collections use plain JSON, with no base64 encoding:

```ts
await db.createCollection("users", [
  { field: "email", unique: true },
  { field: "role" },
]);

await db.putDocument("users", "user_1", { email: "alica@example.com", role: "admin" });
const user = await db.getDocument("users", "user_1");
const admins = await db.queryDocuments("users", "role", "admin", { limit: 100 });
await db.deleteDocument("users", "user_1");

for await (const change of db.subscribeCollection("users")) {
  console.log(change.sequence, change.id, change.document);
}
```

`subscribeCollection` delivers changes committed after the subscription is established; it has no durable cursor, so resynchronize with `listDocuments` after reconnecting. Indexed fields must be `null`, a boolean, a number, or a string, and a collection's indexes must match the stored definition.

Strings are UTF-8 encoded. Pass `Uint8Array` for arbitrary bytes. A `409 transaction_conflict` response is surfaced as `VyrnError` with `code === "transaction_conflict"`; retry the complete transaction when appropriate. Keep gateway service tokens on trusted backends until Vyrn supports end-user scoped credentials.
