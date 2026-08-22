import {
  Connection,
  VyrnConnectionError,
  VyrnServerError,
  type ConnectionOptions,
} from "./connection.js";
import {
  DEFAULT_SCAN_LIMIT,
  MAX_SCAN_LIMIT,
  ProtocolError,
  type Envelope,
  type Message,
} from "./protocol.js";

export {
  Connection,
  VyrnConnectionError,
  VyrnServerError,
  parseConnectionUrl,
  DEFAULT_PORT,
} from "./connection.js";
export { ProtocolError, PROTOCOL_VERSION, MAX_SCAN_LIMIT } from "./protocol.js";
export type { ErrorCode } from "./protocol.js";

export type VyrnBytes = string | Uint8Array;

/**
 * Envelopes buffered for a subscriber before the client declares it too slow.
 * Exceeding this closes the subscription instead of growing without bound, so
 * a stalled consumer cannot exhaust memory; reconnect and resume from your
 * last cursor to recover.
 */
export const MAX_STREAM_BUFFER = 10_000;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface CollectionIndex {
  field: string;
  unique?: boolean;
}

export interface VyrnRow {
  key: Uint8Array;
  value: Uint8Array;
}

export interface VyrnDocument<T = JsonValue> {
  id: string;
  document: T;
}

export interface VyrnChange {
  sequence: number;
  key: Uint8Array;
  value: Uint8Array | null;
}

export interface VyrnDocumentChange<T = JsonValue> {
  sequence: number;
  id: string;
  document: T | null;
}

/**
 * An event from a resumable subscription.
 *
 * Persist `cursor` after handling an event and pass it back on reconnect to
 * resume without gaps or duplicates. The `caught` event marks the end of the
 * replayed backlog, so callers can distinguish history from live traffic.
 */
export type VyrnStreamEvent<T = JsonValue> =
  | { type: "change"; cursor: string; key: Uint8Array; value: Uint8Array | null }
  | { type: "document"; cursor: string; collection: string; id: string; document: T | null }
  | { type: "caught"; cursor: string };

export interface ResumeOptions {
  /**
   * Where to start. Omit for live changes only, pass `""` to replay everything
   * still retained, or pass a previously received cursor to resume.
   */
  cursor?: string;
}

export interface ScanOptions {
  start?: VyrnBytes;
  end?: VyrnBytes;
  limit?: number;
}

export interface DocumentQueryOptions {
  limit?: number;
}

export interface PoolOptions extends ConnectionOptions {
  /** Maximum simultaneous native connections. Defaults to 10. */
  maxConnections?: number;
}

export function bytes(value: VyrnBytes): Uint8Array {
  return typeof value === "string" ? new TextEncoder().encode(value) : value;
}

export function text(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

function limitOf(limit: number | undefined): number {
  const resolved = limit ?? DEFAULT_SCAN_LIMIT;
  if (!Number.isInteger(resolved) || resolved < 1 || resolved > MAX_SCAN_LIMIT) {
    throw new RangeError(`limit must be an integer between 1 and ${MAX_SCAN_LIMIT}`);
  }
  return resolved;
}

function unexpected(message: Message): Error {
  return new ProtocolError(`unexpected response type: ${message.type}`);
}

function decodeJson(payload: Uint8Array): JsonValue {
  return JSON.parse(new TextDecoder().decode(payload)) as JsonValue;
}

function encodeJson(value: unknown): Uint8Array {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) {
    throw new TypeError("value is not JSON-serializable");
  }
  return new TextEncoder().encode(encoded);
}

/** Operations available both on a session and inside a transaction. */
class Operations {
  constructor(protected readonly connection: Connection) {}

  async get(key: VyrnBytes): Promise<Uint8Array | null> {
    const response = await this.connection.call({ type: "get", key: bytes(key) });
    if (response.type !== "value") throw unexpected(response);
    return response.value;
  }

  async put(key: VyrnBytes, value: VyrnBytes): Promise<void> {
    const response = await this.connection.call({
      type: "put",
      key: bytes(key),
      value: bytes(value),
    });
    if (response.type !== "written") throw unexpected(response);
  }

  async delete(key: VyrnBytes): Promise<boolean> {
    const response = await this.connection.call({ type: "delete", key: bytes(key) });
    if (response.type !== "deleted") throw unexpected(response);
    return response.existed;
  }

  async scan(options: ScanOptions = {}): Promise<VyrnRow[]> {
    const response = await this.connection.call({
      type: "scan",
      start: options.start === undefined ? null : bytes(options.start),
      end: options.end === undefined ? null : bytes(options.end),
      limit: limitOf(options.limit),
    });
    if (response.type !== "rows") throw unexpected(response);
    return response.rows.map(([key, value]) => ({ key, value }));
  }

  async lookupIndex(index: VyrnBytes, value: VyrnBytes, limit?: number): Promise<Uint8Array[]> {
    const response = await this.connection.call({
      type: "indexLookup",
      index: bytes(index),
      value: bytes(value),
      limit: limitOf(limit),
    });
    if (response.type !== "keys") throw unexpected(response);
    return response.keys;
  }
}

/**
 * A serializable transaction pinned to one connection.
 *
 * Reads observe the snapshot taken at begin plus this transaction's own writes.
 * `commit` throws a VyrnServerError with code "conflict" if another commit
 * touched a key, point read, or scanned range after that snapshot; retry the
 * whole transaction from the start.
 */
export class Transaction extends Operations {
  #finished = false;

  constructor(connection: Connection, private readonly release: () => void) {
    super(connection);
  }

  get finished(): boolean {
    return this.#finished;
  }

  async updateIndex(
    index: VyrnBytes,
    primaryKey: VyrnBytes,
    oldValue: VyrnBytes | null,
    newValue: VyrnBytes | null,
  ): Promise<void> {
    const response = await this.connection.call({
      type: "indexUpdate",
      index: bytes(index),
      primaryKey: bytes(primaryKey),
      oldValue: oldValue === null ? null : bytes(oldValue),
      newValue: newValue === null ? null : bytes(newValue),
    });
    if (response.type !== "indexUpdated") throw unexpected(response);
  }

  async commit(): Promise<void> {
    this.#finish();
    try {
      const response = await this.connection.call({ type: "commit" });
      if (response.type !== "committed") throw unexpected(response);
    } finally {
      this.release();
    }
  }

  async rollback(): Promise<void> {
    this.#finish();
    try {
      const response = await this.connection.call({ type: "rollback" });
      if (response.type !== "rolledBack") throw unexpected(response);
    } finally {
      this.release();
    }
  }

  #finish(): void {
    if (this.#finished) throw new VyrnConnectionError("transaction is already finished");
    this.#finished = true;
  }
}

/** A single native connection with document, KV, and transaction APIs. */
export class Session extends Operations {
  #transaction: Transaction | null = null;

  static async connect(options: ConnectionOptions): Promise<Session> {
    return new Session(await Connection.connect(options));
  }

  get closedConnection(): boolean {
    return this.connection.closed;
  }

  /** True when `begin` has not yet been followed by `commit` or `rollback`. */
  get transactionActive(): boolean {
    return this.#transaction !== null && !this.#transaction.finished;
  }

  close(): void {
    this.connection.close();
  }

  async createIndex(name: VyrnBytes, unique: boolean): Promise<void> {
    const response = await this.connection.call({
      type: "createIndex",
      name: bytes(name),
      unique,
    });
    if (response.type !== "indexCreated") throw unexpected(response);
  }

  async dropIndex(name: VyrnBytes): Promise<void> {
    const response = await this.connection.call({ type: "dropIndex", name: bytes(name) });
    if (response.type !== "indexDropped") throw unexpected(response);
  }

  async createCollection(collection: string, indexes: CollectionIndex[] = []): Promise<void> {
    const response = await this.connection.call({
      type: "createCollection",
      collection,
      indexes: indexes.map((index) => ({ field: index.field, unique: index.unique ?? false })),
    });
    if (response.type !== "collectionCreated") throw unexpected(response);
  }

  async getDocument<T = JsonValue>(collection: string, id: string): Promise<T | null> {
    const response = await this.connection.call({ type: "getDocument", collection, id });
    if (response.type !== "documentValue") throw unexpected(response);
    return response.document === null ? null : (decodeJson(response.document) as T);
  }

  async putDocument(collection: string, id: string, document: unknown): Promise<void> {
    const response = await this.connection.call({
      type: "putDocument",
      collection,
      id,
      document: encodeJson(document),
    });
    if (response.type !== "documentWritten") throw unexpected(response);
  }

  async deleteDocument(collection: string, id: string): Promise<boolean> {
    const response = await this.connection.call({ type: "deleteDocument", collection, id });
    if (response.type !== "documentDeleted") throw unexpected(response);
    return response.existed;
  }

  async listDocuments<T = JsonValue>(
    collection: string,
    options: DocumentQueryOptions = {},
  ): Promise<Array<VyrnDocument<T>>> {
    const response = await this.connection.call({
      type: "listDocuments",
      collection,
      limit: limitOf(options.limit),
    });
    if (response.type !== "documents") throw unexpected(response);
    return response.documents.map(([id, document]) => ({ id, document: decodeJson(document) as T }));
  }

  async queryDocuments<T = JsonValue>(
    collection: string,
    field: string,
    value: JsonValue,
    options: DocumentQueryOptions = {},
  ): Promise<Array<VyrnDocument<T>>> {
    const response = await this.connection.call({
      type: "queryDocuments",
      collection,
      field,
      value: encodeJson(value),
      limit: limitOf(options.limit),
    });
    if (response.type !== "documents") throw unexpected(response);
    return response.documents.map(([id, document]) => ({ id, document: decodeJson(document) as T }));
  }

  async begin(): Promise<Transaction> {
    if (this.transactionActive) {
      throw new VyrnConnectionError("a transaction is already active on this session");
    }
    const response = await this.connection.call({ type: "begin" });
    if (response.type !== "begun") throw unexpected(response);
    this.#transaction = new Transaction(this.connection, () => {});
    return this.#transaction;
  }

  /**
   * Best-effort rollback of an abandoned transaction, used by the pool before
   * handing the session to its next lessee. Errors propagate so the pool can
   * retire a session it cannot prove clean.
   */
  async rollbackAbandoned(): Promise<void> {
    const transaction = this.#transaction;
    if (transaction && !transaction.finished) await transaction.rollback();
  }

  /**
   * Runs `body` in a transaction, rolling back if it throws. Conflicts are
   * retried up to `attempts` times with the transaction restarted from scratch.
   */
  async transaction<T>(body: (tx: Transaction) => Promise<T>, attempts = 3): Promise<T> {
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const tx = await this.begin();
      try {
        const result = await body(tx);
        await tx.commit();
        return result;
      } catch (error) {
        if (!tx.finished && !this.connection.closed) {
          await tx.rollback().catch(() => {});
        }
        const retryable =
          error instanceof VyrnServerError && error.code === "conflict" && !this.connection.closed;
        if (!retryable) throw error;
        lastError = error;
      }
    }
    throw lastError;
  }
}

/** A queued acquire, settled either by a session or by an error. */
interface PendingAcquire {
  resolve: (session: Session) => void;
  reject: (error: Error) => void;
}

/**
 * Pooled client for backend servers.
 *
 * Each native connection handles one request at a time, so every call leases a
 * connection for its duration. Concurrent calls use separate connections, up to
 * `maxConnections`; further callers queue until one is returned. Dead sessions
 * are discarded with their capacity reclaimed, so a backend restart cannot
 * erode the pool, and queued callers are settled instead of waiting forever.
 */
export class VyrnClient {
  readonly #options: ConnectionOptions;
  readonly #maximum: number;
  readonly #idle: Session[] = [];
  readonly #waiting: PendingAcquire[] = [];
  /** Sessions that connected successfully and are not yet destroyed. */
  #open = 0;
  /** Connections still being established; `#open + #connecting <= #maximum`. */
  #connecting = 0;
  #pumping = false;
  #closed = false;

  constructor(options: PoolOptions) {
    const { maxConnections, ...connectionOptions } = options;
    this.#options = connectionOptions;
    this.#maximum = maxConnections ?? 10;
    if (!Number.isInteger(this.#maximum) || this.#maximum < 1) {
      throw new RangeError("maxConnections must be a positive integer");
    }
  }

  /** Verifies credentials and connectivity by opening one connection. */
  async connect(): Promise<void> {
    const session = await this.#acquire();
    await this.#release(session);
  }

  /**
   * Closes every pooled connection. Queued callers are rejected instead of
   * being left waiting for a session that will never come.
   */
  async close(): Promise<void> {
    this.#closed = true;
    for (const waiter of this.#waiting.splice(0)) {
      waiter.reject(new VyrnConnectionError("client is closed"));
    }
    while (this.#idle.length > 0) {
      this.#destroy(this.#idle.pop() as Session);
    }
  }

  async #acquire(): Promise<Session> {
    if (this.#closed) throw new VyrnConnectionError("client is closed");
    let idle = this.#idle.pop();
    while (idle !== undefined) {
      if (!idle.closedConnection) return idle;
      // Dead session (backend restart): drop it and reclaim its slot before
      // opening anything new.
      this.#destroy(idle);
      idle = this.#idle.pop();
    }
    return new Promise<Session>((resolve, reject) => {
      this.#waiting.push({ resolve, reject });
      void this.#pump();
    });
  }

  #destroy(session: Session): void {
    this.#open -= 1;
    session.close();
  }

  async #release(session: Session): Promise<void> {
    let reusable = !this.#closed && !session.closedConnection;
    if (reusable && session.transactionActive) {
      // The lessee abandoned an open transaction. Roll it back so the next
      // lessee cannot run inside the stale snapshot; if the rollback fails,
      // the session cannot be proven clean, so retire it instead.
      try {
        await session.rollbackAbandoned();
      } catch {
        reusable = false;
      }
    }
    // Re-check #closed: close() may have run while the rollback was in flight.
    if (!reusable || this.#closed || session.closedConnection) {
      this.#destroy(session);
      void this.#pump();
      return;
    }
    const next = this.#waiting.shift();
    if (next) {
      next.resolve(session);
      return;
    }
    this.#idle.push(session);
  }

  /**
   * Hands queued callers idle sessions, replaces dead ones, and opens new
   * connections while capacity remains. Single-flighted so overlapping
   * triggers cannot overshoot `maxConnections`.
   */
  async #pump(): Promise<void> {
    if (this.#pumping) return;
    this.#pumping = true;
    try {
      while (!this.#closed && this.#waiting.length > 0) {
        const idle = this.#idle.pop();
        if (idle !== undefined) {
          if (!idle.closedConnection) {
            (this.#waiting.shift() as PendingAcquire).resolve(idle);
            continue;
          }
          this.#destroy(idle);
          continue;
        }
        if (this.#open + this.#connecting >= this.#maximum) return;
        this.#connecting += 1;
        let session: Session;
        try {
          session = await Session.connect(this.#options);
        } catch (error) {
          this.#connecting -= 1;
          // Settle the head waiter so nobody queues forever behind a backend
          // that refuses connections; the rest stay queued until the next
          // release or acquire retries.
          (this.#waiting.shift() as PendingAcquire | undefined)?.reject(
            error instanceof Error ? error : new VyrnConnectionError(String(error)),
          );
          return;
        }
        this.#connecting -= 1;
        this.#open += 1;
        if (this.#closed) {
          this.#destroy(session);
          return;
        }
        const waiter = this.#waiting.shift();
        if (waiter === undefined) {
          this.#idle.push(session);
          continue;
        }
        waiter.resolve(session);
      }
    } finally {
      this.#pumping = false;
    }
  }

  /** Runs `body` with a leased connection, returning it afterwards. */
  async use<T>(body: (session: Session) => Promise<T>): Promise<T> {
    const session = await this.#acquire();
    try {
      return await body(session);
    } finally {
      await this.#release(session);
    }
  }

  get(key: VyrnBytes): Promise<Uint8Array | null> {
    return this.use((session) => session.get(key));
  }

  put(key: VyrnBytes, value: VyrnBytes): Promise<void> {
    return this.use((session) => session.put(key, value));
  }

  delete(key: VyrnBytes): Promise<boolean> {
    return this.use((session) => session.delete(key));
  }

  scan(options: ScanOptions = {}): Promise<VyrnRow[]> {
    return this.use((session) => session.scan(options));
  }

  createIndex(name: VyrnBytes, unique: boolean): Promise<void> {
    return this.use((session) => session.createIndex(name, unique));
  }

  dropIndex(name: VyrnBytes): Promise<void> {
    return this.use((session) => session.dropIndex(name));
  }

  lookupIndex(index: VyrnBytes, value: VyrnBytes, limit?: number): Promise<Uint8Array[]> {
    return this.use((session) => session.lookupIndex(index, value, limit));
  }

  createCollection(collection: string, indexes: CollectionIndex[] = []): Promise<void> {
    return this.use((session) => session.createCollection(collection, indexes));
  }

  getDocument<T = JsonValue>(collection: string, id: string): Promise<T | null> {
    return this.use((session) => session.getDocument<T>(collection, id));
  }

  putDocument(collection: string, id: string, document: unknown): Promise<void> {
    return this.use((session) => session.putDocument(collection, id, document));
  }

  deleteDocument(collection: string, id: string): Promise<boolean> {
    return this.use((session) => session.deleteDocument(collection, id));
  }

  listDocuments<T = JsonValue>(
    collection: string,
    options: DocumentQueryOptions = {},
  ): Promise<Array<VyrnDocument<T>>> {
    return this.use((session) => session.listDocuments<T>(collection, options));
  }

  queryDocuments<T = JsonValue>(
    collection: string,
    field: string,
    value: JsonValue,
    options: DocumentQueryOptions = {},
  ): Promise<Array<VyrnDocument<T>>> {
    return this.use((session) => session.queryDocuments<T>(collection, field, value, options));
  }

  /** Runs a serializable transaction on one pinned connection, retrying conflicts. */
  transaction<T>(body: (tx: Transaction) => Promise<T>, attempts = 3): Promise<T> {
    return this.use((session) => session.transaction(body, attempts));
  }

  subscribe(prefix: VyrnBytes, signal?: AbortSignal): AsyncGenerator<VyrnChange> {
    return subscribe(this.#options, prefix, signal);
  }

  subscribeCollection<T = JsonValue>(
    collection: string,
    signal?: AbortSignal,
  ): AsyncGenerator<VyrnDocumentChange<T>> {
    return subscribeCollection<T>(this.#options, collection, signal);
  }

  /** Resumable key subscription; see `subscribeFrom`. */
  subscribeFrom(
    prefix: VyrnBytes,
    resume: ResumeOptions = {},
    signal?: AbortSignal,
  ): AsyncGenerator<VyrnStreamEvent> {
    return subscribeFrom(this.#options, prefix, resume, signal);
  }

  /** Resumable collection subscription; see `subscribeCollectionFrom`. */
  subscribeCollectionFrom<T = JsonValue>(
    collection: string,
    resume: ResumeOptions = {},
    signal?: AbortSignal,
  ): AsyncGenerator<VyrnStreamEvent<T>> {
    return subscribeCollectionFrom<T>(this.#options, collection, resume, signal);
  }
}

/**
 * Installs a buffering stream handler before the subscribe message is sent.
 *
 * The server writes the ack and the first replayed events back-to-back, so
 * both frames routinely arrive in a single socket read. Without a handler
 * already registered, the backlog frames land before `streamEnvelopes` starts
 * and are treated as unsolicited traffic, tearing the connection down. The
 * buffered envelopes are handed to `streamEnvelopes` once it begins, which
 * preserves delivery order.
 */
function bufferStream(connection: Connection): Envelope[] {
  const buffered: Envelope[] = [];
  connection.stream((envelope) => buffered.push(envelope), () => {});
  return buffered;
}

async function* streamEnvelopes(
  connection: Connection,
  signal?: AbortSignal,
  buffered: Envelope[] = [],
): AsyncGenerator<Envelope> {
  const queue = buffered;
  let notify: (() => void) | null = null;
  let failure: Error | null = null;

  connection.stream(
    (envelope) => {
      if (failure !== null) return;
      if (queue.length >= MAX_STREAM_BUFFER) {
        // The consumer stopped keeping up. Failing beats buffering without
        // bound: a large retained log would otherwise exhaust memory.
        failure = new VyrnConnectionError(
          `subscriber fell more than ${MAX_STREAM_BUFFER} events behind; the subscription is closing`,
        );
        connection.close();
        notify?.();
        return;
      }
      queue.push(envelope);
      notify?.();
    },
    (error) => {
      if (failure === null) failure = error;
      notify?.();
    },
  );
  const onAbort = () => connection.close();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    while (true) {
      while (queue.length > 0) {
        yield queue.shift() as Envelope;
      }
      if (failure) throw failure;
      if (signal?.aborted) return;
      await new Promise<void>((resolve) => {
        notify = () => {
          notify = null;
          resolve();
        };
      });
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
    connection.close();
  }
}

/**
 * Subscribes to key changes with durable cursors, resuming after
 * `options.cursor`.
 *
 * Changes committed while the subscriber was disconnected are replayed from the
 * durable change log before live events, so nothing is missed. A cursor older
 * than the retained log fails with `VyrnServerError` instead of silently
 * skipping changes.
 */
export async function* subscribeFrom(
  options: ConnectionOptions,
  prefix: VyrnBytes,
  resume: ResumeOptions = {},
  signal?: AbortSignal,
): AsyncGenerator<VyrnStreamEvent> {
  const connection = await Connection.connect(options);
  const buffered = bufferStream(connection);
  const response = await connection.call({
    type: "subscribeFrom",
    prefix: bytes(prefix),
    cursor: resume.cursor ?? null,
  });
  if (response.type !== "subscribed") {
    connection.close();
    throw unexpected(response);
  }
  yield* cursorEvents(connection, signal, buffered);
}

/** Subscribes to document changes in one collection with durable cursors. */
export async function* subscribeCollectionFrom<T = JsonValue>(
  options: ConnectionOptions,
  collection: string,
  resume: ResumeOptions = {},
  signal?: AbortSignal,
): AsyncGenerator<VyrnStreamEvent<T>> {
  const connection = await Connection.connect(options);
  const buffered = bufferStream(connection);
  const response = await connection.call({
    type: "subscribeCollectionFrom",
    collection,
    cursor: resume.cursor ?? null,
  });
  if (response.type !== "collectionSubscribed") {
    connection.close();
    throw unexpected(response);
  }
  yield* cursorEvents<T>(connection, signal, buffered);
}

async function* cursorEvents<T = JsonValue>(
  connection: Connection,
  signal?: AbortSignal,
  buffered: Envelope[] = [],
): AsyncGenerator<VyrnStreamEvent<T>> {
  for await (const envelope of streamEnvelopes(connection, signal, buffered)) {
    const message = envelope.message;
    if (message.type === "error") throw new VyrnServerError(message.code, message.message);
    if (message.type === "cursorChange") {
      yield { type: "change", cursor: message.cursor, key: message.key, value: message.value };
      continue;
    }
    if (message.type === "cursorDocumentChange") {
      yield {
        type: "document",
        cursor: message.cursor,
        collection: message.collection,
        id: message.id,
        document: message.document === null ? null : (decodeJson(message.document) as T),
      };
      continue;
    }
    if (message.type === "caught") {
      yield { type: "caught", cursor: message.cursor };
      continue;
    }
    throw unexpected(message);
  }
}

/**
 * Subscribes to committed changes under a key prefix on a dedicated connection.
 *
 * Delivery begins when the subscription is established, so a reconnecting
 * subscriber can miss changes. Prefer `subscribeFrom` when gaps matter.
 */
export async function* subscribe(
  options: ConnectionOptions,
  prefix: VyrnBytes,
  signal?: AbortSignal,
): AsyncGenerator<VyrnChange> {
  const connection = await Connection.connect(options);
  const buffered = bufferStream(connection);
  const response = await connection.call({ type: "subscribe", prefix: bytes(prefix) });
  if (response.type !== "subscribed") {
    connection.close();
    throw unexpected(response);
  }
  for await (const envelope of streamEnvelopes(connection, signal, buffered)) {
    const message = envelope.message;
    if (message.type === "error") throw new VyrnServerError(message.code, message.message);
    if (message.type !== "change") throw unexpected(message);
    yield { sequence: message.sequence, key: message.key, value: message.value };
  }
}

/**
 * Subscribes to committed document changes in one collection on a dedicated
 * connection. Resynchronize with `listDocuments` after reconnecting.
 */
export async function* subscribeCollection<T = JsonValue>(
  options: ConnectionOptions,
  collection: string,
  signal?: AbortSignal,
): AsyncGenerator<VyrnDocumentChange<T>> {
  const connection = await Connection.connect(options);
  const buffered = bufferStream(connection);
  const response = await connection.call({ type: "subscribeCollection", collection });
  if (response.type !== "collectionSubscribed") {
    connection.close();
    throw unexpected(response);
  }
  for await (const envelope of streamEnvelopes(connection, signal, buffered)) {
    const message = envelope.message;
    if (message.type === "error") throw new VyrnServerError(message.code, message.message);
    if (message.type !== "documentChange") throw unexpected(message);
    yield {
      sequence: message.sequence,
      id: message.id,
      document: message.document === null ? null : (decodeJson(message.document) as T),
    };
  }
}
