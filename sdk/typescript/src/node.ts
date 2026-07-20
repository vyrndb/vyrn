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
  static async connect(options: ConnectionOptions): Promise<Session> {
    return new Session(await Connection.connect(options));
  }

  get closedConnection(): boolean {
    return this.connection.closed;
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
    const response = await this.connection.call({ type: "begin" });
    if (response.type !== "begun") throw unexpected(response);
    return new Transaction(this.connection, () => {});
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

/**
 * Pooled client for backend servers.
 *
 * Each native connection handles one request at a time, so every call leases a
 * connection for its duration. Concurrent calls use separate connections, up to
 * `maxConnections`; further callers queue until one is returned.
 */
export class VyrnClient {
  readonly #options: ConnectionOptions;
  readonly #maximum: number;
  readonly #idle: Session[] = [];
  readonly #waiting: Array<(session: Session) => void> = [];
  #open = 0;
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
    this.#release(session);
  }

  async close(): Promise<void> {
    this.#closed = true;
    while (this.#idle.length > 0) {
      this.#idle.pop()?.close();
    }
  }

  async #acquire(): Promise<Session> {
    if (this.#closed) throw new VyrnConnectionError("client is closed");
    const idle = this.#idle.pop();
    if (idle && !idle.closedConnection) return idle;
    if (this.#open < this.#maximum) {
      this.#open += 1;
      try {
        return await Session.connect(this.#options);
      } catch (error) {
        this.#open -= 1;
        throw error;
      }
    }
    return new Promise<Session>((resolve) => this.#waiting.push(resolve));
  }

  #release(session: Session): void {
    if (session.closedConnection || this.#closed) {
      this.#open -= 1;
      session.close();
      void this.#refill();
      return;
    }
    const next = this.#waiting.shift();
    if (next) {
      next(session);
      return;
    }
    this.#idle.push(session);
  }

  async #refill(): Promise<void> {
    const next = this.#waiting.shift();
    if (!next) return;
    try {
      this.#open += 1;
      next(await Session.connect(this.#options));
    } catch {
      this.#open -= 1;
    }
  }

  /** Runs `body` with a leased connection, returning it afterwards. */
  async use<T>(body: (session: Session) => Promise<T>): Promise<T> {
    const session = await this.#acquire();
    try {
      return await body(session);
    } finally {
      this.#release(session);
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

async function* streamEnvelopes(
  connection: Connection,
  signal?: AbortSignal,
): AsyncGenerator<Envelope> {
  const queue: Envelope[] = [];
  let notify: (() => void) | null = null;
  let failure: Error | null = null;

  connection.stream(
    (envelope) => {
      queue.push(envelope);
      notify?.();
    },
    (error) => {
      failure = error;
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
  const response = await connection.call({
    type: "subscribeFrom",
    prefix: bytes(prefix),
    cursor: resume.cursor ?? null,
  });
  if (response.type !== "subscribed") {
    connection.close();
    throw unexpected(response);
  }
  yield* cursorEvents(connection, signal);
}

/** Subscribes to document changes in one collection with durable cursors. */
export async function* subscribeCollectionFrom<T = JsonValue>(
  options: ConnectionOptions,
  collection: string,
  resume: ResumeOptions = {},
  signal?: AbortSignal,
): AsyncGenerator<VyrnStreamEvent<T>> {
  const connection = await Connection.connect(options);
  const response = await connection.call({
    type: "subscribeCollectionFrom",
    collection,
    cursor: resume.cursor ?? null,
  });
  if (response.type !== "collectionSubscribed") {
    connection.close();
    throw unexpected(response);
  }
  yield* cursorEvents<T>(connection, signal);
}

async function* cursorEvents<T = JsonValue>(
  connection: Connection,
  signal?: AbortSignal,
): AsyncGenerator<VyrnStreamEvent<T>> {
  for await (const envelope of streamEnvelopes(connection, signal)) {
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
  const response = await connection.call({ type: "subscribe", prefix: bytes(prefix) });
  if (response.type !== "subscribed") {
    connection.close();
    throw unexpected(response);
  }
  for await (const envelope of streamEnvelopes(connection, signal)) {
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
  const response = await connection.call({ type: "subscribeCollection", collection });
  if (response.type !== "collectionSubscribed") {
    connection.close();
    throw unexpected(response);
  }
  for await (const envelope of streamEnvelopes(connection, signal)) {
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
