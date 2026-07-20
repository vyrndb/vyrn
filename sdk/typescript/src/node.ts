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
