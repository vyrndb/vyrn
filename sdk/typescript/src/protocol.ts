export const PROTOCOL_VERSION = 6;
export const MAX_FRAME_SIZE = 64 * 1024 * 1024;
export const DEFAULT_SCAN_LIMIT = 1_000;
export const MAX_SCAN_LIMIT = 10_000;

export type ErrorCode =
  | "authentication_failed"
  | "invalid_request"
  | "unsupported_version"
  | "storage"
  | "internal"
  | "conflict";

const ERROR_CODES: Record<number, ErrorCode> = {
  1: "authentication_failed",
  2: "invalid_request",
  3: "unsupported_version",
  4: "storage",
  5: "internal",
  6: "conflict",
};

export interface DocumentIndexWire {
  field: string;
  unique: boolean;
}

export type Message =
  | { type: "authenticate"; username: string; password: string; database: string }
  | { type: "get"; key: Uint8Array }
  | { type: "multiGet"; keys: Uint8Array[] }
  | { type: "put"; key: Uint8Array; value: Uint8Array }
  | { type: "delete"; key: Uint8Array }
  | { type: "scan"; start: Uint8Array | null; end: Uint8Array | null; limit: number }
  | { type: "subscribe"; prefix: Uint8Array }
  | { type: "begin" }
  | { type: "commit" }
  | { type: "rollback" }
  | { type: "createIndex"; name: Uint8Array; unique: boolean }
  | { type: "dropIndex"; name: Uint8Array }
  | {
      type: "indexUpdate";
      index: Uint8Array;
      primaryKey: Uint8Array;
      oldValue: Uint8Array | null;
      newValue: Uint8Array | null;
    }
  | { type: "indexLookup"; index: Uint8Array; value: Uint8Array; limit: number }
  | { type: "createCollection"; collection: string; indexes: DocumentIndexWire[] }
  | { type: "getDocument"; collection: string; id: string }
  | { type: "putDocument"; collection: string; id: string; document: Uint8Array }
  | { type: "deleteDocument"; collection: string; id: string }
  | { type: "listDocuments"; collection: string; limit: number }
  | { type: "queryDocuments"; collection: string; field: string; value: Uint8Array; limit: number }
  | { type: "subscribeCollection"; collection: string }
  | { type: "subscribeFrom"; prefix: Uint8Array; cursor: string | null }
  | { type: "subscribeCollectionFrom"; collection: string; cursor: string | null }
  | { type: "authenticated" }
  | { type: "value"; value: Uint8Array | null }
  | { type: "values"; values: Array<Uint8Array | null> }
  | { type: "written" }
  | { type: "deleted"; existed: boolean }
  | { type: "rows"; rows: Array<[Uint8Array, Uint8Array]> }
  | { type: "subscribed" }
  | { type: "begun" }
  | { type: "committed" }
  | { type: "rolledBack" }
  | { type: "indexCreated" }
  | { type: "indexDropped" }
  | { type: "indexUpdated" }
  | { type: "keys"; keys: Uint8Array[] }
  | { type: "collectionCreated" }
  | { type: "documentValue"; document: Uint8Array | null }
  | { type: "documentWritten" }
  | { type: "documentDeleted"; existed: boolean }
  | { type: "documents"; documents: Array<[string, Uint8Array]> }
  | { type: "collectionSubscribed" }
  | { type: "documentChange"; sequence: number; id: string; document: Uint8Array | null }
  | { type: "cursorChange"; cursor: string; key: Uint8Array; value: Uint8Array | null }
  | {
      type: "cursorDocumentChange";
      cursor: string;
      collection: string;
      id: string;
      document: Uint8Array | null;
    }
  | { type: "caught"; cursor: string }
  | { type: "change"; sequence: number; key: Uint8Array; value: Uint8Array | null }
  | { type: "error"; code: ErrorCode; message: string };

export interface Envelope {
  version: number;
  requestId: number;
  message: Message;
}

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolError";
  }
}

class Writer {
  #chunks: Uint8Array[] = [];
  #length = 0;

  u8(value: number): void {
    this.#push(Uint8Array.of(value));
  }

  u16(value: number): void {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, false);
    this.#push(bytes);
  }

  u32(value: number): void {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    this.#push(bytes);
  }

  u64(value: number | bigint): void {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
    this.#push(bytes);
  }

  bytes(value: Uint8Array): void {
    this.u32(value.length);
    this.#push(value);
  }

  string(value: string): void {
    this.bytes(new TextEncoder().encode(value));
  }

  optionalBytes(value: Uint8Array | null): void {
    if (value === null) {
      this.u8(0);
      return;
    }
    this.u8(1);
    this.bytes(value);
  }

  optionalString(value: string | null): void {
    this.optionalBytes(value === null ? null : new TextEncoder().encode(value));
  }

  finish(): Uint8Array {
    const output = new Uint8Array(this.#length);
    let offset = 0;
    for (const chunk of this.#chunks) {
      output.set(chunk, offset);
      offset += chunk.length;
    }
    return output;
  }

  #push(chunk: Uint8Array): void {
    this.#chunks.push(chunk);
    this.#length += chunk.length;
  }
}

class Reader {
  readonly #view: DataView;
  #offset = 0;

  constructor(private readonly source: Uint8Array) {
    this.#view = new DataView(source.buffer, source.byteOffset, source.byteLength);
  }

  u8(): number {
    this.#require(1);
    return this.#view.getUint8(this.#offset++);
  }

  u16(): number {
    this.#require(2);
    const value = this.#view.getUint16(this.#offset, false);
    this.#offset += 2;
    return value;
  }

  u32(): number {
    this.#require(4);
    const value = this.#view.getUint32(this.#offset, false);
    this.#offset += 4;
    return value;
  }

  u64(): number {
    this.#require(8);
    const value = this.#view.getBigUint64(this.#offset, false);
    this.#offset += 8;
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new ProtocolError("64-bit value exceeds safe integer range");
    }
    return Number(value);
  }

  bytes(): Uint8Array {
    const length = this.u32();
    if (length > MAX_FRAME_SIZE) throw new ProtocolError("byte field exceeds limit");
    this.#require(length);
    const value = this.source.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    return new Uint8Array(value);
  }

  string(): string {
    return new TextDecoder("utf-8", { fatal: true }).decode(this.bytes());
  }

  optionalBytes(): Uint8Array | null {
    const present = this.u8();
    if (present === 0) return null;
    if (present !== 1) throw new ProtocolError("invalid optional value");
    return this.bytes();
  }

  bool(): boolean {
    const value = this.u8();
    if (value > 1) throw new ProtocolError("invalid boolean");
    return value === 1;
  }

  count(limit: number, label: string): number {
    const count = this.u32();
    if (count > limit) throw new ProtocolError(`too many ${label}`);
    return count;
  }

  get done(): boolean {
    return this.#offset === this.source.length;
  }

  #require(length: number): void {
    if (this.#offset + length > this.source.length) {
      throw new ProtocolError("truncated message");
    }
  }
}

export function encodeEnvelope(envelope: Envelope): Uint8Array {
  const writer = new Writer();
  writer.u16(envelope.version);
  writer.u64(envelope.requestId);
  encodeMessage(envelope.message, writer);
  const payload = writer.finish();
  if (payload.length > MAX_FRAME_SIZE) {
    throw new ProtocolError("message exceeds frame limit");
  }
  const frame = new Uint8Array(4 + payload.length);
  new DataView(frame.buffer).setUint32(0, payload.length, false);
  frame.set(payload, 4);
  return frame;
