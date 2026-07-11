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
