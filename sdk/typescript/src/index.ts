export type VyrnBytes = string | Uint8Array;

export interface VyrnClientOptions {
  url: string;
  token: string;
  fetch?: typeof globalThis.fetch;
}

export interface ScanOptions {
  start?: VyrnBytes;
  end?: VyrnBytes;
  limit?: number;
}

export interface VyrnRow {
  key: Uint8Array;
  value: Uint8Array;
}

export interface VyrnChange {
  sequence: number;
  key: Uint8Array;
  value: Uint8Array | null;
}

export type TransactionOperation =
  | { type: "put"; key: VyrnBytes; value: VyrnBytes }
  | { type: "delete"; key: VyrnBytes };

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface CollectionIndex {
  field: string;
  unique?: boolean;
}

export interface VyrnDocument<T = JsonValue> {
  id: string;
  document: T;
}

export interface VyrnDocumentChange<T = JsonValue> {
  sequence: number;
  id: string;
  document: T | null;
}

export interface DocumentQueryOptions {
  limit?: number;
}

export class VyrnError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "VyrnError";
    this.status = status;
    this.code = code;
  }
}

export class VyrnClient {
  readonly #url: string;
  readonly #token: string;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: VyrnClientOptions) {
    this.#url = options.url.replace(/\/$/, "");
    this.#token = options.token;
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (!this.#fetch) throw new Error("fetch is not available");
  }

  async get(key: VyrnBytes, signal?: AbortSignal): Promise<Uint8Array | null> {
    const body = await this.#request<{ value: string | null }>("/v1/get", { key: encode(key) }, signal);
    return body.value === null ? null : decode(body.value);
  }

  async multiGet(keys: VyrnBytes[], signal?: AbortSignal): Promise<Array<Uint8Array | null>> {
    const body = await this.#request<{ values: Array<string | null> }>(
      "/v1/multi-get",
      { keys: keys.map(encode) },
      signal,
    );
    return body.values.map((value) => value === null ? null : decode(value));
  }

  async put(key: VyrnBytes, value: VyrnBytes, signal?: AbortSignal): Promise<void> {
    await this.#request("/v1/put", { key: encode(key), value: encode(value) }, signal);
  }

  async delete(key: VyrnBytes, signal?: AbortSignal): Promise<boolean> {
    const body = await this.#request<{ existed: boolean }>("/v1/delete", { key: encode(key) }, signal);
    return body.existed;
  }

  async scan(options: ScanOptions = {}, signal?: AbortSignal): Promise<VyrnRow[]> {
    const body = await this.#request<{ rows: Array<{ key: string; value: string }> }>(
      "/v1/scan",
      {
        ...(options.start === undefined ? {} : { start: encode(options.start) }),
        ...(options.end === undefined ? {} : { end: encode(options.end) }),
        ...(options.limit === undefined ? {} : { limit: options.limit }),
      },
      signal,
    );
    return body.rows.map((row) => ({ key: decode(row.key), value: decode(row.value) }));
  }

  async transaction(operations: TransactionOperation[], signal?: AbortSignal): Promise<boolean[]> {
    const body = await this.#request<{ deleted: boolean[] }>(
      "/v1/transaction",
      {
        operations: operations.map((operation) =>
          operation.type === "put"
            ? { type: "put", key: encode(operation.key), value: encode(operation.value) }
            : { type: "delete", key: encode(operation.key) },
        ),
      },
      signal,
    );
    return body.deleted;
  }

  async createCollection(
    collection: string,
    indexes: CollectionIndex[] = [],
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#request(
      "/v1/collections/create",
      {
        collection,
        indexes: indexes.map((index) => ({ field: index.field, unique: index.unique ?? false })),
      },
      signal,
    );
  }

  async getDocument<T = JsonValue>(
    collection: string,
    id: string,
    signal?: AbortSignal,
  ): Promise<T | null> {
    const body = await this.#request<{ document: T | null }>(
      "/v1/documents/get",
      { collection, id },
      signal,
    );
    return body.document;
  }

  async putDocument(
    collection: string,
    id: string,
    document: unknown,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#request("/v1/documents/put", { collection, id, document }, signal);
  }

  async deleteDocument(collection: string, id: string, signal?: AbortSignal): Promise<boolean> {
    const body = await this.#request<{ existed: boolean }>(
      "/v1/documents/delete",
      { collection, id },
      signal,
    );
    return body.existed;
  }

  async listDocuments<T = JsonValue>(
    collection: string,
    options: DocumentQueryOptions = {},
    signal?: AbortSignal,
  ): Promise<Array<VyrnDocument<T>>> {
    const body = await this.#request<{ documents: Array<VyrnDocument<T>> }>(
      "/v1/documents/list",
      { collection, ...(options.limit === undefined ? {} : { limit: options.limit }) },
      signal,
    );
    return body.documents;
  }

  async queryDocuments<T = JsonValue>(
    collection: string,
    field: string,
    value: JsonValue,
    options: DocumentQueryOptions = {},
    signal?: AbortSignal,
  ): Promise<Array<VyrnDocument<T>>> {
    const body = await this.#request<{ documents: Array<VyrnDocument<T>> }>(
      "/v1/documents/query",
      {
        collection,
        field,
        value,
        ...(options.limit === undefined ? {} : { limit: options.limit }),
      },
      signal,
    );
    return body.documents;
  }

  async *subscribeCollection<T = JsonValue>(
    collection: string,
    signal?: AbortSignal,
  ): AsyncGenerator<VyrnDocumentChange<T>> {
    const path = `/v1/documents/subscribe?collection=${encodeURIComponent(collection)}`;
    for await (const parsed of this.#events(path, signal)) {
      const change = parsed as { sequence: number; id: string; document: T | null };
      yield { sequence: change.sequence, id: change.id, document: change.document };
    }
  }

  async *subscribe(prefix: VyrnBytes, signal?: AbortSignal): AsyncGenerator<VyrnChange> {
    const path = `/v1/subscribe?prefix=${encodeURIComponent(encode(prefix))}`;
    for await (const parsed of this.#events(path, signal)) {
      const change = parsed as { sequence: number; key: string; value: string | null };
      yield {
        sequence: change.sequence,
        key: decode(change.key),
        value: change.value === null ? null : decode(change.value),
      };
    }
  }

  async *#events(path: string, signal?: AbortSignal): AsyncGenerator<unknown> {
    const response = await this.#fetch(`${this.#url}${path}`, {
      headers: { authorization: `Bearer ${this.#token}`, accept: "text/event-stream" },
      ...(signal === undefined ? {} : { signal }),
    });
    if (!response.ok) throw await responseError(response);
    if (!response.body) throw new VyrnError(0, "invalid_response", "subscription response has no body");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
        let boundary: number;
        while ((boundary = buffer.indexOf("\n\n")) !== -1) {
          const block = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const event = parseEvent(block);
          if (!event.data) continue;
          const parsed = JSON.parse(event.data) as { error?: { code: string; message: string } };
          if (parsed.error) throw new VyrnError(0, parsed.error.code, parsed.error.message);
          yield parsed;
        }
      }
    } finally {
      try {
        await reader.cancel();
      } catch {
        reader.releaseLock();
      }
    }
  }

  async #request<T = unknown>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
    const response = await this.#fetch(`${this.#url}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.#token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
      ...(signal === undefined ? {} : { signal }),
    });
    if (!response.ok) throw await responseError(response);
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }
}

export function text(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

function encode(value: VyrnBytes): string {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decode(value: string): Uint8Array {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(value, "base64"));
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function parseEvent(block: string): { event: string; data: string } {
  let event = "message";
  const data: string[] = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trimStart();
    if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  return { event, data: data.join("\n") };
}

async function responseError(response: Response): Promise<VyrnError> {
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    return new VyrnError(
      response.status,
      body.error?.code ?? "request_failed",
      body.error?.message ?? `request failed with status ${response.status}`,
    );
  } catch {
    return new VyrnError(response.status, "request_failed", `request failed with status ${response.status}`);
  }
}

declare const Buffer:
  | { from(value: Uint8Array | string, encoding?: string): { toString(encoding: string): string; [index: number]: number; length: number } }
  | undefined;
