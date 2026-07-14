import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { readFile } from "node:fs/promises";
import {
  decodeEnvelope,
  encodeEnvelope,
  FrameDecoder,
  PROTOCOL_VERSION,
  ProtocolError,
  type Envelope,
  type ErrorCode,
  type Message,
} from "./protocol.js";

export const DEFAULT_PORT = 7432;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

export class VyrnServerError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "VyrnServerError";
    this.code = code;
  }
}

export class VyrnConnectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VyrnConnectionError";
  }
}

export interface ConnectionOptions {
  /** vyrn://user:password@host:7432/database URL. */
  url: string;
  /** Password supplied outside the URL, so it stays out of logs and history. */
  password?: string;
  /** PEM CA certificate used to verify the server. Required unless tls=disable. */
  ca?: string | Buffer;
  /** Path to a PEM CA certificate, read at connect time. */
  caFile?: string;
  requestTimeoutMs?: number;
}

export interface ParsedConnectionUrl {
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
  tlsRequired: boolean;
}

export function parseConnectionUrl(url: string, passwordOverride?: string): ParsedConnectionUrl {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new VyrnConnectionError("invalid connection string: not a URL");
  }
  if (parsed.protocol !== "vyrn:") {
    throw new VyrnConnectionError("invalid connection string: scheme must be vyrn");
  }
  if (parsed.hash) {
    throw new VyrnConnectionError("invalid connection string: fragments are not supported");
  }
  const host = parsed.hostname;
  if (!host) throw new VyrnConnectionError("invalid connection string: host is required");
  const username = decodeURIComponent(parsed.username);
  if (!username) throw new VyrnConnectionError("invalid connection string: username is required");
  const password = passwordOverride ?? decodeURIComponent(parsed.password);
  if (!password) throw new VyrnConnectionError("invalid connection string: password is required");
  const database = parsed.pathname.replace(/^\//, "");
  if (!database || database.includes("/")) {
    throw new VyrnConnectionError("invalid connection string: exactly one database name is required");
  }

  let tlsRequired = true;
  let sawTls = false;
  for (const [key, value] of parsed.searchParams) {
    if (key !== "tls" || sawTls) {
      throw new VyrnConnectionError(`invalid connection string: unsupported or duplicate option ${key}`);
    }
    if (value === "require") tlsRequired = true;
    else if (value === "disable") tlsRequired = false;
    else throw new VyrnConnectionError("invalid connection string: tls must be require or disable");
    sawTls = true;
  }

  return {
    host,
    port: parsed.port ? Number(parsed.port) : DEFAULT_PORT,
    username,
    password,
    database,
    tlsRequired,
  };
}

interface Pending {
  requestId: number;
  resolve: (message: Message) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

/**
 * One authenticated connection over Vyrn's native protocol.
 *
 * Requests are strictly serialized: the server answers one request per
 * connection at a time, so callers must not issue concurrent requests on a
 * single connection. Use a pool for concurrency.
 */
export class Connection {
  readonly #socket: Socket;
  readonly #decoder = new FrameDecoder();
  readonly #timeoutMs: number;
  #pending: Pending | null = null;
  #streamHandler: ((envelope: Envelope) => void) | null = null;
  #streamClose: ((error: Error) => void) | null = null;
  #nextRequestId = 1;
  #closed: Error | null = null;

  private constructor(socket: Socket, timeoutMs: number) {
    this.#socket = socket;
    this.#timeoutMs = timeoutMs;
    socket.on("data", (chunk: Buffer) => this.#onData(chunk));
    socket.on("error", (error: Error) => this.#fail(new VyrnConnectionError(error.message)));
    socket.on("close", () => this.#fail(new VyrnConnectionError("connection closed by server")));
  }

  static async connect(options: ConnectionOptions): Promise<Connection> {
    const parsed = parseConnectionUrl(options.url, options.password);
    const timeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    let ca: string | Buffer | undefined = options.ca;
    if (ca === undefined && options.caFile !== undefined) {
      ca = await readFile(options.caFile);
    }
    if (parsed.tlsRequired && ca === undefined) {
      throw new VyrnConnectionError("TLS requires a CA certificate; pass ca or caFile");
    }

    const socket = await new Promise<Socket>((resolve, reject) => {
      const pending: Socket = parsed.tlsRequired
        ? tlsConnect({
            host: parsed.host,
            port: parsed.port,
            servername: parsed.host,
            ca,
            minVersion: "TLSv1.3",
          })
        : netConnect({ host: parsed.host, port: parsed.port });
      const onReady = () => {
        pending.removeListener("error", onError);
        resolve(pending);
      };
      const onError = (error: Error) => {
        pending.removeListener(parsed.tlsRequired ? "secureConnect" : "connect", onReady);
        pending.destroy();
        reject(new VyrnConnectionError(error.message));
      };
      pending.setNoDelay(true);
      pending.once(parsed.tlsRequired ? "secureConnect" : "connect", onReady);
      pending.once("error", onError);
    });

    const connection = new Connection(socket, timeoutMs);
    const response = await connection.request({
      type: "authenticate",
      username: parsed.username,
      password: parsed.password,
      database: parsed.database,
    });
    if (response.type !== "authenticated") {
      connection.close();
      throw new VyrnConnectionError("unexpected authentication response");
    }
    return connection;
  }

  get closed(): boolean {
    return this.#closed !== null;
  }

  async request(message: Message): Promise<Message> {
    if (this.#closed) throw this.#closed;
    if (this.#pending) {
      throw new VyrnConnectionError("a request is already in flight on this connection");
    }
    const requestId = this.#nextRequestId;
    this.#nextRequestId = requestId >= Number.MAX_SAFE_INTEGER ? 1 : requestId + 1;

    return new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending = null;
        this.#fail(new VyrnConnectionError("request timed out"));
      }, this.#timeoutMs);
      timer.unref?.();
      this.#pending = { requestId, resolve, reject, timer };
      try {
        this.#socket.write(encodeEnvelope({ version: PROTOCOL_VERSION, requestId, message }));
      } catch (error) {
        clearTimeout(timer);
        this.#pending = null;
        reject(new VyrnConnectionError((error as Error).message));
      }
    });
  }

  /** Converts an error response into a thrown VyrnServerError. */
  async call(message: Message): Promise<Message> {
    const response = await this.request(message);
    if (response.type === "error") throw new VyrnServerError(response.code, response.message);
    return response;
  }

  /**
   * Switches this connection into server-push mode for subscriptions. The
   * connection can no longer be used for requests afterwards.
   */
  stream(onEnvelope: (envelope: Envelope) => void, onClose: (error: Error) => void): void {
    this.#streamHandler = onEnvelope;
    this.#streamClose = onClose;
  }

  close(): void {
    this.#fail(new VyrnConnectionError("connection closed"));
    this.#socket.destroy();
  }

  #onData(chunk: Buffer): void {
    try {
      this.#decoder.push(new Uint8Array(chunk));
      let envelope = this.#decoder.next();
      while (envelope !== null) {
        this.#dispatch(envelope);
        envelope = this.#decoder.next();
      }
    } catch (error) {
      this.#fail(
        error instanceof ProtocolError ? error : new VyrnConnectionError((error as Error).message),
      );
      this.#socket.destroy();
    }
  }

  #dispatch(envelope: Envelope): void {
    if (envelope.version !== PROTOCOL_VERSION) {
      this.#fail(new ProtocolError("server used an unsupported protocol version"));
      this.#socket.destroy();
      return;
    }
    const pending = this.#pending;
    if (pending) {
      if (envelope.requestId !== pending.requestId) {
        this.#fail(new ProtocolError("response request ID did not match"));
        this.#socket.destroy();
        return;
      }
      clearTimeout(pending.timer);
      this.#pending = null;
      pending.resolve(envelope.message);
      return;
    }
    if (this.#streamHandler) {
      this.#streamHandler(envelope);
      return;
    }
    this.#fail(new ProtocolError("server sent an unsolicited message"));
    this.#socket.destroy();
  }

  #fail(error: Error): void {
    if (this.#closed) return;
    this.#closed = error;
    const pending = this.#pending;
    if (pending) {
      clearTimeout(pending.timer);
      this.#pending = null;
      pending.reject(error);
    }
    this.#streamClose?.(error);
  }
}

export function decodeFrame(payload: Uint8Array): Envelope {
  return decodeEnvelope(payload);
}
