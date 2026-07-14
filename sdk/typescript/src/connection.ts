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
