/**
 * Pino-shaped facade over a logixia logger, for Fastify's `loggerInstance` option.
 *
 * Fastify checks `info`, `error`, `debug`, `fatal`, `warn`, `trace` and `child`, then
 * calls `loggerInstance.child({}, { serializers })` once and `child({ reqId }, opts)`
 * for every request. The facade accepts pino's call shapes, applies serializers (so
 * a raw request or reply is never written out) and forwards to logixia's
 * `(message, data)` API.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import { createLogger } from 'logixia';
 * import { createFastifyLogger } from 'logixia/fastify';
 *
 * const app = Fastify({ loggerInstance: createFastifyLogger(createLogger({ appName: 'api' })) });
 * ```
 */

import type { IBaseLogger } from '../types';
import { serializeError } from '../utils/error.utils';
import { internalError } from '../utils/internal-log';
import { assignOwn } from '../utils/own-property';
import { usableRequestId } from '../utils/request-trace';
import { stringifyForLog } from '../utils/safe-stringify';
import {
  buildNameSet,
  DEFAULT_REDACT_QUERY_PARAMS,
  redactUrlQuery,
} from '../utils/sensitive-names';
import { getCurrentTraceId, runWithTraceId } from '../utils/trace.utils';

// ── Public types ─────────────────────────────────────────────────────────────

export type PinoLevelName = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export type SerializerFn = (value: unknown) => unknown;

/** pino's log function: `(obj, msg?, ...args)` or `(msg, ...args)`. Always returns `void`. */
export interface PinoCompatibleLogFn {
  <T extends object>(obj: T, msg?: string, ...args: unknown[]): void;
  (obj: unknown, msg?: string, ...args: unknown[]): void;
  (msg: string, ...args: unknown[]): void;
}

export interface PinoChildOptions {
  /** Level for the child: a pino level name, `silent`, or a logixia level name. */
  level?: string | undefined;
  /** Serializers added to (and overriding) the ones the parent already has. */
  serializers?: Record<string, SerializerFn> | undefined;
}

/** The pino surface Fastify and its plugins use. Satisfies `FastifyBaseLogger` without importing it. */
export interface PinoCompatibleLogger {
  trace: PinoCompatibleLogFn;
  debug: PinoCompatibleLogFn;
  info: PinoCompatibleLogFn;
  warn: PinoCompatibleLogFn;
  error: PinoCompatibleLogFn;
  fatal: PinoCompatibleLogFn;
  /** Accepts the call and writes nothing, like pino's `silent`. */
  silent: PinoCompatibleLogFn;
  /** Current level: a pino level name, `silent`, or a logixia-only level such as `verbose`. */
  level: string;
  /** Numeric value of the current level (pino scale), `Infinity` when silent. */
  readonly levelVal: number;
  readonly levels: {
    readonly values: Record<string, number>;
    readonly labels: Record<number, string>;
  };
  /** Serializers Fastify merges over its own, so these win for `req`, `res` and `err`. */
  readonly serializers: Record<string, SerializerFn>;
  /** True when the configured level would let `level` through. */
  isLevelEnabled(level: string): boolean;
  /** The fields bound to this logger by `child()`. */
  bindings(): Record<string, unknown>;
  child(bindings: Record<string, unknown>, options?: PinoChildOptions): PinoCompatibleLogger;
}

export interface FastifyLoggerOptions {
  /**
   * Serializers keyed by field name. They replace the defaults for `req`, `res` and
   * `err` and apply to any other key you add.
   */
  serializers?: Record<string, SerializerFn>;
  /**
   * Query-string parameter names redacted from the `req` URL, merged with the defaults
   * (token, access_token, refresh_token, code, password, secret, api_key, ...).
   */
  redactQueryParams?: string[];
  /**
   * Binding whose value becomes the trace ID of entries logged outside a trace scope.
   * Default: `'reqId'` (Fastify's `requestIdLogLabel`). Counter IDs such as `req-1`
   * are never used. Pass `false` to leave trace IDs alone.
   */
  traceIdBinding?: string | false;
}

export interface FastifySerializerOptions {
  redactQueryParams?: string[];
}

// ── Levels ───────────────────────────────────────────────────────────────────

const PINO_LEVEL_VALUES: Record<string, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
};
const PINO_LEVEL_LABELS: Record<number, string> = {
  10: 'trace',
  20: 'debug',
  30: 'info',
  40: 'warn',
  50: 'error',
  60: 'fatal',
};

/** Severity rank in logixia's order: lower is more severe. */
const RANK: Record<string, number> = {
  fatal: 0,
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
  trace: 4,
  verbose: 5,
};

type Writer = 'error' | 'warn' | 'info' | 'debug' | 'trace';

// ── Serializers ──────────────────────────────────────────────────────────────

type Obj = Record<string, unknown>;

const asObject = (value: unknown): Obj | undefined =>
  typeof value === 'object' && value !== null ? (value as Obj) : undefined;

const firstString = (value: unknown): string | undefined =>
  typeof value === 'string' && value !== '' ? value : undefined;

/** The host without its port; an IPv6 literal keeps its brackets. */
function hostnameOf(host: string | undefined): string | undefined {
  if (host === undefined) return host;
  return host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':', 1)[0];
}

/**
 * pino-std-like `req`, `res` and `err` serializers. `req` reads a Fastify request or a
 * Node `IncomingMessage` and keeps only method, url (query secrets redacted), hostname,
 * remote address and port, and the request ID; headers, body and sockets are dropped.
 */
export function createFastifySerializers(
  options: FastifySerializerOptions = {}
): Record<'req' | 'res' | 'err', SerializerFn> {
  const params = buildNameSet(DEFAULT_REDACT_QUERY_PARAMS, options.redactQueryParams);

  return {
    req(value) {
      const req = asObject(value);
      if (!req) return value;
      const raw = asObject(req['raw']);
      const headers = asObject(req['headers']) ?? asObject(raw?.['headers']);
      const socket = asObject(req['socket']) ?? asObject(raw?.['socket']);
      const url = firstString(req['originalUrl']) ?? firstString(req['url']);
      const out: Obj = {
        method: req['method'] ?? raw?.['method'],
        url: url === undefined ? url : redactUrlQuery(url, params),
        hostname: hostnameOf(firstString(req['host']) ?? firstString(headers?.['host'])),
        remoteAddress: req['ip'] ?? socket?.['remoteAddress'],
        remotePort: socket?.['remotePort'],
      };
      if (typeof req['id'] === 'string' || typeof req['id'] === 'number') out['reqId'] = req['id'];
      return out;
    },
    res(value) {
      const res = asObject(value);
      return res ? { statusCode: res['statusCode'] } : value;
    },
    err(value) {
      return value instanceof Error ? serializeError(value) : value;
    },
  };
}

function applySerializers(source: Obj, serializers: Record<string, SerializerFn>): Obj {
  const out: Obj = {};
  const renameErr = source['err'] instanceof Error && !('error' in source);
  for (const key of Object.keys(source)) {
    const value = source[key];
    const serializer = serializers[key];
    let result = value;
    if (serializer !== undefined && value !== undefined) {
      try {
        result = serializer(value);
      } catch (error) {
        internalError(`fastify logger: '${key}' serializer failed`, error);
        result = '[serializer failed]';
      }
    }
    assignOwn(out, renameErr && key === 'err' ? 'error' : key, result);
  }
  return out;
}

// ── Argument parsing ─────────────────────────────────────────────────────────

const stringify = (value: unknown): string => stringifyForLog(value) ?? String(value);

function interpolate(format: string, args: unknown[], start: number): string {
  if (args.length <= start || !format.includes('%')) return format;
  let next = start;
  return format.replace(/%([%sdifjoO])/g, (match, token: string) => {
    if (token === '%') return '%';
    if (next >= args.length) return match;
    const arg = args[next++];
    switch (token) {
      case 's':
        if (typeof arg === 'string') return arg;
        if (typeof arg === 'function') return arg.name || '<anonymous>';
        return typeof arg === 'object' && arg !== null ? stringify(arg) : String(arg);
      case 'd':
        return String(Number(arg));
      case 'i':
        return String(Number.parseInt(String(arg), 10));
      case 'f':
        return String(Number.parseFloat(String(arg)));
      default:
        return stringify(arg);
    }
  });
}

interface ParsedCall {
  message: string;
  data: Obj | undefined;
}

function parseCall(args: unknown[], serializers: Record<string, SerializerFn>): ParsedCall {
  const first = args[0];
  const second = args[1];
  const describe = (fallback: string): string => {
    if (second === undefined) return fallback;
    return typeof second === 'string' ? interpolate(second, args, 2) : stringify(second);
  };

  if (first instanceof Error) {
    const serialize = serializers['err'];
    return {
      message: describe(first.message),
      data: { error: serialize ? serialize(first) : serializeError(first) },
    };
  }
  if (typeof first === 'object' && first !== null && !Array.isArray(first)) {
    const data = applySerializers(first as Obj, serializers);
    const err = (first as Obj)['err'];
    return { message: describe(err instanceof Error ? err.message : ''), data };
  }
  return typeof first === 'string'
    ? { message: interpolate(first, args, 1), data: undefined }
    : { message: stringify(first), data: undefined };
}

/** Fire-and-forget: a rejected log call must never become an unhandled rejection. */
function fire(result: unknown): void {
  if (result && typeof (result as Promise<unknown>).catch === 'function') {
    (result as Promise<unknown>).catch((error: unknown) =>
      internalError('fastify logger: log call failed', error)
    );
  }
}

// ── Facade ───────────────────────────────────────────────────────────────────

function toLogixiaLevel(level: string): string {
  return level === 'fatal' ? 'error' : level;
}

class FastifyLoggerFacade implements PinoCompatibleLogger {
  readonly levels = { values: PINO_LEVEL_VALUES, labels: PINO_LEVEL_LABELS };

  constructor(
    private readonly target: IBaseLogger,
    readonly serializers: Record<string, SerializerFn>,
    private readonly bound: Obj,
    private readonly traceIdBinding: string | false,
    private readonly traceId: string | undefined,
    private muted: boolean
  ) {}

  trace(...args: unknown[]): void {
    this.write('trace', args);
  }
  debug(...args: unknown[]): void {
    this.write('debug', args);
  }
  info(...args: unknown[]): void {
    this.write('info', args);
  }
  warn(...args: unknown[]): void {
    this.write('warn', args);
  }
  error(...args: unknown[]): void {
    this.write('error', args);
  }
  fatal(...args: unknown[]): void {
    this.write('error', args);
  }
  silent(..._args: unknown[]): void {}

  get level(): string {
    return this.muted ? 'silent' : this.target.getLevel();
  }

  set level(level: string) {
    if (level === 'silent') {
      this.muted = true;
      return;
    }
    this.muted = false;
    this.target.setLevel(toLogixiaLevel(level));
  }

  get levelVal(): number {
    return this.muted ? Infinity : (PINO_LEVEL_VALUES[this.level] ?? PINO_LEVEL_VALUES['info']!);
  }

  isLevelEnabled(level: string): boolean {
    if (this.muted) return false;
    const wanted = RANK[level];
    const current = RANK[this.target.getLevel()];
    return wanted === undefined || current === undefined || wanted <= current;
  }

  bindings(): Record<string, unknown> {
    return { ...this.bound };
  }

  child(bindings: Record<string, unknown>, options: PinoChildOptions = {}): PinoCompatibleLogger {
    const serializers = options.serializers
      ? { ...this.serializers, ...options.serializers }
      : this.serializers;
    const fields = applySerializers(bindings ?? {}, serializers);
    const traceId = this.traceIdBinding ? usableRequestId(fields[this.traceIdBinding]) : undefined;
    const child = new FastifyLoggerFacade(
      this.target.child(this.target.getContext() ?? '', fields),
      serializers,
      { ...this.bound, ...fields },
      this.traceIdBinding,
      traceId ?? this.traceId,
      this.muted
    );
    if (options.level) child.level = options.level;
    return child;
  }

  private write(method: Writer, args: unknown[]): void {
    if (this.muted) return;
    try {
      const { message, data } = parseCall(args, this.serializers);
      const traceId = this.traceId;
      const send = (): void => fire(this.target[method](message, data));
      if (traceId !== undefined && getCurrentTraceId() === undefined) runWithTraceId(traceId, send);
      else send();
    } catch (error) {
      internalError('fastify logger: log call failed', error);
    }
  }
}

/**
 * Wrap a logixia logger so Fastify accepts it as `loggerInstance`.
 *
 * - Call shapes: `(obj, msg?, ...args)`, `(msg, ...args)` with `%s %d %i %f %j %o %O`,
 *   and `(err)` / `(err, msg)`. An `Error` under `err` is logged under `error`, like
 *   `logger.error(err)` does, with its stack and `cause` chain.
 * - `fatal` is logged at `error`. `silent` mutes the facade (and children made after).
 * - `child(bindings)` creates a logixia child that carries the bindings as context data.
 *   It starts no transports and registers nothing for shutdown, so one per request is cheap.
 * - Methods return `void`; rejected log calls are caught.
 * - `req`, `res` and `err` serializers are supplied; Fastify gives them precedence over
 *   its own. Override or extend them with `options.serializers`.
 *
 * @example
 * ```ts
 * const app = Fastify({ loggerInstance: createFastifyLogger(logger) });
 * ```
 */
export function createFastifyLogger(
  logger: IBaseLogger,
  options: FastifyLoggerOptions = {}
): PinoCompatibleLogger {
  const serializers: Record<string, SerializerFn> = {
    ...createFastifySerializers(
      options.redactQueryParams ? { redactQueryParams: options.redactQueryParams } : {}
    ),
    ...options.serializers,
  };
  return new FastifyLoggerFacade(
    logger,
    serializers,
    {},
    options.traceIdBinding ?? 'reqId',
    undefined,
    false
  );
}
