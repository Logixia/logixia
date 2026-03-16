/**
 * logixia — Browser / Edge Runtime entry point
 *
 * This module is the browser-safe subset of logixia. It contains **no**
 * references to Node.js built-ins (`node:fs`, `node:http`, `node:worker_threads`,
 * `node:crypto`, `node:async_hooks`) so it can be bundled for:
 *
 * - Browser (Webpack / Vite / esbuild)
 * - Cloudflare Workers / Vercel Edge Functions
 * - Deno (via ESM import)
 * - Bun (core subset, no file/DB transports)
 *
 * Excluded from this entry: FileTransport, DatabaseTransport, WorkerTransport,
 * CloudWatchTransport, GCPTransport, AzureMonitorTransport, and anything that
 * requires `AsyncLocalStorage`.
 *
 * @example Basic browser usage
 * ```ts
 * import { createBrowserLogger, BrowserConsoleTransport } from 'logixia/browser';
 *
 * const logger = createBrowserLogger({ appName: 'my-app' });
 * logger.info('Page loaded', { url: location.href });
 * ```
 *
 * @example Custom transport in browser
 * ```ts
 * import { createBrowserLogger, BrowserConsoleTransport } from 'logixia/browser';
 *
 * const logger = createBrowserLogger({
 *   appName: 'my-app',
 *   json: false,       // pretty-print in devtools
 *   level: 'debug',
 * });
 * ```
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type BrowserLogLevel = 'verbose' | 'debug' | 'info' | 'warn' | 'error' | 'critical';

export interface BrowserLogEntry {
  timestamp: string;
  level: BrowserLogLevel;
  appName: string;
  message: string;
  payload?: Record<string, unknown>;
  traceId?: string;
  context?: string;
}

export interface BrowserLoggerConfig {
  /** Application name shown in every log entry. @default 'App' */
  appName?: string;
  /** Minimum log level to emit. @default 'info' */
  level?: BrowserLogLevel;
  /**
   * When `true` serializes entries as compact JSON strings — useful for
   * structured logging pipelines (Sentry breadcrumbs, LogRocket, etc.).
   * When `false` (default) uses console group/table for devtools-friendly output.
   */
  json?: boolean;
  /**
   * Additional transports to write to (e.g. a remote analytics endpoint).
   * The built-in `BrowserConsoleTransport` is always added unless `silent: true`.
   */
  transports?: IBrowserTransport[];
  /** Suppress all output (useful for tests). @default false */
  silent?: boolean;
  /** Static context fields merged into every log entry. */
  context?: Record<string, unknown>;
}

export interface IBrowserTransport {
  name: string;
  level?: BrowserLogLevel;
  write(entry: BrowserLogEntry): void;
}

// ── Level ordering ────────────────────────────────────────────────────────────

const LEVEL_ORDER: Record<BrowserLogLevel, number> = {
  verbose: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  critical: 5,
};

function shouldLog(entryLevel: BrowserLogLevel, minLevel: BrowserLogLevel): boolean {
  return LEVEL_ORDER[entryLevel] >= LEVEL_ORDER[minLevel];
}

// ── Browser Console Transport ─────────────────────────────────────────────────

/**
 * Default browser transport — writes to the browser console using native
 * level methods so devtools can filter by severity.
 *
 * In pretty mode (default):
 *   - Groups each entry under a collapsible header with timestamp + app name
 *   - Payload displayed as an expandable object via `console.table` / `console.dir`
 *
 * In JSON mode:
 *   - Emits compact JSON strings via `console.log` / `console.error`
 */
export class BrowserConsoleTransport implements IBrowserTransport {
  public readonly name = 'browser-console';
  public readonly level?: BrowserLogLevel;

  private readonly json: boolean;

  constructor(options: { json?: boolean; level?: BrowserLogLevel } = {}) {
    this.json = options.json ?? false;
    if (options.level !== undefined) this.level = options.level;
  }

  write(entry: BrowserLogEntry): void {
    if (this.json) {
      this.writeJson(entry);
    } else {
      this.writePretty(entry);
    }
  }

  /* eslint-disable no-console */
  private writeJson(entry: BrowserLogEntry): void {
    const line = JSON.stringify(entry);
    switch (entry.level) {
      case 'verbose':
      case 'debug':
        console.debug(line);
        break;
      case 'warn':
        console.warn(line);
        break;
      case 'error':
      case 'critical':
        console.error(line);
        break;
      default:
        console.log(line);
    }
  }

  private writePretty(entry: BrowserLogEntry): void {
    const { timestamp, level, appName, message, payload, context } = entry;

    const ts = timestamp.slice(11, 23); // HH:MM:SS.mmm
    const contextLabel = context ? ` [${context}]` : '';
    const prefix = `[${appName}]${contextLabel}`;
    const levelLabel = level.toUpperCase().padEnd(8);

    const header = `%c${ts} %c${levelLabel} %c${prefix} ${message}`;
    const tsStyle = 'color: #888; font-size: 11px;';
    const levelStyle = this.levelStyle(level);
    const msgStyle = 'color: inherit; font-weight: normal;';

    const hasPayload = payload && Object.keys(payload).length > 0;

    if (hasPayload) {
      console.groupCollapsed(header, tsStyle, levelStyle, msgStyle);
      console.dir(payload);
      console.groupEnd();
    } else {
      switch (level) {
        case 'verbose':
        case 'debug':
          console.debug(header, tsStyle, levelStyle, msgStyle);
          break;
        case 'warn':
          console.warn(header, tsStyle, levelStyle, msgStyle);
          break;
        case 'error':
        case 'critical':
          console.error(header, tsStyle, levelStyle, msgStyle);
          break;
        default:
          console.log(header, tsStyle, levelStyle, msgStyle);
      }
    }
  }
  /* eslint-enable no-console */

  private levelStyle(level: BrowserLogLevel): string {
    const styles: Record<BrowserLogLevel, string> = {
      verbose: 'color: #aaa; font-weight: bold;',
      debug: 'color: #7ec8e3; font-weight: bold;',
      info: 'color: #4caf50; font-weight: bold;',
      warn: 'color: #ff9800; font-weight: bold;',
      error: 'color: #f44336; font-weight: bold;',
      critical: 'color: #fff; background: #f44336; font-weight: bold; padding: 1px 4px;',
    };
    return styles[level] ?? 'color: inherit; font-weight: bold;';
  }
}

// ── Remote Batch Transport ────────────────────────────────────────────────────

/**
 * Browser transport that batches log entries and sends them to a remote
 * HTTP endpoint via `fetch` (available in all modern browsers and Edge runtimes).
 *
 * @example
 * ```ts
 * const logger = createBrowserLogger({
 *   transports: [
 *     new BrowserRemoteTransport({
 *       url: '/api/logs',
 *       batchSize: 50,
 *       flushIntervalMs: 10_000,
 *     }),
 *   ],
 * });
 * ```
 */
export class BrowserRemoteTransport implements IBrowserTransport {
  public readonly name = 'browser-remote';
  public readonly level?: BrowserLogLevel;

  private readonly url: string;
  private readonly batchSize: number;
  private readonly flushIntervalMs: number;
  private readonly headers: Record<string, string>;

  private batch: BrowserLogEntry[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: {
    /** Endpoint URL to POST batched log entries to. */
    url: string;
    /** Headers added to each request (e.g. `Authorization`). @default {} */
    headers?: Record<string, string>;
    /** Max entries per batch. @default 100 */
    batchSize?: number;
    /** Auto-flush interval in milliseconds. @default 5000 */
    flushIntervalMs?: number;
    level?: BrowserLogLevel;
  }) {
    this.url = options.url;
    this.headers = options.headers ?? {};
    this.batchSize = options.batchSize ?? 100;
    this.flushIntervalMs = options.flushIntervalMs ?? 5000;
    if (options.level !== undefined) this.level = options.level;
    this.scheduleFlush();
  }

  write(entry: BrowserLogEntry): void {
    this.batch.push(entry);
    if (this.batch.length >= this.batchSize) {
      this.flush();
    }
  }

  async flush(): Promise<void> {
    if (this.batch.length === 0) return;
    const entries = this.batch.splice(0, this.batchSize);
    try {
      await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this.headers },
        body: JSON.stringify(entries),
        keepalive: true, // survives page unload
      });
    } catch {
      // Silently restore on failure — best effort in browser
      this.batch.unshift(...entries);
    }
  }

  private scheduleFlush(): void {
    if (
      typeof globalThis !== 'undefined' &&
      typeof (globalThis as Record<string, unknown>)['setInterval'] === 'function'
    ) {
      this.timer = setInterval(() => {
        this.flush().catch(() => {});
      }, this.flushIntervalMs);
    }
  }

  destroy(): void {
    if (this.timer !== null) clearInterval(this.timer);
  }
}

// ── Core Browser Logger ───────────────────────────────────────────────────────

/**
 * Lightweight browser-safe logger.
 *
 * Unlike the Node.js `LogixiaLogger`, this implementation has **zero**
 * Node.js dependencies. It can be bundled for any runtime.
 */
export class BrowserLogger {
  private readonly config: Required<Pick<BrowserLoggerConfig, 'appName' | 'level' | 'silent'>> & {
    context: Record<string, unknown> | undefined;
  };
  private readonly transports: IBrowserTransport[];

  constructor(config: BrowserLoggerConfig = {}) {
    this.config = {
      appName: config.appName ?? 'App',
      level: config.level ?? 'info',
      silent: config.silent ?? false,
      context: config.context,
    };

    if (config.silent) {
      this.transports = [];
    } else {
      const builtIn = new BrowserConsoleTransport({ json: config.json ?? false });
      this.transports = [builtIn, ...(config.transports ?? [])];
    }
  }

  // ── Logging methods ───────────────────────────────────────────────────────

  verbose(message: string, payload?: Record<string, unknown>): void {
    this.emit('verbose', message, payload);
  }

  debug(message: string, payload?: Record<string, unknown>): void {
    this.emit('debug', message, payload);
  }

  info(message: string, payload?: Record<string, unknown>): void {
    this.emit('info', message, payload);
  }

  log(message: string, payload?: Record<string, unknown>): void {
    this.emit('info', message, payload);
  }

  warn(message: string, payload?: Record<string, unknown>): void {
    this.emit('warn', message, payload);
  }

  error(message: string, payload?: Record<string, unknown>): void {
    this.emit('error', message, payload);
  }

  critical(message: string, payload?: Record<string, unknown>): void {
    this.emit('critical', message, payload);
  }

  /**
   * Create a child logger that inherits config and merges extra context fields
   * into every emitted entry.
   *
   * @example
   * ```ts
   * const childLogger = logger.child({ context: 'AuthService', userId: '42' });
   * childLogger.info('Login succeeded'); // → { context: 'AuthService', userId: '42', ... }
   * ```
   */
  child(extraContext: Record<string, unknown>): BrowserLogger {
    // Exclude 'context' string label from data fields (used for identification only)
    const { _, ...rest } = extraContext;
    // _context (string label) is intentionally unused — it's stripped from the data payload
    return new BrowserLogger({
      appName: this.config.appName,
      level: this.config.level,
      silent: this.config.silent,
      context: { ...this.config.context, ...rest },
      // Reuse existing transport list
      transports: this.transports.filter((t) => t.name !== 'browser-console'),
    });
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private emit(level: BrowserLogLevel, message: string, payload?: Record<string, unknown>): void {
    if (!shouldLog(level, this.config.level)) return;

    const entry: BrowserLogEntry = {
      timestamp: new Date().toISOString(),
      level,
      appName: this.config.appName,
      message,
      ...(payload || this.config.context
        ? { payload: { ...this.config.context, ...payload } }
        : {}),
    };

    for (const transport of this.transports) {
      if (transport.level && !shouldLog(level, transport.level)) continue;
      transport.write(entry);
    }
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create a browser-safe logixia logger instance.
 *
 * @example
 * ```ts
 * import { createBrowserLogger } from 'logixia/browser';
 *
 * const logger = createBrowserLogger({ appName: 'checkout', level: 'debug' });
 * logger.info('Cart updated', { itemCount: 3, total: 49.99 });
 * ```
 */
export function createBrowserLogger(config?: BrowserLoggerConfig): BrowserLogger {
  return new BrowserLogger(config);
}

// ── Re-exports of browser-safe utilities ─────────────────────────────────────

// OTel utilities are browser-safe (dynamic require with try/catch)
export type { OtelBridgeOptions, OtelSpanContext } from './utils/otel';
export {
  disableOtelBridge,
  getActiveOtelContext,
  getOtelMetaFields,
  initOtelBridge,
} from './utils/otel';

// Typed logger utilities are pure TypeScript, no runtime deps
export type {
  CompiledSchema,
  LogFieldDef,
  LogFieldType,
  LoggerLike,
  LogSchema,
  TypedLogger,
} from './utils/typed-logger';
export { createTypedLogger, defineLogSchema } from './utils/typed-logger';

/**
 * Default browser logger instance (singleton, console transport, info level).
 *
 * @example
 * ```ts
 * import { browserLogger } from 'logixia/browser';
 * browserLogger.info('Hello from browser');
 * ```
 */
export const browserLogger = new BrowserLogger({ appName: 'App' });
