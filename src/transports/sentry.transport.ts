/**
 * Sentry transport.
 *
 * Sends entries at or above `minLevel` (default `error`) to Sentry as events and
 * everything below it as breadcrumbs (or as Sentry Logs when `logs: true`). It has
 * no dependency on `@sentry/*`: pass your initialised Sentry namespace, typed
 * structurally by `SentryLike`.
 *
 * Transports receive entries after redaction, so nothing here sees a value the
 * logger's `redact` config removed. A serialized error (`data.error`, written by
 * `logger.error(err)`) is rebuilt into an `Error` with the original name, message
 * and stack, so Sentry groups by the real stack.
 *
 * @example
 * import * as Sentry from '@sentry/node';
 * transports: { custom: [ new SentryTransport({ sentry: Sentry }) ] }
 */

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';

export type SentrySeverity = 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug';
type SentryLogMethod = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

/** The part of a Sentry scope the transport uses. `withScope` hands one to its callback. */
export interface SentryScopeLike {
  setLevel(level: SentrySeverity): unknown;
  setTag(key: string, value: string): unknown;
  setExtras(extras: Record<string, unknown>): unknown;
  setContext(name: string, context: Record<string, unknown> | null): unknown;
}

/** The part of the Sentry Logs API (`Sentry.logger`, SDK 9.41+) the transport uses. */
export type SentryLoggerLike = Partial<
  Record<SentryLogMethod, (message: string, attributes?: Record<string, unknown>) => unknown>
>;

/**
 * The part of the Sentry JS namespace the transport calls (`import * as Sentry from
 * '@sentry/node'` satisfies it). Only the two capture functions are required.
 */
export interface SentryLike {
  captureException(exception: unknown, hint?: unknown): unknown;
  captureMessage(message: string, hint?: unknown): unknown;
  addBreadcrumb?(breadcrumb: Record<string, unknown>): unknown;
  withScope?(callback: (scope: SentryScopeLike) => void): unknown;
  logger?: SentryLoggerLike;
  flush?(timeout?: number): PromiseLike<unknown>;
}

export interface SentryTransportConfig {
  /** Your initialised Sentry namespace, e.g. `import * as Sentry from '@sentry/node'`. */
  sentry: SentryLike;
  /**
   * Lowest level sent as a Sentry event. Lower levels become breadcrumbs or logs.
   * A logixia level name; compared by its Sentry severity. Default: 'error'.
   */
  minLevel?: string;
  /**
   * Send levels below `minLevel` to the Sentry Logs API (`sentry.logger`) instead of
   * breadcrumbs. Needs SDK 9.41+ with `enableLogs: true` in `Sentry.init` (on by default
   * from 10.71). Default: false. Without `sentry.logger` it falls back to breadcrumbs.
   */
  logs?: boolean;
  /** Record levels below `minLevel` as breadcrumbs (when not sent as logs). Default: true. */
  breadcrumbs?: boolean;
  /** Extra or overriding level -> Sentry severity mappings, e.g. for custom levels. */
  levelMap?: Record<string, SentrySeverity>;
  /** Max ms `flush()` and `close()` wait for `sentry.flush`. Default: 2000. */
  flushTimeoutMs?: number;
  filter?: (entry: TransportLogEntry) => boolean;
}

const DEFAULT_FLUSH_TIMEOUT_MS = 2000;
const MAX_CAUSE_DEPTH = 5;
const MAX_TAG_LENGTH = 200;

const SEVERITY_RANK: Record<SentrySeverity, number> = {
  debug: 0,
  log: 1,
  info: 2,
  warning: 3,
  error: 4,
  fatal: 5,
};

const BUILTIN_SEVERITY: Record<string, SentrySeverity> = {
  fatal: 'fatal',
  error: 'error',
  warn: 'warning',
  warning: 'warning',
  info: 'info',
  log: 'log',
  debug: 'debug',
  verbose: 'debug',
  trace: 'debug',
};

const LOG_METHOD_BY_LEVEL: Record<string, SentryLogMethod> = {
  trace: 'trace',
  verbose: 'trace',
  debug: 'debug',
  info: 'info',
  log: 'info',
  warn: 'warn',
  warning: 'warn',
  error: 'error',
  fatal: 'fatal',
};

const LOG_METHOD_BY_SEVERITY: Record<SentrySeverity, SentryLogMethod> = {
  debug: 'debug',
  log: 'info',
  info: 'info',
  warning: 'warn',
  error: 'error',
  fatal: 'fatal',
};

export class SentryTransport implements IAsyncTransport {
  public readonly name = 'sentry';
  public filter?: (entry: TransportLogEntry) => boolean;

  private readonly sentry: SentryLike;
  private readonly minRank: number;
  private readonly useLogs: boolean;
  private readonly useBreadcrumbs: boolean;
  private readonly levelMap: Readonly<Record<string, SentrySeverity>>;
  private readonly flushTimeoutMs: number;
  private warnedNoLogger = false;

  constructor(config: SentryTransportConfig) {
    const sentry = config?.sentry as SentryLike | undefined;
    if (
      !sentry ||
      typeof sentry.captureException !== 'function' ||
      typeof sentry.captureMessage !== 'function'
    ) {
      throw new TypeError(
        'SentryTransport: `sentry` must provide captureException and captureMessage (pass `import * as Sentry from "@sentry/node"`)'
      );
    }
    this.sentry = sentry;
    this.levelMap = normalizeLevelMap(config.levelMap);
    const minLevel = (config.minLevel ?? 'error').toLowerCase();
    const minSeverity = this.levelMap[minLevel];
    if (!minSeverity) {
      throw new TypeError(`SentryTransport: unknown minLevel "${minLevel.slice(0, 40)}"`);
    }
    this.minRank = SEVERITY_RANK[minSeverity];
    this.useLogs = config.logs === true;
    this.useBreadcrumbs = config.breadcrumbs !== false;
    this.flushTimeoutMs = Math.max(0, config.flushTimeoutMs ?? DEFAULT_FLUSH_TIMEOUT_MS);
    if (config.filter) this.filter = config.filter;
  }

  write(entry: TransportLogEntry): void {
    try {
      const severity = this.severityOf(entry.level);
      if (SEVERITY_RANK[severity] >= this.minRank) {
        this.captureEvent(entry, severity);
      } else if (this.useLogs && this.sendLog(entry, severity)) {
        // sent to the Logs API
      } else if (this.useBreadcrumbs) {
        this.addBreadcrumb(entry, severity);
      }
    } catch (error) {
      internalError('SentryTransport: failed to send entry', error);
    }
  }

  async flush(): Promise<void> {
    const { flush } = this.sentry;
    if (typeof flush !== 'function') return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeout = new Promise<void>((resolve) => {
        timer = setTimeout(resolve, this.flushTimeoutMs + 50);
        timer.unref?.();
      });
      await Promise.race([Promise.resolve(flush.call(this.sentry, this.flushTimeoutMs)), timeout]);
    } catch (error) {
      internalError('SentryTransport: flush failed', error);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Flushes pending events; the Sentry client itself stays open for the application. */
  close(): Promise<void> {
    return this.flush();
  }

  private severityOf(level: string): SentrySeverity {
    return this.levelMap[level.toLowerCase()] ?? 'info';
  }

  private captureEvent(entry: TransportLogEntry, severity: SentrySeverity): void {
    const { error, rest } = splitError(entry.data);
    const tags: Record<string, string> = { logixia_level: truncate(entry.level) };
    if (entry.traceId) tags['trace_id'] = truncate(entry.traceId);
    if (entry.context) tags['context'] = truncate(entry.context);

    const extra: Record<string, unknown> = { ...rest };
    if (error && error.message !== entry.message) extra['logMessage'] = entry.message;

    const logixia: Record<string, unknown> = { level: entry.level };
    if (entry.traceId) logixia['traceId'] = entry.traceId;
    if (entry.context) logixia['context'] = entry.context;
    if (entry.appName) logixia['appName'] = entry.appName;
    if (entry.environment) logixia['environment'] = entry.environment;

    const capture = (hint?: unknown): void => {
      if (error) this.sentry.captureException(error, hint);
      else this.sentry.captureMessage(entry.message, hint ?? severity);
    };

    if (typeof this.sentry.withScope === 'function') {
      this.sentry.withScope((scope) => {
        scope.setLevel(severity);
        for (const [key, value] of Object.entries(tags)) scope.setTag(key, value);
        scope.setExtras(extra);
        scope.setContext('logixia', logixia);
        capture();
      });
    } else {
      capture({ level: severity, tags, extra, contexts: { logixia } });
    }
  }

  private sendLog(entry: TransportLogEntry, severity: SentrySeverity): boolean {
    const logger = this.sentry.logger;
    const method = logger
      ? (LOG_METHOD_BY_LEVEL[entry.level.toLowerCase()] ?? LOG_METHOD_BY_SEVERITY[severity])
      : undefined;
    const fn = method ? logger?.[method] : undefined;
    if (!fn) {
      if (!this.warnedNoLogger) {
        this.warnedNoLogger = true;
        internalWarn(
          'SentryTransport: logs: true but sentry.logger is unavailable (needs SDK 9.41+); using breadcrumbs'
        );
      }
      return false;
    }
    const attributes: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(entry.data ?? {})) attributes[key] = attr(value);
    if (entry.traceId) attributes['trace_id'] = entry.traceId;
    if (entry.context) attributes['context'] = entry.context;
    fn.call(logger, entry.message, attributes);
    return true;
  }

  private addBreadcrumb(entry: TransportLogEntry, severity: SentrySeverity): void {
    if (typeof this.sentry.addBreadcrumb !== 'function') return;
    const data: Record<string, unknown> = { ...entry.data };
    if (entry.traceId) data['traceId'] = entry.traceId;
    this.sentry.addBreadcrumb({
      category: entry.context ?? 'logixia',
      message: entry.message,
      level: severity,
      timestamp: entry.timestamp.getTime() / 1000,
      ...(Object.keys(data).length > 0 ? { data } : {}),
    });
  }
}

function normalizeLevelMap(
  custom?: Record<string, SentrySeverity>
): Record<string, SentrySeverity> {
  const map: Record<string, SentrySeverity> = { ...BUILTIN_SEVERITY };
  for (const [level, severity] of Object.entries(custom ?? {})) {
    if (severity in SEVERITY_RANK) map[level.toLowerCase()] = severity;
  }
  return map;
}

function truncate(value: string): string {
  return value.length > MAX_TAG_LENGTH ? value.slice(0, MAX_TAG_LENGTH) : value;
}

/** Sentry log attributes are primitives; anything else is sent as JSON text. */
function attr(value: unknown): string | number | boolean {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  return stringifyForLog(value);
}

function splitError(data: Record<string, unknown> | undefined): {
  error: Error | undefined;
  rest: Record<string, unknown>;
} {
  if (!data) return { error: undefined, rest: {} };
  const { error: raw, ...rest } = data;
  const error = toError(raw, 0);
  return error ? { error, rest } : { error: undefined, rest: data };
}

/** Rebuilds an Error from `serializeError` output (or passes a real Error through). */
function toError(value: unknown, depth: number): Error | undefined {
  if (value instanceof Error) return value;
  if (!value || typeof value !== 'object') return undefined;
  const { name, message, stack, cause } = value as Record<string, unknown>;
  if (typeof message !== 'string') return undefined;
  const error = new Error(message);
  const errorName = typeof name === 'string' && name ? name : 'Error';
  error.name = errorName;
  error.stack = typeof stack === 'string' && stack ? stack : `${errorName}: ${message}`;
  if (cause !== undefined && depth < MAX_CAUSE_DEPTH) {
    const nested = toError(cause, depth + 1);
    if (nested) (error as Error & { cause?: unknown }).cause = nested;
  }
  return error;
}
