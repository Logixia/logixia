/**
 * logixia/testing — Zero-dependency mock logger for Vitest & Jest.
 *
 * @example
 * ```ts
 * import { createMockLogger } from 'logixia/testing';
 *
 * const mock = createMockLogger();
 * await myService.doSomething(mock.logger);
 *
 * mock.expectLog('info', { message: 'order created' });
 * mock.expectLog('error', { message: /failed/ });
 * mock.reset();
 * ```
 */

import type { IBaseLogger, LogEntry } from '../types';

// ── Types ────────────────────────────────────────────────────────────────────

export interface MockLogCall {
  level: string;
  message: string;
  data?: Record<string, unknown>;
  /** Full LogEntry shape for assertions that inspect the complete record. */
  entry: Pick<LogEntry, 'level' | 'message' | 'context'> & { data?: Record<string, unknown> };
}

export type LogMatcher =
  | string
  | RegExp
  | ((call: MockLogCall) => boolean)
  | Partial<Record<'message' | 'level' | string, unknown>>;

export interface MockLoggerInstance {
  /** The logger itself — pass this where an IBaseLogger is expected. */
  readonly logger: IBaseLogger;
  /** Every call recorded across all levels, in insertion order. */
  readonly calls: MockLogCall[];
  /**
   * Get all calls for a specific level (case-insensitive). If `level` is
   * omitted, returns all calls across every level.
   */
  getCalls(level?: string): MockLogCall[];
  /** Return the most recent call, optionally filtered by level. */
  getLastCall(level?: string): MockLogCall | undefined;
  /**
   * Assert that at least one recorded call matches `matcher`.
   *
   * - string → exact message match
   * - RegExp → message test
   * - function → receives the full MockLogCall
   * - object → every key/value must match (supports RegExp values)
   *
   * Throws an Error with a descriptive message if the assertion fails (works
   * with both Vitest `expect` and Jest matchers via `.toThrow()`, or you can
   * let it propagate directly).
   */
  expectLog(level: string, matcher?: LogMatcher): void;
  /**
   * Assert that NO recorded call matches `matcher` at the given level.
   */
  expectNoLog(level: string, matcher?: LogMatcher): void;
  /** Clear all recorded calls. Call between tests. */
  reset(): void;
  /**
   * Silence — when true, the mock suppresses all console output from the
   * logger. Default: true.
   */
  silent: boolean;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function resolveCallField(call: MockLogCall, key: string): unknown {
  if (key === 'message') return call.message;
  if (key === 'level') return call.level;
  return call.data?.[key] ?? (call.entry as Record<string, unknown>)[key];
}

function formatMatcherDescription(matcher: LogMatcher | undefined): string {
  if (matcher === undefined) return '(any)';
  if (matcher instanceof RegExp) return matcher.toString();
  return JSON.stringify(matcher);
}

function matchesCall(call: MockLogCall, matcher?: LogMatcher): boolean {
  if (matcher === undefined) return true;
  if (typeof matcher === 'string') return call.message === matcher;
  if (matcher instanceof RegExp) return matcher.test(call.message);
  if (typeof matcher === 'function') return matcher(call);
  // Object shape: every key/value must match
  for (const [key, expected] of Object.entries(matcher)) {
    const actual = resolveCallField(call, key);
    if (expected instanceof RegExp) {
      if (!expected.test(String(actual ?? ''))) return false;
    } else {
      if (actual !== expected) return false;
    }
  }
  return true;
}

function formatCalls(calls: MockLogCall[]): string {
  if (calls.length === 0) return '  (no calls recorded)';
  return calls
    .map((c) => `  [${c.level}] "${c.message}" ${c.data ? JSON.stringify(c.data) : ''}`)
    .join('\n');
}

// ── Implementation ────────────────────────────────────────────────────────────

/**
 * Create a mock logger for use in tests.
 *
 * The returned object implements `IBaseLogger` and additionally exposes `.calls`,
 * `.getCalls()`, `.getLastCall()`, `.expectLog()`, `.expectNoLog()`, and `.reset()`.
 *
 * @param options.silent  Suppress console output (default: true)
 * @param options.context Optional context label written into every `entry.context`
 */
export function createMockLogger(
  options: { silent?: boolean; context?: string } = {}
): MockLoggerInstance {
  const { silent = true, context } = options;
  const _calls: MockLogCall[] = [];

  function record(
    level: string,
    messageOrError: string | Error,
    data?: Record<string, unknown>
  ): void {
    const message = messageOrError instanceof Error ? messageOrError.message : messageOrError;
    const extraData =
      messageOrError instanceof Error
        ? { ...data, error: { message: messageOrError.message, stack: messageOrError.stack } }
        : data;

    _calls.push({
      level,
      message,
      data: extraData,
      entry: { level, message, context, data: extraData },
    });
  }

  const logger: IBaseLogger = {
    async error(messageOrError, data) {
      record('error', messageOrError as string | Error, data);
    },
    async warn(message, data) {
      record('warn', message, data);
    },
    async info(message, data) {
      record('info', message, data);
    },
    async debug(message, data) {
      record('debug', message, data);
    },
    async trace(message, data) {
      record('trace', message, data);
    },
    async verbose(message, data) {
      record('verbose', message, data);
    },
    async logLevel(level, message, data) {
      record(level, message, data);
    },

    time(_label) {
      /* no-op in tests */
    },
    async timeEnd(_label) {
      return 0;
    },
    async timeAsync(_label, fn) {
      return fn();
    },

    setLevel(_level) {
      /* no-op */
    },
    getLevel() {
      return 'info';
    },
    setContext(_ctx) {
      /* no-op */
    },
    getContext() {
      return context;
    },

    enableField(_f) {
      /* no-op */
    },
    disableField(_f) {
      /* no-op */
    },
    isFieldEnabled(_f) {
      return true;
    },
    getFieldState() {
      return {};
    },
    resetFieldState() {
      /* no-op */
    },

    enableTransportLevelPrompting() {
      /* no-op */
    },
    disableTransportLevelPrompting() {
      /* no-op */
    },
    setTransportLevels(_id, _levels) {
      /* no-op */
    },
    getTransportLevels(_id) {
      return;
    },
    clearTransportLevelPreferences() {
      /* no-op */
    },
    getAvailableTransports() {
      return [];
    },

    child(ctx, _data) {
      return createMockLogger({ silent, context: ctx }).logger;
    },
    async close() {
      /* no-op */
    },
    async flush() {
      /* no-op */
    },
    async healthCheck() {
      return { healthy: true, details: {} };
    },
  };

  const instance: MockLoggerInstance = {
    get logger() {
      return logger;
    },
    get calls() {
      return _calls;
    },

    getCalls(level?: string): MockLogCall[] {
      if (!level) return [..._calls];
      const l = level.toLowerCase();
      return _calls.filter((c) => c.level.toLowerCase() === l);
    },

    getLastCall(level?: string): MockLogCall | undefined {
      const filtered = level
        ? _calls.filter((c) => c.level.toLowerCase() === level.toLowerCase())
        : _calls;
      return filtered[filtered.length - 1];
    },

    expectLog(level: string, matcher?: LogMatcher): void {
      const levelCalls = instance.getCalls(level);
      const matched = levelCalls.some((c) => matchesCall(c, matcher));
      if (!matched) {
        const matcherDesc = formatMatcherDescription(matcher);
        throw new Error(
          `Expected at least one [${level}] log matching ${matcherDesc}.\n` +
            `Recorded calls:\n${formatCalls(_calls)}`
        );
      }
    },

    expectNoLog(level: string, matcher?: LogMatcher): void {
      const levelCalls = instance.getCalls(level);
      const matched = levelCalls.some((c) => matchesCall(c, matcher));
      if (matched) {
        const matcherDesc = formatMatcherDescription(matcher);
        throw new Error(
          `Expected NO [${level}] log matching ${matcherDesc}, but one was found.\n` +
            `Recorded calls:\n${formatCalls(_calls)}`
        );
      }
    },

    reset(): void {
      _calls.length = 0;
    },

    silent,
  };

  return instance;
}
