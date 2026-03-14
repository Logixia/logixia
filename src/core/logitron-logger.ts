/**
 * Core Logixia Logger implementation
 *
 * v1.1 additions:
 *  - Feature 1: Graceful shutdown / flushOnExit (auto-registered via config)
 *  - Feature 2: Built-in log redaction (path-based + regex)
 *  - Feature 3: Per-namespace log levels + LOGIXIA_LEVEL* ENV overrides
 *  - Feature 4: Cause-chain error serialization (handled in error.utils)
 *  - Feature 5: Adaptive log level based on NODE_ENV / CI detection
 */

import buildFastStringify from 'fast-json-stringify';

// ── Module-level JSON serializer (built once, reused for all loggers) ─────────
// Covers the fixed LogEntry shape; unknown payload fields handled by additionalProperties
const _fastStringifyEntry = buildFastStringify({
  type: 'object',
  properties: {
    timestamp: { type: 'string' },
    level: { type: 'string' },
    appName: { type: 'string' },
    environment: { type: 'string' },
    message: { type: 'string' },
    context: { type: 'string' },
    traceId: { type: 'string' },
    payload: { type: 'object', additionalProperties: true },
  },
  additionalProperties: true,
});

import { TransportManager } from '../transports/transport.manager';
import type {
  ContextData,
  GracefulShutdownConfig,
  ILogger,
  ILoggerDefault,
  LogEntry,
  LoggerConfig,
  LoggerWithLevels,
  LogLevelString,
  TimingEntry,
} from '../types';
import { LogLevel } from '../types';
import { isError, serializeError } from '../utils/error.utils';
import { internalError, internalLog, internalWarn } from '../utils/internal-log';
import { applyRedaction } from '../utils/redact.utils';
import { deregisterFromShutdown, flushOnExit, registerForShutdown } from '../utils/shutdown.utils';
import { generateTraceId, getCurrentTraceId } from '../utils/trace.utils';

// ── Namespace level helpers ──────────────────────────────────────────────────

function namespacePatternToRegex(pattern: string): RegExp {
  const escaped = pattern
    .split('.')
    .map((s) => (s === '*' ? '[^.]+' : s.replace(/[$()*+.?[\\\]^{|}]/g, '\\$&')))
    .join('\\.');
  return new RegExp(`^${escaped}$`);
}

const _nsPatternCache = new Map<string, RegExp>();

function matchesNamespacePattern(ns: string, pattern: string): boolean {
  let re = _nsPatternCache.get(pattern);
  if (!re) {
    re = namespacePatternToRegex(pattern);
    _nsPatternCache.set(pattern, re);
  }
  return re.test(ns);
}

// ── Feature 5: Adaptive level resolution ────────────────────────────────────

function resolveInitialLevel(config: LoggerConfig): LogLevelString {
  // 1. Hard env override
  const envLevel = process.env['LOGIXIA_LEVEL'];
  if (envLevel) return envLevel as LogLevelString;

  // 2. Explicit config value
  if (config.levelOptions?.level) return config.levelOptions.level as LogLevelString;

  // 3. NODE_ENV smart defaults
  const nodeEnv = process.env['NODE_ENV'];
  if (nodeEnv === 'development') return LogLevel.DEBUG;
  if (nodeEnv === 'test') return LogLevel.WARN;
  if (nodeEnv === 'production') return LogLevel.INFO;

  // 4. CI detection
  if (process.env['CI']) return LogLevel.INFO;

  return LogLevel.INFO;
}

// ── Logger class ─────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- generic logger config allows any transport config shape
export class LogixiaLogger<TConfig extends LoggerConfig<any> = LoggerConfig>
  implements ILoggerDefault
{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- index signature for dynamic custom level methods
  [K: string]: any;

  private config: TConfig;
  private context?: string;
  private timers: Map<string, TimingEntry> = new Map();
  private contextData: ContextData = {};
  private transportManager?: TransportManager;
  private fieldState: Map<string, boolean> = new Map();

  /** Stable fallback trace ID generated ONCE per logger instance. */
  private readonly fallbackTraceId: string = generateTraceId();

  // ── Performance: hot-path caches (rebuilt when config changes) ───────────────
  /** Numeric value for each known log level — built once, read on every log call. */
  private _levelValues: Map<string, number> = new Map();
  /** Numeric threshold for the currently active log level. */
  private _minLevelValue = 2;
  /** Pre-built ANSI color codes to avoid recreating the object in colorize(). */
  private _colorMap: Map<string, string> = new Map();
  /** Pre-computed field-enabled booleans so isFieldEnabled() isn't called per log. */
  private _fieldCache: Map<string, boolean> = new Map();
  /** True when contextData is non-empty — avoids Object.keys() check on hot path. */
  private _hasContextData = false;
  /**
   * Pre-computed `[INFO] `, `[WARN] ` etc. strings — avoids a colorize() call per log.
   * Key: lowercase level name. Value: formatted bracket string ready to concatenate.
   */
  private _formattedLevels: Map<string, string> = new Map();
  /** Pre-computed `[appName] ` string — avoids template literal allocation per log. */
  private _formattedAppName = '';
  /** True when a redact config is present — short-circuits applyRedaction when false. */
  private _hasRedact = false;

  constructor(config: TConfig, context?: string) {
    const defaultConfig: LoggerConfig = {
      appName: 'App',
      environment: 'development',
      traceId: true,
      format: { timestamp: true, colorize: true, json: false },
      silent: false,
      levelOptions: {
        level: LogLevel.INFO,
        levels: {
          [LogLevel.ERROR]: 0,
          [LogLevel.WARN]: 1,
          [LogLevel.INFO]: 2,
          [LogLevel.DEBUG]: 3,
          [LogLevel.TRACE]: 4,
          [LogLevel.VERBOSE]: 5,
        },
        colors: {
          [LogLevel.ERROR]: 'red',
          [LogLevel.WARN]: 'yellow',
          [LogLevel.INFO]: 'blue',
          [LogLevel.DEBUG]: 'green',
          [LogLevel.TRACE]: 'gray',
          [LogLevel.VERBOSE]: 'cyan',
        },
      },
    };

    this.config = { ...defaultConfig, ...config };

    // ── Feature 5: Adaptive log level ───────────────────────────────────────
    const resolvedLevel = resolveInitialLevel(this.config);
    this.config.levelOptions = { ...this.config.levelOptions, level: resolvedLevel };

    if (!this.config.fields) {
      this.config.fields = {
        timestamp: '[yyyy-mm-dd HH:MM:ss.MS]',
        level: '[log_level]',
        appName: '[app_name]',
        traceId: '[trace_id]',
        message: '[message]',
        payload: '[payload]',
        timeTaken: '[time_taken_MS]',
      };
    }

    this.context = context ?? '';

    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- transports is on extended config shapes
    if ((this.config as any).transports) {
      this.transportManager = new TransportManager(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (this.config as any).transports
      );
    }

    // ── Feature 1: Graceful shutdown ─────────────────────────────────────────
    this.setupGracefulShutdown();

    this.createCustomLevelMethods();

    // ── Build hot-path caches after all config is finalised ──────────────────
    this._buildPerfCaches();
  }

  // ── Feature 1 ────────────────────────────────────────────────────────────────

  private setupGracefulShutdown(): void {
    const shutdownCfg = this.config.gracefulShutdown;
    if (!shutdownCfg) return;

    const normalized: GracefulShutdownConfig =
      shutdownCfg === true ? { enabled: true } : (shutdownCfg as GracefulShutdownConfig);

    if (!normalized.enabled) return;

    registerForShutdown(this);
    flushOnExit({
      timeout: normalized.timeout ?? 5000,
      signals: normalized.signals ?? ['SIGTERM', 'SIGINT'],
    });
  }

  private createCustomLevelMethods(): void {
    if (this.config.levelOptions?.levels) {
      for (const levelName of Object.keys(this.config.levelOptions.levels)) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (!(this as any)[levelName.toLowerCase()]) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (this as any)[levelName.toLowerCase()] = async (
            message: string,
            data?: Record<string, unknown>
          ) => {
            await this.logLevel(levelName.toLowerCase(), message, data);
          };
        }
      }
    }
  }

  /**
   * Rebuild all hot-path caches after any config mutation or level change.
   * Keeps the actual log() call free of allocations in the common case.
   */
  private _buildPerfCaches(): void {
    // 1. Level value map — pre-merge built-ins + custom levels once
    const customLevelEntries = Object.entries(
      (this.config.levelOptions?.levels ?? {}) as Record<string, number>
    );
    this._levelValues = new Map<string, number>([
      [LogLevel.ERROR, 0],
      [LogLevel.WARN, 1],
      [LogLevel.INFO, 2],
      [LogLevel.DEBUG, 3],
      [LogLevel.TRACE, 4],
      [LogLevel.VERBOSE, 5],
      ...customLevelEntries,
    ]);
    const effectiveLevel = this.resolveEffectiveLevel();
    this._minLevelValue = this._levelValues.get(effectiveLevel) ?? 2;

    // 2. ANSI color map — static, built once
    this._colorMap = new Map([
      ['red', '\x1b[31m'],
      ['green', '\x1b[32m'],
      ['yellow', '\x1b[33m'],
      ['blue', '\x1b[34m'],
      ['magenta', '\x1b[35m'],
      ['cyan', '\x1b[36m'],
      ['white', '\x1b[37m'],
      ['gray', '\x1b[90m'],
      ['reset', '\x1b[0m'],
    ]);

    // 3. Field enabled cache — replaces per-call isFieldEnabled() calls
    const fieldNames = [
      'timestamp',
      'level',
      'appName',
      'traceId',
      'context',
      'message',
      'payload',
    ];
    for (const f of fieldNames) {
      if (this.fieldState.has(f)) {
        this._fieldCache.set(f, this.fieldState.get(f)!);
      } else if (this.config.fields?.[f as keyof typeof this.config.fields] !== undefined) {
        this._fieldCache.set(f, this.config.fields[f as keyof typeof this.config.fields] !== false);
      } else {
        this._fieldCache.set(f, true);
      }
    }

    // 4. Pre-computed formatted level strings (e.g. "[INFO] " with ANSI codes baked in)
    //    Eliminates a colorize() call + template literal allocation on every log call.
    const colorize = this.config.format?.colorize ?? true;
    this._formattedLevels = new Map();
    for (const [lvl] of this._levelValues) {
      const upper = lvl.toUpperCase();
      if (colorize && this._fieldCache.get('level') !== false) {
        const colorName = (this.config.levelOptions?.colors?.[lvl] ?? 'white') as string;
        const code = this._colorMap.get(colorName.toLowerCase()) ?? this._colorMap.get('white')!;
        const reset = this._colorMap.get('reset')!;
        this._formattedLevels.set(lvl, `[${code}${upper}${reset}] `);
      } else {
        this._formattedLevels.set(lvl, `[${upper}] `);
      }
    }

    // 5. Pre-computed "[appName] " string
    this._formattedAppName =
      this._fieldCache.get('appName') !== false ? `[${this.config.appName ?? 'App'}] ` : '';

    // 6. Redact flag — if no redact config, skip applyRedaction entirely
    this._hasRedact = !!(
      this.config.redact &&
      ((this.config.redact.paths?.length ?? 0) > 0 ||
        (this.config.redact.patterns?.length ?? 0) > 0)
    );
  }

  // ── Public logging API ───────────────────────────────────────────────────────

  async error(messageOrError: string | Error, data?: Record<string, unknown>): Promise<void> {
    if (isError(messageOrError)) {
      await this.log('error', messageOrError.message, {
        ...data,
        error: serializeError(messageOrError),
      });
    } else {
      await this.log('error', messageOrError, data);
    }
  }

  async warn(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('warn', message, data);
  }

  async info(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('info', message, data);
  }

  async debug(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('debug', message, data);
  }

  async trace(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('trace', message, data);
  }

  async verbose(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('verbose', message, data);
  }

  async logLevel(level: string, message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log(level, message, data);
  }

  // ── Timer API ────────────────────────────────────────────────────────────────

  time(label: string): void {
    this.timers.set(label, { label, startTime: Date.now() });
  }

  async timeEnd(label: string): Promise<number | undefined> {
    const timer = this.timers.get(label);
    if (!timer) {
      await this.warn(`Timer '${label}' does not exist`);
      return undefined;
    }
    const endTime = Date.now();
    const duration = endTime - timer.startTime;
    timer.endTime = endTime;
    timer.duration = duration;
    await this.info(`Timer '${label}' finished`, {
      duration: `${duration}ms`,
      startTime: new Date(timer.startTime).toISOString(),
      endTime: new Date(endTime).toISOString(),
    });
    this.timers.delete(label);
    return duration;
  }

  async timeAsync<T>(label: string, fn: () => Promise<T>): Promise<T> {
    this.time(label);
    try {
      const result = await fn();
      await this.timeEnd(label);
      return result;
    } catch (error) {
      await this.timeEnd(label);
      throw error;
    }
  }

  // ── Level & context management ───────────────────────────────────────────────

  setLevel(level: LogLevelString): void {
    this.config.levelOptions = this.config.levelOptions ?? {};
    this.config.levelOptions.level = level as string;
    // Refresh the cached numeric threshold so shouldLog() stays accurate
    this._minLevelValue = this._levelValues.get(level) ?? this._minLevelValue;
    // Rebuild level string cache in case colours are keyed per-level
    this._buildPerfCaches();
  }

  getLevel(): LogLevelString {
    return (this.config.levelOptions?.level as LogLevelString) ?? LogLevel.INFO;
  }

  setContext(context: string): void {
    this.context = context;
  }

  getContext(): string | undefined {
    return this.context;
  }

  // ── Field management ─────────────────────────────────────────────────────────

  enableField(fieldName: string): void {
    this.fieldState.set(fieldName, true);
    this._fieldCache.set(fieldName, true);
    // Rebuild derivative caches that depend on field visibility
    if (fieldName === 'level' || fieldName === 'appName') this._buildPerfCaches();
    internalLog(`Field '${fieldName}' enabled`);
  }

  disableField(fieldName: string): void {
    this.fieldState.set(fieldName, false);
    this._fieldCache.set(fieldName, false);
    // Rebuild derivative caches that depend on field visibility
    if (fieldName === 'level' || fieldName === 'appName') this._buildPerfCaches();
    internalLog(`Field '${fieldName}' disabled`);
  }

  isFieldEnabled(fieldName: string): boolean {
    if (this.fieldState.has(fieldName)) return this.fieldState.get(fieldName)!;
    if (this.config.fields?.[fieldName as keyof typeof this.config.fields] !== undefined) {
      return this.config.fields[fieldName as keyof typeof this.config.fields] !== false;
    }
    return true;
  }

  getFieldState(): Record<string, boolean> {
    const allFields = [
      'timestamp',
      'level',
      'appName',
      'service',
      'traceId',
      'message',
      'payload',
      'timeTaken',
      'context',
      'requestId',
      'userId',
      'sessionId',
      'environment',
    ];
    return Object.fromEntries(allFields.map((f) => [f, this.isFieldEnabled(f)]));
  }

  resetFieldState(): void {
    this.fieldState.clear();
    internalLog('Field state reset to configuration defaults');
  }

  // ── Transport level management ───────────────────────────────────────────────

  enableTransportLevelPrompting(): void {
    if (this.transportManager) this.transportManager.enableLevelPrompting();
    else internalWarn('Transport manager not initialized');
  }

  disableTransportLevelPrompting(): void {
    if (this.transportManager) this.transportManager.disableLevelPrompting();
    else internalWarn('Transport manager not initialized');
  }

  setTransportLevels(transportId: string, levels: string[]): void {
    if (this.transportManager) this.transportManager.setTransportLevels(transportId, levels);
    else internalWarn('Transport manager not initialized');
  }

  getTransportLevels(transportId: string): string[] | undefined {
    if (this.transportManager) return this.transportManager.getTransportLevels(transportId);
    internalWarn('Transport manager not initialized');
    return undefined;
  }

  clearTransportLevelPreferences(): void {
    if (this.transportManager) this.transportManager.clearTransportLevelPreferences();
    else internalWarn('Transport manager not initialized');
  }

  getAvailableTransports(): string[] {
    return this.transportManager?.getTransports() ?? [];
  }

  // ── Child logger ─────────────────────────────────────────────────────────────

  child(context: string, data?: Record<string, unknown>): ILogger {
    const childLogger = new LogixiaLogger(this.config, context);
    if (data) childLogger.contextData = { ...this.contextData, ...data };
    return childLogger;
  }

  // ── Flush / health / close ───────────────────────────────────────────────────

  async flush(): Promise<void> {
    if (this.transportManager) await this.transportManager.flush();
  }

  async healthCheck(): Promise<{ healthy: boolean; details: Record<string, unknown> }> {
    if (!this.transportManager) {
      return { healthy: false, details: { error: 'TransportManager not initialized' } };
    }
    return this.transportManager.healthCheck();
  }

  async close(): Promise<void> {
    for (const [label, timer] of this.timers) {
      await this.warn(`Timer '${label}' was not ended properly`, {
        startTime: new Date(timer.startTime).toISOString(),
        duration: `${Date.now() - timer.startTime}ms (incomplete)`,
      });
    }
    this.timers.clear();

    if (this.transportManager) {
      await this.transportManager.flush();
      await this.transportManager.close();
    }

    deregisterFromShutdown(this);
  }

  // ── Core log method ──────────────────────────────────────────────────────────

  private async log(level: string, message: string, data?: Record<string, unknown>): Promise<void> {
    if (this.config.silent) return;
    if (!this.shouldLog(level)) return;

    // ── Feature 2: Redaction ─────────────────────────────────────────────────
    // Avoid spread allocation when contextData is empty (the common case)
    const rawPayload = this._hasContextData ? { ...this.contextData, ...data } : data;
    // _hasRedact is pre-computed in _buildPerfCaches() — skips the entire redaction
    // code path when no redact config is present (fast path for the common case).
    let payload: Record<string, unknown> | undefined;
    if (rawPayload !== undefined && rawPayload !== null) {
      payload = this._hasRedact
        ? (applyRedaction(rawPayload, this.config.redact) ?? rawPayload)
        : rawPayload;
    }

    // Use a monomorphic LogEntry shape — always the same fields, some may be undefined.
    // Consistent shape lets V8 inline-cache property accesses across calls.
    const traceId = this.config.traceId ? (getCurrentTraceId() ?? this.fallbackTraceId) : undefined;
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      appName: this.config.appName ?? 'App',
      environment: this.config.environment ?? 'development',
      message,
    };
    if (this.context) entry.context = this.context;
    if (payload !== undefined) entry.payload = payload;
    if (traceId !== undefined) entry.traceId = traceId;

    const formattedLog = this.formatLog(entry);
    await this.output(formattedLog, level, entry);
  }

  // ── Feature 3: Namespace-aware shouldLog ─────────────────────────────────────

  /**
   * Hot-path level check: a single Map lookup + integer compare.
   * The level map and threshold are pre-built in _buildPerfCaches().
   */
  private shouldLog(level: string): boolean {
    const v = this._levelValues.get(level);
    return v !== undefined && v <= this._minLevelValue;
  }

  /**
   * Feature 3: Resolve the effective log level for this logger instance.
   *
   * Priority:
   *  1. ENV `LOGIXIA_LEVEL_<NS_UPPER>` (e.g. LOGIXIA_LEVEL_DB for ns "db" or "db.queries")
   *  2. Matching `namespaceLevels` config entry (longer pattern = more specific, wins)
   *  3. Global `LOGIXIA_LEVEL` ENV override
   *  4. `levelOptions.level` (resolved via Feature 5 in constructor)
   */
  private resolveEffectiveLevel(): LogLevelString {
    const ns = this.context;

    if (ns) {
      // 1. ENV namespace override: LOGIXIA_LEVEL_DB → context "db" or "db.queries"
      const nsKey = ns.split('.')[0]!.toUpperCase();
      const envNsLevel = process.env[`LOGIXIA_LEVEL_${nsKey}`];
      if (envNsLevel) return envNsLevel as LogLevelString;

      // 2. namespaceLevels config
      const namespaceLevels = this.config.namespaceLevels;
      if (namespaceLevels) {
        const sortedPatterns = Object.keys(namespaceLevels).sort((a, b) => b.length - a.length);
        for (const pattern of sortedPatterns) {
          if (matchesNamespacePattern(ns, pattern)) {
            return namespaceLevels[pattern]!;
          }
        }
      }
    }

    // 3. Global ENV override
    const globalEnv = process.env['LOGIXIA_LEVEL'];
    if (globalEnv) return globalEnv as LogLevelString;

    // 4. Config-resolved level
    return this.getLevel();
  }

  // ── Formatters ───────────────────────────────────────────────────────────────

  private formatLog(entry: LogEntry): string {
    // JSON mode: use fast-json-stringify (pre-compiled serializer, ~59% faster than JSON.stringify)
    if (this.config.format?.json) return _fastStringifyEntry(entry);

    let formatted = '';

    // Use _fieldCache instead of calling isFieldEnabled() per field
    if (this.config.format?.timestamp !== false && this._fieldCache.get('timestamp') !== false) {
      // entry.timestamp is already an ISO string — no need to re-parse it
      formatted += `[${entry.timestamp}] `;
    }

    // Use pre-computed level string (avoids colorize() call + template literal allocation)
    if (this._fieldCache.get('level') !== false) {
      formatted += this._formattedLevels.get(entry.level) ?? `[${entry.level.toUpperCase()}] `;
    }

    // Use pre-computed "[appName] " string (built once in _buildPerfCaches)
    formatted += this._formattedAppName;

    if (entry.traceId && this._fieldCache.get('traceId') !== false)
      formatted += `[${entry.traceId}] `;
    if (entry.context && this._fieldCache.get('context') !== false)
      formatted += `[${entry.context}] `;
    if (this._fieldCache.get('message') !== false) formatted += entry.message;

    if (entry.payload !== undefined && this._fieldCache.get('payload') !== false) {
      formatted += ` ${JSON.stringify(entry.payload)}`;
    }

    return formatted;
  }

  private colorize(text: string, color: string): string {
    if (!this.config.format?.colorize) return text;
    // Use pre-built _colorMap instead of recreating the colors object every call
    const code = this._colorMap.get(color.toLowerCase()) ?? this._colorMap.get('white')!;
    return `${code}${text}${this._colorMap.get('reset')!}`;
  }

  private async output(message: string, level: string, entry: LogEntry): Promise<void> {
    if (this.transportManager) {
      try {
        await this.transportManager.write(entry);
        return;
      } catch (error) {
        internalError('Transport write failed', error);
      }
    }

    // Fallback: direct stdout/stderr write — faster than console wrappers
    const out = level === LogLevel.ERROR ? process.stderr : process.stdout;
    out.write(message + '\n');
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- generic config type parameter
export function createLogger<T extends LoggerConfig<any>>(
  config: T,
  context?: string
): LoggerWithLevels<T> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- cast needed for dynamic method attachment
  const logger = new LogixiaLogger<T>(config, context) as any;

  if (config.levelOptions?.levels) {
    for (const levelName of Object.keys(config.levelOptions.levels)) {
      if (!logger[levelName]) {
        logger[levelName] = async (message: string, data?: Record<string, unknown>) => {
          await logger.logLevel(levelName, message, data);
        };
      }
    }
  }

  return logger as LoggerWithLevels<T>;
}
