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
    internalLog(`Field '${fieldName}' enabled`);
  }

  disableField(fieldName: string): void {
    this.fieldState.set(fieldName, false);
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
    const rawPayload = { ...this.contextData, ...data };
    const payload =
      Object.keys(rawPayload).length > 0
        ? (applyRedaction(rawPayload, this.config.redact) ?? rawPayload)
        : undefined;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      appName: this.config.appName ?? 'App',
      environment: this.config.environment ?? 'development',
      message,
      ...(this.context && { context: this.context }),
      ...(payload && { payload }),
    };

    if (this.config.traceId) {
      entry.traceId = getCurrentTraceId() ?? this.fallbackTraceId;
    }

    const formattedLog = this.formatLog(entry);
    await this.output(formattedLog, level, entry);
  }

  // ── Feature 3: Namespace-aware shouldLog ─────────────────────────────────────

  private shouldLog(level: string): boolean {
    const effectiveLevel = this.resolveEffectiveLevel();

    const levelMap: Record<string, number> = {
      [LogLevel.ERROR]: 0,
      [LogLevel.WARN]: 1,
      [LogLevel.INFO]: 2,
      [LogLevel.DEBUG]: 3,
      [LogLevel.TRACE]: 4,
      [LogLevel.VERBOSE]: 5,
      ...(this.config.levelOptions?.levels ?? {}),
    };

    const currentLevelValue = levelMap[effectiveLevel];
    const messageLevelValue = levelMap[level];

    return (
      messageLevelValue !== undefined &&
      currentLevelValue !== undefined &&
      messageLevelValue <= currentLevelValue
    );
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
    if (this.config.format?.json) return JSON.stringify(entry);

    let formatted = '';

    if (this.config.format?.timestamp !== false && this.isFieldEnabled('timestamp')) {
      formatted += `[${new Date(entry.timestamp).toLocaleString()}] `;
    }

    if (this.isFieldEnabled('level')) {
      const coloredLevel = this.config.format?.colorize
        ? this.colorize(
            entry.level.toUpperCase(),
            this.config.levelOptions?.colors?.[entry.level] ?? 'white'
          )
        : entry.level.toUpperCase();
      formatted += `[${coloredLevel}] `;
    }

    if (this.isFieldEnabled('appName')) formatted += `[${entry.appName}] `;
    if (entry.traceId && this.isFieldEnabled('traceId')) formatted += `[${entry.traceId}] `;
    if (entry.context && this.isFieldEnabled('context')) formatted += `[${entry.context}] `;
    if (this.isFieldEnabled('message')) formatted += entry.message;

    if (entry.payload && Object.keys(entry.payload).length > 0 && this.isFieldEnabled('payload')) {
      formatted += ` ${JSON.stringify(entry.payload)}`;
    }

    return formatted;
  }

  private colorize(text: string, color: string): string {
    if (!this.config.format?.colorize) return text;

    const colors: Record<string, string> = {
      red: '\x1b[31m',
      green: '\x1b[32m',
      yellow: '\x1b[33m',
      blue: '\x1b[34m',
      magenta: '\x1b[35m',
      cyan: '\x1b[36m',
      white: '\x1b[37m',
      gray: '\x1b[90m',
      reset: '\x1b[0m',
    };

    const colorCode = colors[color.toLowerCase()] ?? colors['white']!;
    return `${colorCode}${text}${colors['reset']}`;
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

    switch (level) {
      case LogLevel.ERROR:
        console.error(message);
        break;
      case LogLevel.WARN:
        console.warn(message);
        break;
      case LogLevel.DEBUG:
      case LogLevel.TRACE:
        console.debug(message);
        break;
      default:
        console.log(message);
    }
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
