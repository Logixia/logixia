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

import { LogixiaContext } from '../context/async-context';
import type { LogixiaPlugin } from '../plugin';
import { globalPluginRegistry, PluginRegistry } from '../plugin';
import { protectSecrets } from '../transports/secret-config';
import { TransportManager } from '../transports/transport.manager';
import type {
  ContextData,
  GracefulShutdownConfig,
  ILoggerDefault,
  LogEntry,
  LoggerConfig,
  LoggerWithLevels,
  LogixiaLoggerInstance,
  LogLevelString,
  NamespaceLevels,
  TimingEntry,
} from '../types';
import { LogLevel } from '../types';
import { safeToString } from '../utils/coerce.utils';
import { isError, serializeError } from '../utils/error.utils';
import { internalError, internalLog, internalWarn } from '../utils/internal-log';
import { _getOtelPayloadIfEnabled, _isOtelBridgeEnabled } from '../utils/otel';
import { applyRedaction, applyRedactionToString, REDACTION_FAILED } from '../utils/redact.utils';
import { stringifyForLog } from '../utils/safe-stringify';
import { Sampler } from '../utils/sampling.utils';
import { stripControlChars } from '../utils/sanitize.utils';
import { deregisterFromShutdown, flushOnExit, registerForShutdown } from '../utils/shutdown.utils';
import { TraceContext } from '../utils/trace.utils';
import { warnOnReservedLevelNames } from './reserved-levels';

// ── Hot-path timestamp cache ─────────────────────────────────────────────────
// `new Date().toISOString()` is one of the most expensive things on the log hot
// path (~2.2M ops/sec vs ~18M for Date.now()). Within a single millisecond every
// log shares the same ISO string, so cache it keyed on the integer epoch ms and
// only re-format when the clock ticks over. Worst case at very high throughput:
// thousands of logs reuse one allocation instead of each paying for toISOString.
let _tsCacheMs = 0;
let _tsCacheStr = '';
function nowIso(): string {
  const ms = Date.now();
  if (ms !== _tsCacheMs) {
    _tsCacheMs = ms;
    _tsCacheStr = new Date(ms).toISOString();
  }
  return _tsCacheStr;
}

// ── Namespace level helpers ──────────────────────────────────────────────────

function namespacePatternToRegex(pattern: string): RegExp {
  const escaped = pattern
    .split('.')
    .map((s) => (s === '*' ? '[^.]+' : s.replace(/[$()*+.?[\\\]^{|}]/g, '\\$&')))
    .join('\\.');
  return new RegExp(`^${escaped}$`);
}

/** Max compiled patterns to keep in memory. Oldest entry is evicted when full. */
const _NS_CACHE_MAX = 1000;
const _nsPatternCache = new Map<string, RegExp>();
/**
 * One-shot warning so operators notice runaway pattern growth.
 * If the cache is being thrashed (>N evictions) the namespace level config is
 * almost certainly wrong — likely dynamic/unique patterns being registered.
 */
let _nsCacheEvictionWarned = false;
let _nsCacheEvictionCount = 0;

function matchesNamespacePattern(ns: string, pattern: string): boolean {
  let re = _nsPatternCache.get(pattern);
  if (!re) {
    re = namespacePatternToRegex(pattern);
    // Evict the oldest entry when the cache hits its limit
    if (_nsPatternCache.size >= _NS_CACHE_MAX) {
      const firstKey = _nsPatternCache.keys().next().value;
      if (firstKey !== undefined) _nsPatternCache.delete(firstKey);
      _nsCacheEvictionCount++;
      if (!_nsCacheEvictionWarned) {
        _nsCacheEvictionWarned = true;
        internalWarn(
          `namespace pattern cache hit ${_NS_CACHE_MAX} entries — evicting. ` +
            `This usually means dynamic/unique patterns are being registered at runtime; ` +
            `review your levelOptions.namespaces configuration.`
        );
      }
    }
    _nsPatternCache.set(pattern, re);
  }
  return re.test(ns);
}

/** @internal Test helper to inspect/reset namespace pattern cache state. */
export const _nsCacheInternal = {
  size: (): number => _nsPatternCache.size,
  evictionCount: (): number => _nsCacheEvictionCount,
  reset: (): void => {
    _nsPatternCache.clear();
    _nsCacheEvictionCount = 0;
    _nsCacheEvictionWarned = false;
  },
};

// ── Feature 5: Adaptive level resolution ────────────────────────────────────

/**
 * Map a level name onto a known level key: exact match first (so custom levels
 * keep their declared casing), then lower case (so `DEBUG` → `debug`).
 */
function canonicalLevel(level: unknown, known: { has(key: string): boolean }): string | undefined {
  if (typeof level !== 'string') return undefined;
  if (known.has(level)) return level;
  const lower = level.toLowerCase();
  return known.has(lower) ? lower : undefined;
}

function resolveInitialLevel(config: LoggerConfig): LogLevelString {
  // 1. Hard env override — an unknown value is skipped here so the configured level
  //    still applies; resolveEffectiveLevel() reports it.
  const envLevel = process.env['LOGIXIA_LEVEL'];
  const knownLevels = new Set<string>([
    ...Object.values(LogLevel),
    ...Object.keys(config.levelOptions?.levels ?? {}),
  ]);
  if (envLevel && canonicalLevel(envLevel, knownLevels)) return envLevel as LogLevelString;

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

/**
 * The logixia logger. Create instances with {@link createLogger} so that custom
 * levels from `levelOptions.levels` also become methods.
 *
 * @example
 * ```ts
 * const logger = createLogger({ appName: 'api', environment: 'production' });
 * await logger.info('Server started', { port: 3000 });
 * const req = logger.child('RequestHandler', { requestId: 'r-1' });
 * await req.error(new Error('boom'));
 * await logger.close(); // flush buffered transports before exit
 * ```
 */
export class LogixiaLogger<
  TConfig extends LoggerConfig<Record<string, number>> = LoggerConfig,
> implements ILoggerDefault {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- index signature for dynamic custom level methods
  [K: string]: any;

  private config: TConfig;
  private context?: string;
  private timers: Map<string, TimingEntry> = new Map();
  private contextData: ContextData = {};
  private transportManager: TransportManager | undefined;
  private fieldState: Map<string, boolean> = new Map();

  /** Stable fallback trace ID generated ONCE per logger instance. */
  private readonly fallbackTraceId: string = TraceContext.instance.generate();

  // ── Performance: hot-path caches (rebuilt when config changes) ───────────────
  /** Numeric value for each known log level — built once, read on every log call. */
  private _levelValues: Map<string, number> = new Map();
  /** Numeric threshold for the currently active log level. */
  private _minLevelValue = 2;
  /** Level set via setLevel(); outranks every other level source until the process ends. */
  private _runtimeLevel: string | undefined;
  /** `source=value` pairs already reported as unknown levels — warn once per logger. */
  private readonly _warnedInvalidLevels = new Set<string>();
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
  /** Sampling engine — only created when sampling config is present. */
  private _sampler: Sampler | undefined;
  /** Per-instance plugin registry — also inherits from the global registry at creation time. */
  private readonly _pluginRegistry: PluginRegistry;
  /** Set on loggers created by child(); they borrow the root's transports, sampler and plugins. */
  private readonly _parent: LogixiaLogger<TConfig> | undefined;
  /** Namespace level map shared by a logger and all its children; `version` bumps on every change. */
  private readonly _nsStore: { levels: NamespaceLevels; version: number };
  /** Store version this logger's threshold was last computed against. */
  private _nsSeenVersion = 0;

  constructor(config: TConfig, context?: string, parent?: LogixiaLogger<TConfig>) {
    this._parent = parent;
    this._nsStore = parent
      ? parent._nsStore
      : { levels: { ...config.namespaceLevels }, version: 0 };
    this._nsSeenVersion = this._nsStore.version;
    this._pluginRegistry = parent ? parent._pluginRegistry : new PluginRegistry();

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

    this.config.fields ??= {
      timestamp: '[yyyy-mm-dd HH:MM:ss.MS]',
      level: '[log_level]',
      appName: '[app_name]',
      traceId: '[trace_id]',
      message: '[message]',
      payload: '[payload]',
      timeTaken: '[time_taken_MS]',
    };

    this.context = context ?? '';
    protectSecrets(this, ['config']);

    if (parent) {
      this.transportManager = parent.transportManager;
      this._sampler = parent._sampler;
    } else if (this.config.transports) {
      // Inject levelOptions.colors into the console transport config so
      // ConsoleTransport can colorize custom levels (e.g. kafka, mongo)
      // using the same colors the user configured on the logger.
      const transportsWithColors = { ...this.config.transports };
      const userColors = this.config.levelOptions?.colors as Record<string, string> | undefined;
      if (userColors && transportsWithColors.console) {
        const consoleBase =
          typeof transportsWithColors.console === 'object' ? transportsWithColors.console : {};
        transportsWithColors.console = { ...consoleBase, levelColors: userColors };
      }
      this.transportManager = new TransportManager(transportsWithColors);
    }

    // ── Feature 8: Log sampling ───────────────────────────────────────────────
    if (!parent && this.config.sampling) {
      this._sampler = new Sampler(this.config.sampling, (stats) => {
        // Emit sampling stats as an INFO log via direct stdout to avoid recursion
        process.stdout.write(
          JSON.stringify({
            level: 'info',
            message: '[logixia/sampling] stats',
            ...stats,
          }) + '\n'
        );
      });
    }

    // ── Feature 1: Graceful shutdown ─────────────────────────────────────────
    if (!parent) this.setupGracefulShutdown();

    this.createCustomLevelMethods();

    // ── Feature 20: Seed with any plugins already in the global registry ─────
    // Plugins registered via usePlugin() before this logger was created are
    // automatically included in this instance's registry.
    if (!parent) {
      for (const p of (globalPluginRegistry as unknown as { _plugins: LogixiaPlugin[] })._plugins) {
        this._pluginRegistry.register(p);
      }
    }

    // ── Build hot-path caches after all config is finalised ──────────────────
    this._buildPerfCaches();
  }

  // ── Feature 1 ────────────────────────────────────────────────────────────────

  private setupGracefulShutdown(): void {
    const shutdownCfg = this.config.gracefulShutdown;
    if (!shutdownCfg) return;

    const normalized: GracefulShutdownConfig =
      shutdownCfg === true ? { enabled: true } : shutdownCfg;

    if (!normalized.enabled) return;

    registerForShutdown(this);
    flushOnExit({
      timeout: normalized.timeout ?? 5000,
      signals: normalized.signals ?? ['SIGTERM', 'SIGINT'],
      ...(normalized.exit ? { exit: normalized.exit } : {}),
    });
  }

  private createCustomLevelMethods(): void {
    warnOnReservedLevelNames(this.config.levelOptions?.levels);
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
    const customLevelEntries = Object.entries(this.config.levelOptions?.levels ?? {});
    this._levelValues = new Map<string, number>([
      [LogLevel.ERROR, 0],
      [LogLevel.WARN, 1],
      [LogLevel.INFO, 2],
      [LogLevel.DEBUG, 3],
      [LogLevel.TRACE, 4],
      [LogLevel.VERBOSE, 5],
      ...customLevelEntries,
    ]);
    // Validate the configured level against the real map (built-ins + custom levels)
    // and store it in canonical form so getLevel() reports what is actually in effect.
    this.config.levelOptions = this.config.levelOptions ?? {};
    this.config.levelOptions.level =
      this._validLevel(this.config.levelOptions.level, 'levelOptions.level') ?? LogLevel.INFO;
    const effectiveLevel = this.resolveEffectiveLevel();
    this._minLevelValue = this._levelValues.get(effectiveLevel) ?? 2;

    // 2. ANSI color map — static, built once
    this._colorMap = new Map([
      ['black', '\x1b[30m'],
      ['red', '\x1b[31m'],
      ['green', '\x1b[32m'],
      ['yellow', '\x1b[33m'],
      ['blue', '\x1b[34m'],
      ['magenta', '\x1b[35m'],
      ['cyan', '\x1b[36m'],
      ['white', '\x1b[37m'],
      ['gray', '\x1b[90m'],
      ['grey', '\x1b[90m'],
      ['brightred', '\x1b[91m'],
      ['brightgreen', '\x1b[92m'],
      ['brightyellow', '\x1b[93m'],
      ['brightblue', '\x1b[94m'],
      ['brightmagenta', '\x1b[95m'],
      ['brightcyan', '\x1b[96m'],
      ['brightwhite', '\x1b[97m'],
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
      } else if (this.config.fields?.[f as keyof typeof this.config.fields] === undefined) {
        this._fieldCache.set(f, true);
      } else {
        this._fieldCache.set(f, this.config.fields[f as keyof typeof this.config.fields] !== false);
      }
    }

    // 4. Pre-computed formatted level strings (e.g. "[INFO] " with ANSI codes baked in)
    //    Eliminates a colorize() call + template literal allocation on every log call.
    const colorize = this.config.format?.colorize ?? true;
    this._formattedLevels = new Map();

    // Palette cycled for custom levels that have no explicit color configured.
    // Skips 'white' because it looks identical to the terminal default (appears "uncolored").
    const _AUTO_PALETTE: readonly string[] = ['magenta', 'cyan', 'yellow', 'green', 'blue'];
    const _BUILTIN_LEVELS = new Set(['error', 'warn', 'info', 'debug', 'trace', 'verbose']);
    let _paletteIdx = 0;

    for (const [lvl] of this._levelValues) {
      const upper = lvl.toUpperCase();
      if (colorize && this._fieldCache.get('level') !== false) {
        let colorName = this.config.levelOptions?.colors?.[lvl] as string | undefined;
        if (!colorName) {
          if (_BUILTIN_LEVELS.has(lvl)) {
            colorName = 'white'; // built-in fallback (shouldn't happen with default config)
          } else {
            // Custom level — auto-assign a distinctive color from the palette
            colorName = _AUTO_PALETTE[_paletteIdx % _AUTO_PALETTE.length]!;
            _paletteIdx++;
          }
        }
        const code = this._colorMap.get(colorName.toLowerCase()) ?? this._colorMap.get('white')!;
        const reset = this._colorMap.get('reset')!;
        this._formattedLevels.set(lvl, `[${code}${upper}${reset}] `);
      } else {
        this._formattedLevels.set(lvl, `[${upper}] `);
      }
    }

    // 5. Pre-computed "[appName] " string (gray when colorize is on)
    const appNameRaw = `[${this.config.appName ?? 'App'}]`;
    if (this._fieldCache.get('appName') === false) {
      this._formattedAppName = '';
    } else {
      this._formattedAppName = colorize
        ? `${this._colorMap.get('gray')!}${appNameRaw}${this._colorMap.get('reset')!} `
        : `${appNameRaw} `;
    }

    // 6. Redact flag — if no redact config, skip applyRedaction entirely.
    //    autoDetect injects built-in PII paths/patterns at redaction time, so
    //    it must flip the flag on even with no explicit paths/patterns set —
    //    otherwise autoDetect-only configs silently leak PII.
    this._hasRedact = !!(
      this.config.redact &&
      ((this.config.redact.paths?.length ?? 0) > 0 ||
        (this.config.redact.patterns?.length ?? 0) > 0 ||
        !!this.config.redact.autoDetect)
    );
  }

  // ── Public logging API ───────────────────────────────────────────────────────

  /**
   * Log at `error` level. An `Error` is logged with its message and serialized
   * (name, message, stack) under `data.error`; a string is logged as-is.
   * `data` is merged into the entry payload.
   */
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

  /** Log `message` at `warn` level; `data` is merged into the entry payload. */
  async warn(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('warn', message, data);
  }

  /** Log `message` at `info` level; `data` is merged into the entry payload. */
  async info(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('info', message, data);
  }

  /** Log `message` at `debug` level; `data` is merged into the entry payload. */
  async debug(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('debug', message, data);
  }

  /** Log `message` at `trace` level; `data` is merged into the entry payload. */
  async trace(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('trace', message, data);
  }

  /** Log `message` at `verbose` level; `data` is merged into the entry payload. */
  async verbose(message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log('verbose', message, data);
  }

  /**
   * Log at an arbitrary level name, including custom levels. Levels below the
   * active threshold are dropped, as are level names that are not registered
   * in `levelOptions.levels` (and are not built-in).
   */
  async logLevel(level: string, message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log(level, message, data);
  }

  // ── Timer API ────────────────────────────────────────────────────────────────

  /** Start a named timer; finish it with {@link timeEnd}. Reusing a label restarts it. */
  time(label: string): void {
    this.timers.set(label, { label, startTime: Date.now() });
  }

  /**
   * Stop the timer `label`, log its duration at `info` level, and return the
   * elapsed milliseconds. Logs a `warn` and returns `undefined` if the timer
   * does not exist.
   *
   * @example
   * ```ts
   * logger.time('db');
   * await query();
   * const ms = await logger.timeEnd('db');
   * ```
   */
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

  /**
   * Change the minimum log level at runtime. The override outranks
   * `LOGIXIA_LEVEL`, `LOGIXIA_LEVEL_<NS>` and `namespaceLevels`, and survives
   * later changes to fields or namespace levels. Unknown level names are
   * ignored with a warning and the current level is kept.
   *
   * @example
   * ```ts
   * logger.setLevel('debug');
   * ```
   */
  setLevel(level: LogLevelString): void {
    const canonical = canonicalLevel(level, this._levelValues);
    if (canonical === undefined) {
      // Refuse unknown levels so getLevel() and the active threshold stay unchanged
      internalWarn(
        `setLevel: unknown log level '${String(level)}' ignored; valid levels: ${this._validLevelList()}. ` +
          `Keeping '${this.getLevel()}'.`
      );
      return;
    }
    this.config.levelOptions = this.config.levelOptions ?? {};
    this.config.levelOptions.level = canonical;
    // Remember the override so later cache rebuilds (enableField, setNamespaceLevels, ...) keep it
    this._runtimeLevel = canonical;
    // Rebuild the threshold and the level string cache
    this._buildPerfCaches();
  }

  /**
   * Return the configured minimum log level, not the per-namespace effective
   * one. Without `setLevel()` it is `LOGIXIA_LEVEL`, else `levelOptions.level`,
   * else a `NODE_ENV` default (`debug` in development, `warn` in test), else `info`.
   */
  getLevel(): LogLevelString {
    return (this.config.levelOptions?.level as LogLevelString) ?? LogLevel.INFO;
  }

  private _validLevelList(): string {
    return [...this._levelValues.keys()].join(', ');
  }

  /**
   * Canonicalise a level from config/ENV. Unknown values return undefined so the
   * caller falls through to the next source, and warn once per logger per source.
   */
  private _validLevel(level: unknown, source: string): string | undefined {
    if (level === undefined || level === '') return undefined;
    const canonical = canonicalLevel(level, this._levelValues);
    if (canonical === undefined) {
      const key = `${source}=${String(level)}`;
      if (!this._warnedInvalidLevels.has(key)) {
        this._warnedInvalidLevels.add(key);
        internalWarn(
          `Unknown log level '${String(level)}' from ${source}; valid levels: ${this._validLevelList()}. ` +
            `Falling back to the next level source (default '${LogLevel.INFO}').`
        );
      }
    }
    return canonical;
  }

  /**
   * Replace the per-namespace level map at runtime — no restart needed.
   *
   * This is the runtime counterpart to the `namespaceLevels` config option and
   * the most-requested logging feature across the Winston/Pino issue trackers
   * (flip a module's verbosity live to chase a bug without raising global
   * volume). The new map fully replaces the previous one.
   *
   * The map is shared by a logger and all its `child()` loggers: calling this on
   * a child changes the whole family, and existing children pick the change up on
   * their next log call.
   *
   * @example
   * ```ts
   * // Turn on debug for the DB layer only, live:
   * logger.setNamespaceLevels({ 'db.*': 'debug', '*': 'info' });
   * ```
   */
  setNamespaceLevels(levels: NamespaceLevels): void {
    this._nsStore.levels = { ...levels };
    this._nsStore.version++;
    // Re-resolve this logger's threshold now; children and the root do the same
    // lazily on their next log call, when they see the bumped store version.
    this._syncNamespaceLevels();
  }

  /** Merge entries into the existing per-namespace level map at runtime. */
  patchNamespaceLevels(levels: NamespaceLevels): void {
    this._nsStore.levels = { ...this._nsStore.levels, ...levels };
    this._nsStore.version++;
    this._syncNamespaceLevels();
  }

  /** Return a copy of the current per-namespace level map. */
  getNamespaceLevels(): NamespaceLevels {
    return { ...this._nsStore.levels };
  }

  private _syncNamespaceLevels(): void {
    this._nsSeenVersion = this._nsStore.version;
    this._minLevelValue = this._levelValues.get(this.resolveEffectiveLevel()) ?? 2;
  }

  /** Set the context label (e.g. a class or module name) attached to every subsequent entry. */
  setContext(context: string): void {
    this.context = typeof context === 'string' ? context : safeToString(context);
  }

  /** Return the current context label, or `undefined` if none is set. */
  getContext(): string | undefined {
    return this.context;
  }

  // ── Field management ─────────────────────────────────────────────────────────

  /** Show `fieldName` in log output, overriding the config for this logger instance. */
  enableField(fieldName: string): void {
    this.fieldState.set(fieldName, true);
    this._fieldCache.set(fieldName, true);
    // Rebuild derivative caches that depend on field visibility
    if (fieldName === 'level' || fieldName === 'appName') this._buildPerfCaches();
    internalLog(`Field '${fieldName}' enabled`);
  }

  /** Hide `fieldName` from log output, overriding the config for this logger instance. */
  disableField(fieldName: string): void {
    this.fieldState.set(fieldName, false);
    this._fieldCache.set(fieldName, false);
    // Rebuild derivative caches that depend on field visibility
    if (fieldName === 'level' || fieldName === 'appName') this._buildPerfCaches();
    internalLog(`Field '${fieldName}' disabled`);
  }

  /** Whether `fieldName` is currently shown: runtime override first, then config, default `true`. */
  isFieldEnabled(fieldName: string): boolean {
    if (this.fieldState.has(fieldName)) return this.fieldState.get(fieldName)!;
    if (this.config.fields?.[fieldName as keyof typeof this.config.fields] !== undefined) {
      return this.config.fields[fieldName as keyof typeof this.config.fields] !== false;
    }
    return true;
  }

  /** Return the visibility (`true` = shown) of every standard log field. */
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
      'userId',
      'sessionId',
      'environment',
    ];
    return Object.fromEntries(allFields.map((f) => [f, this.isFieldEnabled(f)]));
  }

  /** Drop all runtime enable/disable overrides so field visibility follows the config again. */
  resetFieldState(): void {
    this.fieldState.clear();
    internalLog('Field state reset to configuration defaults');
  }

  // ── Transport level management ───────────────────────────────────────────────

  /** @deprecated No-op. Library code never prompts on stdin; use setTransportLevels(). */
  enableTransportLevelPrompting(): void {
    if (this.transportManager) this.transportManager.enableLevelPrompting();
    else internalWarn('Transport manager not initialized');
  }

  /** @deprecated No-op. */
  disableTransportLevelPrompting(): void {
    if (this.transportManager) this.transportManager.disableLevelPrompting();
    else internalWarn('Transport manager not initialized');
  }

  /** Restrict `transportId` to only the given `levels`. Warns if no transports are configured. */
  setTransportLevels(transportId: string, levels: string[]): void {
    if (this.transportManager) this.transportManager.setTransportLevels(transportId, levels);
    else internalWarn('Transport manager not initialized');
  }

  /** Return the levels `transportId` is restricted to, or `undefined` if it has none. */
  getTransportLevels(transportId: string): string[] | undefined {
    if (this.transportManager) return this.transportManager.getTransportLevels(transportId);
    internalWarn('Transport manager not initialized');
    return undefined;
  }

  clearTransportLevelPreferences(): void {
    if (this.transportManager) this.transportManager.clearTransportLevelPreferences();
    else internalWarn('Transport manager not initialized');
  }

  /** Return the identifiers of the configured transports (empty if none). */
  getAvailableTransports(): string[] {
    return this.transportManager?.getTransports() ?? [];
  }

  // ── Child logger ─────────────────────────────────────────────────────────────

  /**
   * Create a child logger with its own `context` that shares this logger's
   * configuration and transports. `data` is merged into the bound fields
   * inherited from this logger and added to every entry the child writes.
   * Closing a child does not close the shared transports.
   *
   * @example
   * ```ts
   * const req = logger.child('Checkout', { requestId: 'r-42' });
   * await req.info('started'); // entry includes requestId
   * ```
   */
  child(context: string, data?: Record<string, unknown>): LogixiaLoggerInstance {
    const childLogger = new LogixiaLogger(this.config, context, this);
    // Inherit the parent's bound fields plus any child-specific data. The
    // hot-path merge in log() is gated on _hasContextData, so it must be set
    // here or the merged fields are silently dropped from every log.
    const mergedContextData = { ...this.contextData, ...data };
    if (Object.keys(mergedContextData).length > 0) {
      childLogger.contextData = mergedContextData;
      childLogger._hasContextData = true;
    }
    return childLogger;
  }

  // ── Feature 20: Plugin API ────────────────────────────────────────────────────

  /**
   * Register a plugin on this logger instance.
   *
   * @example
   * ```ts
   * logger.use({
   *   name: 'audit',
   *   onLog(entry) { auditQueue.push(entry); return entry; },
   * });
   * ```
   */
  use(plugin: LogixiaPlugin): this {
    this._pluginRegistry.register(plugin);
    return this;
  }

  /**
   * Remove a previously registered plugin by name.
   * No-op if the plugin is not registered on this instance.
   */
  unuse(pluginName: string): this {
    this._pluginRegistry.unregister(pluginName);
    return this;
  }

  // ── Flush / health / close ───────────────────────────────────────────────────

  /** Flush buffered entries in all transports without closing them. */
  async flush(): Promise<void> {
    if (this.transportManager) await this.transportManager.flush();
  }

  /** Report whether the transports are healthy; `healthy: false` if no transport manager exists. */
  async healthCheck(): Promise<{ healthy: boolean; details: Record<string, unknown> }> {
    if (!this.transportManager) {
      return { healthy: false, details: { error: 'TransportManager not initialized' } };
    }
    return this.transportManager.healthCheck();
  }

  /**
   * Warn about timers that were never ended, then flush and close all transports,
   * stop the sampler and run plugin shutdown hooks. On a child logger only the
   * timer warnings run; the shared transports stay open.
   *
   * To flush on SIGTERM/SIGINT, set the `gracefulShutdown` config option rather
   * than writing your own signal handler; do not combine it with a manual
   * handler that calls `process.exit`, which can cut the flush short.
   *
   * @example
   * ```ts
   * await logger.close(); // e.g. at the end of a script or a test
   * ```
   */
  async close(): Promise<void> {
    for (const [label, timer] of this.timers) {
      await this.warn(`Timer '${label}' was not ended properly`, {
        startTime: new Date(timer.startTime).toISOString(),
        duration: `${Date.now() - timer.startTime}ms (incomplete)`,
      });
    }
    this.timers.clear();

    if (this._parent) return;

    if (this.transportManager) {
      await this.transportManager.close();
    }

    this._sampler?.destroy();
    await this._pluginRegistry.runOnShutdown();
    deregisterFromShutdown(this);
  }

  // ── Core log method ──────────────────────────────────────────────────────────

  private async log(level: string, message: string, data?: Record<string, unknown>): Promise<void> {
    if (this.config.silent) return;
    if (!this.shouldLog(level)) return;

    // One read of each ALS store per call. TraceContext is the source of truth for
    // the trace ID; a traceId on a bare LogixiaContext scope is only a fallback.
    const alsContext = LogixiaContext.get();
    let activeTraceId: string | undefined;
    if (this.config.traceId) {
      const ctxTraceId = alsContext?.traceId;
      activeTraceId =
        TraceContext.instance.getCurrentTraceId() ??
        (typeof ctxTraceId === 'string' ? ctxTraceId : undefined);
    }

    // ── Feature 8: Sampling ───────────────────────────────────────────────────
    if (this._sampler && !this._sampler.shouldEmit(level, activeTraceId)) return;

    // ── Feature 6: AsyncLocalStorage context auto-merge ───────────────────────
    // Merge ALS-stored fields (requestId, userId, …) into the payload so every
    // log call inside a LogixiaContext.run() scope automatically carries them.
    const hasAls = alsContext !== undefined && Object.keys(alsContext).length > 0;
    // ── Feature 14: OTel auto trace-log correlation ────────────────────────────
    // Only touch the OTel bridge when it has actually been initialised — skipping
    // the `{}` allocation + Object.keys on every log in the common (bridge-off) case.
    const otelFields = _isOtelBridgeEnabled() ? _getOtelPayloadIfEnabled() : undefined;
    const hasOtel = otelFields !== undefined && Object.keys(otelFields).length > 0;
    let mergedData: typeof data;
    if (hasAls) {
      mergedData = { ...alsContext, ...(hasOtel ? otelFields : {}), ...data };
    } else if (hasOtel) {
      mergedData = { ...otelFields, ...data };
    } else {
      mergedData = data;
    }

    // ── Feature 2: Redaction ─────────────────────────────────────────────────
    // Avoid spread allocation when contextData is empty (the common case)
    const rawPayload = this._hasContextData ? { ...this.contextData, ...mergedData } : mergedData;
    // _hasRedact is pre-computed in _buildPerfCaches() — skips the entire redaction
    // code path when no redact config is present (fast path for the common case).
    let payload: Record<string, unknown> | undefined;
    if (rawPayload !== undefined && rawPayload !== null) {
      if (this._hasRedact) {
        // Fail closed: if redaction cannot complete, never emit the raw payload.
        try {
          payload = applyRedaction(rawPayload, this.config.redact) ?? rawPayload;
        } catch (error) {
          internalError('Redaction failed', error);
          payload = { redaction: REDACTION_FAILED };
        }
      } else {
        payload = rawPayload;
      }
    }

    // Use a monomorphic LogEntry shape — always the same fields, some may be undefined.
    // Consistent shape lets V8 inline-cache property accesses across calls.
    const traceId = this.config.traceId ? (activeTraceId ?? this.fallbackTraceId) : undefined;
    // Pattern-based redaction also applies to the message string — a secret
    // interpolated into the message (e.g. `Auth: Bearer ${token}`) would
    // otherwise bypass redaction entirely and leak in plaintext. Path rules
    // don't apply to a bare string, so only `patterns` run here.
    let safeMessage: string = message;
    if (this._hasRedact) {
      try {
        safeMessage = applyRedactionToString(message, this.config.redact);
      } catch (error) {
        internalError('Redaction failed', error);
        safeMessage = REDACTION_FAILED;
      }
    }
    const entry: LogEntry = {
      timestamp: nowIso(),
      level,
      appName: this.config.appName ?? 'App',
      environment: this.config.environment ?? 'development',
      message: safeMessage,
    };
    if (this.context) entry.context = this.context;
    if (payload !== undefined) entry.payload = payload;
    if (traceId !== undefined) entry.traceId = traceId;

    // ── Feature 20: Plugin onLog hooks ────────────────────────────────────────
    // Plugins run post-redaction, pre-transport. Any plugin may mutate or cancel
    // the entry by returning null. We only run the pipeline when plugins are registered.
    let finalEntry: LogEntry | null = entry;
    if (this._pluginRegistry.size > 0) {
      finalEntry = await this._pluginRegistry.runOnLog(entry);
      if (finalEntry === null) return; // entry cancelled by a plugin
    }

    // NOTE: do NOT pre-format here. When a transport manager is present (the
    // normal case) each transport formats the entry itself, so eagerly calling
    // formatLog() would be wasted work thrown away. output() formats lazily only
    // for the no-transport fallback path.
    const out = this.output(finalEntry, level);
    if (out !== undefined) await out;
  }

  // ── Feature 3: Namespace-aware shouldLog ─────────────────────────────────────

  /**
   * Hot-path level check: a single Map lookup + integer compare.
   * The level map and threshold are pre-built in _buildPerfCaches().
   */
  private shouldLog(level: string): boolean {
    if (this._nsSeenVersion !== this._nsStore.version) this._syncNamespaceLevels();
    const v = this._levelValues.get(level);
    return v !== undefined && v <= this._minLevelValue;
  }

  /**
   * Feature 3: Resolve the effective log level for this logger instance.
   *
   * Priority:
   *  0. A level set at runtime with `setLevel()` (explicit programmatic call, wins over all below)
   *  1. ENV `LOGIXIA_LEVEL_<NS_UPPER>` (e.g. LOGIXIA_LEVEL_DB for ns "db" or "db.queries")
   *  2. Matching `namespaceLevels` config entry (longer pattern = more specific, wins)
   *  3. Global `LOGIXIA_LEVEL` ENV override
   *  4. `levelOptions.level` (resolved via Feature 5 in constructor)
   */
  private resolveEffectiveLevel(): LogLevelString {
    if (this._runtimeLevel) return this._runtimeLevel as LogLevelString;

    const ns = this.context;

    if (ns) {
      // 1. ENV namespace override: LOGIXIA_LEVEL_DB → context "db" or "db.queries"
      const nsKey = ns.split('.')[0]!.toUpperCase();
      const envNsLevel = this._validLevel(
        process.env[`LOGIXIA_LEVEL_${nsKey}`],
        `LOGIXIA_LEVEL_${nsKey}`
      );
      if (envNsLevel) return envNsLevel;

      // 2. namespaceLevels config
      const namespaceLevels = this._nsStore.levels;
      if (Object.keys(namespaceLevels).length > 0) {
        const sortedPatterns = Object.keys(namespaceLevels).sort((a, b) => b.length - a.length);
        for (const pattern of sortedPatterns) {
          if (matchesNamespacePattern(ns, pattern)) {
            const nsLevel = this._validLevel(
              namespaceLevels[pattern],
              `namespaceLevels['${pattern}']`
            );
            if (nsLevel) return nsLevel;
          }
        }
      }
    }

    // 3. Global ENV override
    const globalEnv = this._validLevel(process.env['LOGIXIA_LEVEL'], 'LOGIXIA_LEVEL');
    if (globalEnv) return globalEnv;

    // 4. Config-resolved level
    return this.getLevel();
  }

  // ── Formatters ───────────────────────────────────────────────────────────────

  private formatLog(entry: LogEntry): string {
    // JSON mode: use fast-json-stringify (pre-compiled serializer, ~59% faster than JSON.stringify)
    if (this.config.format?.json) {
      try {
        return _fastStringifyEntry(entry);
      } catch {
        // A BigInt or a cycle in the payload — rare, so pay for the safe walk only then.
        return stringifyForLog(entry);
      }
    }

    let formatted = '';

    const doColorize = this.config.format?.colorize ?? true;
    const gray = doColorize ? this._colorMap.get('gray')! : '';
    const cyan = doColorize ? this._colorMap.get('cyan')! : '';
    const yellow = doColorize ? this._colorMap.get('yellow')! : '';
    const reset = doColorize ? this._colorMap.get('reset')! : '';

    // Use _fieldCache instead of calling isFieldEnabled() per field
    if (this.config.format?.timestamp !== false && this._fieldCache.get('timestamp') !== false) {
      // entry.timestamp is already an ISO string — no need to re-parse it
      formatted += `${gray}[${entry.timestamp}]${reset} `;
    }

    // Use pre-computed level string (avoids colorize() call + template literal allocation)
    if (this._fieldCache.get('level') !== false) {
      formatted += this._formattedLevels.get(entry.level) ?? `[${entry.level.toUpperCase()}] `;
    }

    // Use pre-computed "[appName] " string (built once in _buildPerfCaches)
    formatted += this._formattedAppName;

    if (entry.traceId && this._fieldCache.get('traceId') !== false)
      formatted += `${cyan}[${stripControlChars(String(entry.traceId))}]${reset} `;
    if (entry.context && this._fieldCache.get('context') !== false)
      formatted += `${yellow}[${stripControlChars(String(entry.context))}]${reset} `;
    if (this._fieldCache.get('message') !== false) {
      formatted += stripControlChars(safeToString(entry.message));
    }

    if (entry.payload !== undefined && this._fieldCache.get('payload') !== false) {
      formatted += ` ${stringifyForLog(entry.payload)}`;
    }

    return formatted;
  }

  private colorize(text: string, color: string): string {
    if (!this.config.format?.colorize) return text;
    // Use pre-built _colorMap instead of recreating the colors object every call
    const code = this._colorMap.get(color.toLowerCase()) ?? this._colorMap.get('white')!;
    return `${code}${text}${this._colorMap.get('reset')!}`;
  }

  /**
   * Dispatch the entry to transports (each formats itself). Returns `void` when
   * the write completes synchronously (console-only hot path) and a Promise only
   * when a transport is genuinely async — so the caller awaits only when needed.
   * Formatting for the no-transport fallback is done lazily, never on the
   * transport path.
   */
  private output(entry: LogEntry, level: string): void | Promise<void> {
    if (this.transportManager) {
      let result: void | Promise<void>;
      try {
        result = this.transportManager.write(entry);
      } catch (error) {
        return this._handleOutputError(error, entry, level);
      }
      if (result && typeof (result as Promise<void>).then === 'function') {
        return (result as Promise<void>).then(undefined, (error: unknown) =>
          this._handleOutputError(error, entry, level)
        );
      }
      return; // synchronous transport write completed
    }

    // Fallback: no transport manager → format lazily and write to stdout/stderr.
    const sink = level === LogLevel.ERROR ? process.stderr : process.stdout;
    sink.write(this.formatLog(entry) + '\n');
  }

  /** Shared transport-failure handler: log internally, notify plugins, then fall
   * back to a direct stdout/stderr write so the entry is never lost. */
  private async _handleOutputError(error: unknown, entry: LogEntry, level: string): Promise<void> {
    internalError('Transport write failed', error);
    if (this._pluginRegistry.size > 0) {
      await this._pluginRegistry.runOnError(
        error instanceof Error ? error : new Error(String(error)),
        entry
      );
    }
    const sink = level === LogLevel.ERROR ? process.stderr : process.stdout;
    sink.write(this.formatLog(entry) + '\n');
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create a logger from `config`, with an optional default `context` label.
 *
 * Every key of `levelOptions.levels` that is not already a method becomes an
 * async method on the returned logger, typed through the config, and routes to
 * {@link LogixiaLogger.logLevel}.
 *
 * @example
 * ```ts
 * const logger = createLogger({
 *   appName: 'api',
 *   levelOptions: { level: 'info', levels: { error: 0, warn: 1, info: 2, audit: 2 } },
 * });
 * await logger.audit('user exported data', { userId: 'u1' });
 * ```
 */
export function createLogger<T extends LoggerConfig<Record<string, number>>>(
  config: T,
  context?: string
): LoggerWithLevels<T> {
  const logger = new LogixiaLogger<T>(config, context);
  const mutableLogger = logger as unknown as Record<string, unknown>;

  if (config.levelOptions?.levels) {
    for (const levelName of Object.keys(config.levelOptions.levels)) {
      if (!mutableLogger[levelName]) {
        mutableLogger[levelName] = async (message: string, data?: Record<string, unknown>) => {
          await logger.logLevel(levelName, message, data);
        };
      }
    }
  }

  return logger as unknown as LoggerWithLevels<T>;
}
