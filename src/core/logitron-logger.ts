/**
 * Core Logixia Logger implementation
 */

import { TransportManager } from '../transports/transport.manager';
import type {
  ContextData,
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
import { generateTraceId, getCurrentTraceId } from '../utils/trace.utils';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- generic logger config allows any transport config shape
export class LogixiaLogger<TConfig extends LoggerConfig<any> = LoggerConfig>
  implements ILoggerDefault
{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- index signature for dynamic custom level methods
  [K: string]: any; // Allow dynamic custom level methods
  private config: TConfig;
  private context?: string;
  private timers: Map<string, TimingEntry> = new Map();
  private contextData: ContextData = {};
  private transportManager?: TransportManager;
  private fieldState: Map<string, boolean> = new Map(); // Track field enable/disable state
  /**
   * Stable fallback trace ID generated ONCE per logger instance.
   * Used when no request-scoped trace ID is available in AsyncLocalStorage
   * (e.g. background jobs, CLI scripts, tests). This ensures all log lines
   * from a single logger instance share the same ID instead of generating a
   * fresh UUID on every log() call.
   */
  private readonly fallbackTraceId: string = generateTraceId();

  constructor(config: TConfig, context?: string) {
    const defaultConfig: LoggerConfig = {
      appName: 'App',
      environment: 'development',
      traceId: true,
      format: {
        timestamp: true,
        colorize: true,
        json: false,
      },
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

    // Set default fields if not provided
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

    // Initialize transport manager if transports are configured
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- transports is on extended config shapes
    if ((this.config as any).transports) {
      this.transportManager = new TransportManager(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- transports typed as any in extended config
        (this.config as any).transports
      );
    }

    // Create dynamic methods for custom levels
    this.createCustomLevelMethods();
  }

  /**
   * Create dynamic methods for custom levels
   */
  private createCustomLevelMethods(): void {
    if (this.config.levelOptions?.levels) {
      for (const levelName of Object.keys(this.config.levelOptions.levels)) {
        // Skip if method already exists (predefined levels)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- dynamic method lookup on index signature
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
   * Error logging with overloads
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

  /**
   * Log with custom level
   */
  async logLevel(level: string, message: string, data?: Record<string, unknown>): Promise<void> {
    await this.log(level, message, data);
  }

  /**
   * Timing methods
   */
  time(label: string): void {
    this.timers.set(label, {
      label,
      startTime: Date.now(),
    });
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

  /**
   * Level and context management
   */
  setLevel(level: LogLevelString): void {
    this.config.levelOptions = this.config.levelOptions || {};
    this.config.levelOptions.level = level as string;
  }

  getLevel(): LogLevelString {
    return (this.config.levelOptions?.level as LogLevelString) || LogLevel.INFO;
  }

  setContext(context: string): void {
    this.context = context;
  }

  getContext(): string | undefined {
    return this.context;
  }

  // Field Management Methods
  enableField(fieldName: string): void {
    this.fieldState.set(fieldName, true);
    internalLog(`Field '${fieldName}' enabled`);
  }

  disableField(fieldName: string): void {
    this.fieldState.set(fieldName, false);
    internalLog(`Field '${fieldName}' disabled`);
  }

  isFieldEnabled(fieldName: string): boolean {
    // Check fieldState first, then fall back to config
    if (this.fieldState.has(fieldName)) {
      return this.fieldState.get(fieldName)!;
    }

    // Check config.fields
    if (
      this.config.fields &&
      this.config.fields[fieldName as keyof typeof this.config.fields] !== undefined
    ) {
      const fieldValue = this.config.fields[fieldName as keyof typeof this.config.fields];
      return fieldValue !== false;
    }

    return true; // Default to enabled
  }

  getFieldState(): Record<string, boolean> {
    const state: Record<string, boolean> = {};

    // Get all possible fields from config
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

    for (const field of allFields) {
      state[field] = this.isFieldEnabled(field);
    }

    return state;
  }

  resetFieldState(): void {
    this.fieldState.clear();
    internalLog('Field state reset to configuration defaults');
  }

  // Transport Level Management Methods
  enableTransportLevelPrompting(): void {
    if (this.transportManager) {
      this.transportManager.enableLevelPrompting();
    } else {
      internalWarn('Transport manager not initialized');
    }
  }

  disableTransportLevelPrompting(): void {
    if (this.transportManager) {
      this.transportManager.disableLevelPrompting();
    } else {
      internalWarn('Transport manager not initialized');
    }
  }

  setTransportLevels(transportId: string, levels: string[]): void {
    if (this.transportManager) {
      this.transportManager.setTransportLevels(transportId, levels);
    } else {
      internalWarn('Transport manager not initialized');
    }
  }

  getTransportLevels(transportId: string): string[] | undefined {
    if (this.transportManager) {
      return this.transportManager.getTransportLevels(transportId);
    }
    internalWarn('Transport manager not initialized');
    return undefined;
  }

  clearTransportLevelPreferences(): void {
    if (this.transportManager) {
      this.transportManager.clearTransportLevelPreferences();
    } else {
      internalWarn('Transport manager not initialized');
    }
  }

  getAvailableTransports(): string[] {
    if (this.transportManager) {
      return this.transportManager.getTransports();
    }
    return [];
  }

  /**
   * Create child logger
   */
  child(context: string, data?: Record<string, unknown>): ILogger {
    const childLogger = new LogixiaLogger(this.config, context);
    if (data) {
      childLogger.contextData = { ...this.contextData, ...data };
    }
    return childLogger;
  }

  /**
   * Flush all transports
   */
  async flush(): Promise<void> {
    if (this.transportManager) {
      await this.transportManager.flush();
    }
  }

  /**
   * Check health of all transports
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    details: Record<string, unknown>;
  }> {
    if (!this.transportManager) {
      return {
        healthy: false,
        details: { error: 'TransportManager not initialized' },
      };
    }

    return await this.transportManager.healthCheck();
  }

  /**
   * Close logger and cleanup resources
   */
  async close(): Promise<void> {
    // Log any remaining timers
    for (const [label, timer] of this.timers) {
      await this.warn(`Timer '${label}' was not ended properly`, {
        startTime: new Date(timer.startTime).toISOString(),
        duration: `${Date.now() - timer.startTime}ms (incomplete)`,
      });
    }
    this.timers.clear();

    // Flush and close transport manager
    if (this.transportManager) {
      await this.transportManager.flush();
      await this.transportManager.close();
    }
  }

  /**
   * Core logging method
   */
  private async log(level: string, message: string, data?: Record<string, unknown>): Promise<void> {
    // Check if logging is disabled
    if (this.config.silent) {
      return;
    }

    // Check log level
    if (!this.shouldLog(level)) {
      return;
    }

    // Create log entry
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      appName: this.config.appName ?? 'App',
      environment: this.config.environment ?? 'development',
      message,
      ...(this.context && { context: this.context }),
      payload: { ...this.contextData, ...data },
    };

    // Add trace ID if enabled.
    // Priority: 1) request-scoped ID from AsyncLocalStorage (set by TraceMiddleware)
    //           2) stable fallback ID generated once per logger instance
    // Never call generateTraceId() per-log-call — that creates a different UUID for
    // every log line, making distributed tracing useless.
    if (this.config.traceId) {
      entry.traceId = getCurrentTraceId() ?? this.fallbackTraceId;
    }

    // Format and output log
    const formattedLog = this.formatLog(entry);
    await this.output(formattedLog, level, entry);
  }

  /**
   * Format log entry according to configuration
   */
  private formatLog(entry: LogEntry): string {
    if (this.config.format?.json) {
      return JSON.stringify(entry);
    }

    // Build formatted string
    let formatted = '';

    // Timestamp
    if (this.config.format?.timestamp !== false && this.isFieldEnabled('timestamp')) {
      const timestamp = new Date(entry.timestamp).toLocaleString();
      formatted += `[${timestamp}] `;
    }

    // Log level
    if (this.isFieldEnabled('level')) {
      const levelName = entry.level;
      const coloredLevel = this.config.format?.colorize
        ? this.colorize(
            levelName.toUpperCase(),
            this.config.levelOptions?.colors?.[levelName] || 'white'
          )
        : levelName.toUpperCase();
      formatted += `[${coloredLevel}] `;
    }

    // App name
    if (this.isFieldEnabled('appName')) {
      formatted += `[${entry.appName}] `;
    }

    // Trace ID
    if (entry.traceId && this.isFieldEnabled('traceId')) {
      formatted += `[${entry.traceId}] `;
    }

    // Context
    if (entry.context && this.isFieldEnabled('context')) {
      formatted += `[${entry.context}] `;
    }

    // Message
    if (this.isFieldEnabled('message')) {
      formatted += entry.message;
    }

    // Payload
    if (entry.payload && Object.keys(entry.payload).length > 0 && this.isFieldEnabled('payload')) {
      formatted += ` ${JSON.stringify(entry.payload)}`;
    }

    return formatted;
  }

  /**
   * Colorize text based on color name
   */
  private colorize(text: string, color: string): string {
    if (!this.config.format?.colorize) {
      return text;
    }

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

    const colorCode = colors[color.toLowerCase()] || colors.white;
    return `${colorCode}${text}${colors.reset}`;
  }

  private shouldLog(level: string): boolean {
    const currentLevel = this.getLevel();

    // Create level map with custom levels
    const levelMap: Record<string, number> = {
      [LogLevel.ERROR]: 0,
      [LogLevel.WARN]: 1,
      [LogLevel.INFO]: 2,
      [LogLevel.DEBUG]: 3,
      [LogLevel.TRACE]: 4,
      [LogLevel.VERBOSE]: 5,
      ...(this.config.levelOptions?.levels || {}),
    };

    const currentLevelValue = levelMap[currentLevel];
    const messageLevelValue = levelMap[level];

    return (
      messageLevelValue !== undefined &&
      currentLevelValue !== undefined &&
      messageLevelValue <= currentLevelValue
    );
  }

  /**
   * Output log to console or other destinations
   */
  private async output(message: string, level: string, entry: LogEntry): Promise<void> {
    // Use transport manager if available
    if (this.transportManager) {
      try {
        await this.transportManager.write(entry);
        return;
      } catch (error) {
        // Fallback to console if transport fails
        internalError('Transport write failed', error);
      }
    }

    // Fallback to console output
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

/**
 * Factory function to create a typed logger with custom levels
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- generic config type parameter
export function createLogger<T extends LoggerConfig<any>>(
  config: T,
  context?: string
): LoggerWithLevels<T> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- cast needed for dynamic method attachment
  const logger = new LogixiaLogger<T>(config, context) as any;

  // Add custom level methods dynamically
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
