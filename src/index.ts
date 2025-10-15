/**
 * Logixia - Advanced TypeScript Logger
 * 
 * A comprehensive logging library with support for:
 * - Multiple output formats (console, file, JSON)
 * - Trace ID tracking
 * - Performance monitoring
 * - NestJS integration
 * - Customizable log levels and colors
 */

import { LogixiaLogger, createLogger as createLoggerFromCore } from './core/logitron-logger';
import { LogixiaLoggerService } from './core/logitron-nestjs.service';
import { LoggerConfig, LogLevel, LogColor, Environment } from './types';

// Type exports
export * from './types';
export * from './core/logitron-nestjs.service';
export * from './core/logitron-logger.module';
export * from './formatters';
export * from './utils/trace.utils';
export * from './utils/error.utils';
export * from './security';

// Core exports
export { LogixiaLogger, LogixiaLoggerService, DEFAULT_CONFIG };

/**
 * Default configuration for Logixia logger
 */
const DEFAULT_CONFIG = {
  appName: 'App',
  environment: 'development' as Environment,
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
    } as Record<string, LogColor>,
  },
  fields: {
    timestamp: true,
    level: true,
    appName: true,
    traceId: true,
    message: true,
    payload: true,
    timeTaken: true,
  },
  outputs: ['console'],
};

/**
 * Create a new Logixia logger instance with TypeScript support for custom levels
 * @param config - Logger configuration
 * @returns Typed logger instance
 */
export const createLogger = createLoggerFromCore;

/**
 * Create a new Logixia logger service for NestJS
 * @param config - Logger configuration
 * @returns LogixiaLoggerService instance
 */
export function createLoggerService(config?: Partial<LoggerConfig>): LogixiaLoggerService {
  return new LogixiaLoggerService({ ...DEFAULT_CONFIG, ...config });
}

/**
 * Default logger instance
 */
export const logger = new LogixiaLogger(DEFAULT_CONFIG);

/**
 * Export default configuration for reference
 */