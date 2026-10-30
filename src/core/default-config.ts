import type { Environment, LogColor } from '../types';
import { LogLevel } from '../types';

/**
 * Default configuration for Logixia logger
 */
export const DEFAULT_CONFIG = {
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
