import { LogLevel } from '../../../src/types';
import type { LogixiaServiceWith } from '../../../src/core/logitron-nestjs.service';

/**
 * Shared Logixia config — define custom levels once with `as const`,
 * derive the typed logger alias from it.
 *
 * Real-world apps importing from 'logixia/nest':
 *   import type { LogixiaServiceWith } from 'logixia/nest';
 */
export const logixiaConfig = {
  levelOptions: {
    levels: {
      [LogLevel.ERROR]: 0,
      [LogLevel.WARN]: 1,
      [LogLevel.INFO]: 2,
      [LogLevel.DEBUG]: 3,
      [LogLevel.VERBOSE]: 4,
      kafka: 5,
    },
    colors: {
      [LogLevel.ERROR]: 'red',
      [LogLevel.WARN]: 'yellow',
      [LogLevel.INFO]: 'blue',
      [LogLevel.DEBUG]: 'green',
      [LogLevel.VERBOSE]: 'cyan',
      kafka: 'magenta',
    },
  },
} as const;

/**
 * Use this type everywhere instead of plain `LogixiaLoggerService`.
 * Gives typed autocomplete for `kafka()` (and any future custom levels).
 */
export type AppLogger = LogixiaServiceWith<typeof logixiaConfig>;
