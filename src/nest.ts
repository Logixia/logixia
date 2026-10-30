/**
 * logixia/nest — NestJS integration
 *
 * @example
 * import { LogixiaLoggerModule, LogixiaLoggerService } from 'logixia/nest';
 *
 * @Module({
 *   imports: [LogixiaLoggerModule.forRoot({ level: 'info' })],
 * })
 * export class AppModule {}
 */

import { DEFAULT_CONFIG } from './core/default-config';
import { LogixiaLoggerService } from './core/logitron-nestjs.service';
import type { LoggerConfig } from './types';

// Everything NestJS-specific. These were exported from the root `logixia`
// entry before 2.0.0; keep this list a superset of what the root used to export.
export * from './core/logitron-logger.module';
export * from './core/logitron-nestjs.service';
export type { LogixiaExceptionFilterOptions, LogMethodOptions } from './core/nestjs-extras';
export {
  InjectLogger,
  LOGIXIA_EXCEPTION_FILTER_OPTIONS,
  LogixiaExceptionFilter,
  LogMethod,
} from './core/nestjs-extras';
export { TraceMiddleware } from './core/trace.middleware';

/**
 * Create a new Logixia logger service for NestJS
 * @param config - Logger configuration
 * @returns LogixiaLoggerService instance
 */
export function createLoggerService(config?: Partial<LoggerConfig>): LogixiaLoggerService {
  return new LogixiaLoggerService({ ...DEFAULT_CONFIG, ...config });
}
