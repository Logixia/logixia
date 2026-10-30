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

export { KafkaTraceInterceptor } from './core/kafka-trace.interceptor';
export type { LogixiaAsyncOptions, LogixiaOptionsFactory } from './core/logitron-logger.module';
export {
  LOGIXIA_LOGGER_CONFIG,
  LOGIXIA_LOGGER_PREFIX,
  LogixiaLoggerModule,
} from './core/logitron-logger.module';
export type { LogixiaServiceWith, LogixiaServiceWithLevels } from './core/logitron-nestjs.service';
export { LogixiaLoggerService } from './core/logitron-nestjs.service';
export type { LogixiaExceptionFilterOptions } from './core/nestjs-extras';
export { LOGIXIA_EXCEPTION_FILTER_OPTIONS, LogixiaExceptionFilter } from './core/nestjs-extras';
export { TraceMiddleware } from './core/trace.middleware';
export { WebSocketTraceInterceptor } from './core/websocket-trace.interceptor';

/**
 * Create a new Logixia logger service for NestJS
 * @param config - Logger configuration
 * @returns LogixiaLoggerService instance
 */
export function createLoggerService(config?: Partial<LoggerConfig>): LogixiaLoggerService {
  return new LogixiaLoggerService({ ...DEFAULT_CONFIG, ...config });
}
