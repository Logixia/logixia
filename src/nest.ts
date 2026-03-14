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

export { KafkaTraceInterceptor } from './core/kafka-trace.interceptor';
export type { LogixiaAsyncOptions, LogixiaOptionsFactory } from './core/logitron-logger.module';
export {
  LOGIXIA_LOGGER_CONFIG,
  LOGIXIA_LOGGER_PREFIX,
  LogixiaLoggerModule,
} from './core/logitron-logger.module';
export { LogixiaLoggerService } from './core/logitron-nestjs.service';
export { RequestContextManager } from './core/request-context';
export { TraceMiddleware } from './core/trace.middleware';
export { WebSocketTraceInterceptor } from './core/websocket-trace.interceptor';
