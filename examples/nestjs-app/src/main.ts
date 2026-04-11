import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';
import { AppModule } from './app.module';
import { LogixiaLoggerService } from '../../../src/core/logitron-nestjs.service';
import { LogixiaExceptionFilter } from '../../../src/core/nestjs-extras';
import { HttpLoggingInterceptor } from './interceptors/http-logging.interceptor';

const KAFKA_BROKERS = (process.env['KAFKA_BROKERS'] ?? 'localhost:9092').split(',');
const KAFKA_GROUP   = process.env['KAFKA_GROUP_ID'] ?? 'logixia-group';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  // ── 1. Logger — replace NestJS built-in with Logixia ──────────────────────
  const logger = app.get(LogixiaLoggerService);
  app.useLogger(logger);

  // ── 2. Global exception filter ────────────────────────────────────────────
  // Catches ALL unhandled exceptions.
  // LogixiaException  → WARN  + structured { method, url, status, request_id }
  // plain Error / 5xx → ERROR + structured { method, url, status, request_id }
  app.useGlobalFilters(new LogixiaExceptionFilter(logger));

  // ── 3. Global HTTP logging interceptor ───────────────────────────────────
  // Logs every request (→) and response (←) with method, url, status, duration.
  // TraceMiddleware (registered by LogixiaLoggerModule) runs BEFORE interceptors,
  // so every log line inside the interceptor already carries the traceId.
  app.useGlobalInterceptors(new HttpLoggingInterceptor(logger));

  // ── 4. WebSocket adapter ─────────────────────────────────────────────────
  // Required for @WebSocketGateway to work with socket.io
  const { IoAdapter } = await import('@nestjs/platform-socket.io');
  app.useWebSocketAdapter(new IoAdapter(app));

  // ── 5. Kafka microservice consumer ───────────────────────────────────────
  // Only connect when KAFKA_BROKERS is set (i.e. inside Docker).
  // @EventPattern handlers in KafkaController consume from the real broker.
  // KafkaTraceInterceptor on KafkaController extracts traceId from message
  // body so all logs inside the handler carry the same traceId as the producer.
  if (process.env['KAFKA_ENABLED'] === 'true') {
    app.connectMicroservice<MicroserviceOptions>({
      transport: Transport.KAFKA,
      options: {
        client: {
          clientId: 'logixia-consumer',
          brokers:  KAFKA_BROKERS,
        },
        consumer: {
          groupId: KAFKA_GROUP,
        },
      },
    });
    await app.startAllMicroservices();
  }

  const port = Number(process.env['PORT'] ?? 3000);
  await app.listen(port);

  await logger.info(`Application running on http://localhost:${port}`, {
    kafka: process.env['KAFKA_ENABLED'] === 'true' ? { brokers: KAFKA_BROKERS, group: KAFKA_GROUP } : 'disabled',
    routes: [
      // HTTP
      'GET  /health               — liveness + current traceId',
      'POST /health/broadcast     — HTTP→WS traceId propagation demo',
      'GET  /health/log-levels    — fires all log levels',
      'GET  /users                — list users  (@LogMethod debug + child logger)',
      'GET  /users/:id            — find user   (LogixiaException 404 on miss)',
      'POST /users                — create user (timeAsync + conflict 409)',
      'GET  /users/trace-check             — TraceIdGuard: 403 if no traceId in context',
      'POST /users/trace-check             — TraceIdGuard: 403 if no traceId in context',
      'GET  /orders               — list orders',
      'POST /orders               — create order',
      'GET  /orders/boom          — LogixiaException 400 → WARN log',
      'GET  /orders/crash         — plain Error 500   → ERROR log',
      'GET  /orders/conflict      — LogixiaException 409 → WARN log',
      'GET  /orders/rate-limit    — LogixiaException 429 → WARN + Retry-After header',
      'POST /kafka/simulate       — in-process Kafka simulation (no broker needed)',
      'POST /kafka/publish        — publish to real Kafka broker (requires Docker)',
      // WebSocket
      'WS   ws://localhost:3000/events  ping / chat events (WebSocketTraceInterceptor)',
    ],
  });
}

bootstrap().catch(console.error);
