---
title: NestJS integration
description: 'Use logixia in NestJS: LogixiaLoggerModule, LogixiaLoggerService, trace IDs, LogixiaExceptionFilter, LogMethod and Kafka or WebSocket interceptors.'
order: 8
---

# NestJS integration

Everything NestJS-specific lives in `logixia/nest`. The root `logixia` entry does not export it, so you can use logixia without NestJS installed.

```ts
import { LogixiaLoggerModule, LogixiaLoggerService } from 'logixia/nest';
```

`@nestjs/common`, `reflect-metadata` and `express` are optional peer dependencies. Install the ones your app already uses.

## Register the module

```ts
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia/nest';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'orders-api',
      environment: 'production',
      levelOptions: { level: 'info' },
      traceId: true,
      redact: { autoDetect: true },
      transports: { console: { format: 'json' } },
    }),
  ],
})
export class AppModule {}
```

`forRoot(config)` takes a `Partial<LoggerConfig>`; see [Configuration](/guide/configuration). It registers a global module that provides `LogixiaLoggerService`, the interceptors below, and applies the trace middleware to every route.

::: tip Use levelOptions for the level
The level is configured in `levelOptions.level`. A top-level `level` key is not a `LoggerConfig` option and has no effect.
:::

### Async configuration

```ts
import { Injectable, Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia/nest';
import type { LogixiaOptionsFactory } from 'logixia/nest';

@Injectable()
class LoggingConfig implements LogixiaOptionsFactory {
  createLogixiaOptions() {
    return {
      appName: 'orders-api',
      levelOptions: { level: process.env['LOG_LEVEL'] ?? 'info' },
    };
  }
}

@Module({
  imports: [LogixiaLoggerModule.forRootAsync({ useClass: LoggingConfig })],
})
export class AppModule {}
```

`forRootAsync` accepts `useFactory` (with `inject` and `imports`), or `useClass` / `useExisting` with a class that implements `createLogixiaOptions()`, as above. A factory receives the injected providers as `unknown` arguments, so cast them to the types you need.

If the module is initialised more than once in a process (some test setups), the first logger wins and a warning is printed.

## Inject the service

Inject the class directly:

```ts
import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService } from 'logixia/nest';

@Injectable()
export class OrderService {
  constructor(private readonly logger: LogixiaLoggerService) {}

  async create(orderId: string): Promise<void> {
    await this.logger.info('order created', { orderId });
  }
}
```

`LogixiaLoggerService` implements Nest's `LoggerService` (so it also has `log()`), plus `info`, `warn`, `error`, `debug`, `verbose`, `trace`, `logLevel`, the timer methods, `setContext()`, `child()`, `getCurrentTraceId()`, `close()` and `getLogger()` (the underlying `LogixiaLogger`). Its `warn`, `debug` and `verbose` accept either `(message, data)` and return a promise, or Nest's `(message, context)` form.

To make Nest's own internal logging use it:

<!-- snippet-check: skip -->

```ts
import { NestFactory } from '@nestjs/core';
import { LogixiaLoggerService } from 'logixia/nest';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(LogixiaLoggerService));
  await app.listen(3000);
}

void bootstrap();
```

Outside dependency injection, `LogixiaLoggerModule.getGlobalLogger()` returns the service once the module has booted, or `null` before that. `createLoggerService(config?)` builds a standalone service without the module.

### Feature loggers and @InjectLogger

`LogixiaLoggerModule.forFeature('Payments')` provides a child logger under the token `LOGIXIA_LOGGER_PAYMENTS` (the upper-cased context after the `LOGIXIA_LOGGER_` prefix). Inject it with `@Inject('LOGIXIA_LOGGER_PAYMENTS')`.

`@InjectLogger()` injects the token `LOGIXIA_LOGGER_SERVICE`. `forRoot()` does not register that token, so on its own `@InjectLogger()` fails to resolve with "Nest can't resolve dependencies". It resolves if you also import `LogixiaLoggerModule.forFeature('service')`, which gives the injected logger the context `service`. Injecting `LogixiaLoggerService` by class, as above, is the more direct option.

## Request trace IDs

The module applies a trace middleware to all routes. For each request it reads an incoming ID from the headers in `DEFAULT_TRACE_HEADERS` (see [Tracing](/guide/tracing)) or the `traceId` / `trace_id` query parameters, generates one if none is valid, stores it on `req.traceId`, echoes it as `X-Trace-Id`, and runs the rest of the request inside the trace scope together with `method`, `url`, `userAgent` and `ip`. Every log in that request carries the ID.

Customize it with the object form of `traceId`:

```ts
import { LogixiaLoggerModule } from 'logixia/nest';

export const loggingModule = LogixiaLoggerModule.forRoot({
  appName: 'orders-api',
  traceId: {
    enabled: true,
    responseHeader: 'X-Request-Trace',
    extractor: { header: ['x-request-id'] },
  },
});
```

`TraceMiddleware` is exported for manual use with `consumer.apply(TraceMiddleware)`.

::: warning Set traceId explicitly for interceptors
The Kafka and WebSocket interceptors take their configuration from the `traceId` option. If you call `forRoot()` without `traceId`, they are created disabled and do nothing, even though the HTTP middleware still runs. Pass `traceId: true` (or an object) when you use them.
:::

## Exception filter

`LogixiaExceptionFilter` turns any thrown value into a consistent JSON error body and logs it with request context.

<!-- snippet-check: skip -->

```ts
import { NestFactory } from '@nestjs/core';
import { LogixiaExceptionFilter, LogixiaLoggerService } from 'logixia/nest';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const logger = app.get(LogixiaLoggerService);

  app.useGlobalFilters(
    new LogixiaExceptionFilter(logger, undefined, {
      exposeDebug: process.env['NODE_ENV'] === 'development',
    })
  );

  await app.listen(3000);
}

void bootstrap();
```

The constructor is `(logger?, loggerConfig?, options?)`; without a logger it falls back to the global one.

It handles, in order: a `LogixiaException`, a NestJS `HttpException`, and anything else (reported as a 500 `server_error`). Entries with status 500 or above are logged at `error`; the rest at `warn`.

Options:

| Option              | Default | Description                                                                             |
| ------------------- | ------- | --------------------------------------------------------------------------------------- |
| `exposeDebug`       | `false` | Include the `debug` block (stack, service, duration) in the response.                   |
| `exposeCause`       | `false` | Also include `debug.cause`. Needs `exposeDebug`.                                        |
| `redactQueryParams` | `[]`    | Extra query parameter names to redact, on top of the defaults and `redact.queryParams`. |

Debug output is off by default in every environment; enable it only for local development, because stacks and causes can reveal internals such as connection strings.

The logged `url` and the response `meta.path` have sensitive query values replaced with `[REDACTED]` (for example `/reset?token=[REDACTED]&page=2`), using the same default parameter list as the [HTTP logger](/guide/http-logging) (`token`, `access_token`, `code`, `password`, `api_key`, presigned-URL signatures and similar) plus any `redact.queryParams` from the logger config. The URL is read from `originalUrl` when present, so mount prefixes are kept and records match the HTTP logger.

Nest's built-in 404 puts the full URL in its message (`Cannot GET /reset?token=abc123`). The filter replaces the values of this request's sensitive parameters wherever they appear in the response `error.message`, `error.details`, `debug.stack` and `debug.cause`, redacts any `?query` inside those texts, and for 5xx errors logs a sanitized copy of the error. The exception you threw is never modified. The trace context `url` set by the trace middleware is redacted the same way.

The response body:

```json
{
  "success": false,
  "error": {
    "type": "validation_error",
    "code": "PE-VAL-001",
    "message": "Validation failed.",
    "param": "email",
    "details": [{ "field": "email", "message": "must be a valid email", "code": "invalid_format" }],
    "doc_url": "https://docs.example.com/errors/PE-VAL-001"
  },
  "meta": { "trace_id": "…", "timestamp": "…", "path": "/users", "status": 400 }
}
```

The trace ID is echoed in the configured trace response header, and `429` responses get `Retry-After: 60`.

Throw typed errors with `LogixiaException`. You choose the code and type unions; logixia fixes only the wire format:

```ts
import { LogixiaException } from 'logixia';

type AppCode = 'PE-AUTH-001' | 'PE-VAL-001';
type AppType = 'authentication_error' | 'validation_error';

export function rejectLogin(): never {
  throw new LogixiaException<AppCode, AppType>({
    code: 'PE-AUTH-001',
    type: 'authentication_error',
    httpStatus: 401,
    message: 'Invalid email or password.',
    metadata: { attempt: 3 },
  });
}
```

`metadata` is for logging only and never appears in the response. `cause` is serialized into `debug.cause` only when `exposeCause` is on. `isLogixiaException()` and `ErrorResponseBuilder` are exported from `logixia` for use outside Nest.

To configure the filter through dependency injection, provide `LOGIXIA_EXCEPTION_FILTER_OPTIONS`.

## @LogMethod

`@LogMethod()` logs entry, exit, duration and errors for a method. It uses `this.logger` if the class has one, otherwise the global logger.

```ts
import { Injectable } from '@nestjs/common';
import { LogMethod, LogixiaLoggerService } from 'logixia/nest';

@Injectable()
export class PaymentService {
  constructor(readonly logger: LogixiaLoggerService) {}

  @LogMethod({ level: 'info', logResult: true, label: 'payments.charge' })
  async charge(orderId: string, cents: number): Promise<{ ok: boolean }> {
    return { ok: cents > 0 && orderId.length > 0 };
  }
}
```

| Option      | Default        | Description                      |
| ----------- | -------------- | -------------------------------- |
| `level`     | `'debug'`      | Level for entry and exit lines.  |
| `logArgs`   | `true`         | Include the arguments.           |
| `logResult` | `false`        | Include the return value.        |
| `logErrors` | `true`         | Log thrown errors, then rethrow. |
| `label`     | `Class.method` | Name used in the messages.       |

Synchronous methods stay synchronous; async methods are awaited so the exit line reflects the result. Arguments are logged as they are, so combine this with [`redact`](/guide/redaction) or turn `logArgs` off for sensitive methods.

## Kafka and WebSocket interceptors

`KafkaTraceInterceptor` and `WebSocketTraceInterceptor` continue a trace in message handlers. They read an existing ID from the message body (`traceId`, `trace_id`, `x-trace-id`), headers (`x-trace-id`, `trace-id`) and, for WebSockets, the handshake query. They do not generate IDs; with none found the handler runs untraced.

```ts
import { Controller, UseInterceptors } from '@nestjs/common';
import { EventPattern, Payload } from '@nestjs/microservices';
import { KafkaTraceInterceptor, LogixiaLoggerService } from 'logixia/nest';

@Controller()
@UseInterceptors(KafkaTraceInterceptor)
export class OrderEvents {
  constructor(private readonly logger: LogixiaLoggerService) {}

  @EventPattern('orders.created')
  async onCreated(@Payload() event: { orderId: string }): Promise<void> {
    await this.logger.info('order event', { orderId: event.orderId });
  }
}
```

For Kafka, the scope also carries `topic`, `partition`, `offset`, `key` and `timestamp`. To drop messages that have no trace ID, construct it yourself with `new KafkaTraceInterceptor(traceConfig, true)`: such messages are acknowledged without running the handler, a warning is logged and `KafkaTraceInterceptor.metrics.dropped` is incremented. `KafkaTraceInterceptor.metrics` (`accepted`, `acceptedWithoutTrace`, `dropped`) can be scraped into your metrics system.

## Exports

`logixia/nest` exports `LogixiaLoggerModule`, `LogixiaLoggerService`, `LogixiaExceptionFilter`, `LOGIXIA_EXCEPTION_FILTER_OPTIONS`, `InjectLogger`, `LogMethod`, `TraceMiddleware`, `KafkaTraceInterceptor`, `WebSocketTraceInterceptor`, `createLoggerService`, the option types and the provider token constants. Upgrading from 1.x? See [Migrating to 2.0](/guide/migration-v2).
