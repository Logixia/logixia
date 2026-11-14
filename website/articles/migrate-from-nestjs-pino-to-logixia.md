---
title: 'Migrate from nestjs-pino to logixia: A NestJS Mapping Guide'
description: 'Looking for a nestjs-pino alternative? Map LoggerModule.forRoot, PinoLogger, InjectPinoLogger, app.useLogger, request context and redact to logixia in NestJS.'
date: 2026-11-14
tags: [nestjs, nestjs-pino, migration, logging, nodejs]
---

# Migrate from nestjs-pino to logixia: A NestJS Mapping Guide

**TL;DR:** To move a NestJS app from `nestjs-pino` to logixia, replace `LoggerModule.forRoot({ pinoHttp })` with `LogixiaLoggerModule.forRoot({ ... })` from `logixia/nest`, replace `PinoLogger` and `@InjectPinoLogger()` with `LogixiaLoggerService`, keep `app.useLogger(...)` pointing at the new service, swap the argument order of log calls (`logger.info(obj, msg)` becomes `logger.info(msg, obj)`), and move `pinoHttp.redact` to logixia's `redact`. Two things do not map one-to-one: logixia's module does not log one line per request by itself (you add the HTTP middleware), and there is no `req.log`. If `nestjs-pino` works for you, keep it; this guide is for teams who want logixia's built-in tracing, redaction and transports. I maintain logixia.

For the broader decision, see [the best NestJS logger comparison](/articles/best-nestjs-logger). For the pino concepts underneath (levels, redact, transports), see [migrating from pino to logixia](/articles/migrate-from-pino-to-logixia).

## What does a typical nestjs-pino setup look like?

<!-- snippet-check: skip -->

```ts
// app.module.ts
import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';

@Module({
  imports: [
    LoggerModule.forRoot({
      pinoHttp: {
        level: 'info',
        redact: ['req.headers.authorization'],
        autoLogging: { ignore: (req) => req.url === '/health' },
        customProps: () => ({ service: 'orders-api' }),
      },
    }),
  ],
})
export class AppModule {}

// order.service.ts
import { Injectable } from '@nestjs/common';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';

@Injectable()
export class OrderService {
  constructor(@InjectPinoLogger(OrderService.name) private readonly logger: PinoLogger) {}

  create(orderId: string) {
    this.logger.info({ orderId }, 'order created');
  }
}

// main.ts
import { NestFactory } from '@nestjs/core';
import { Logger } from 'nestjs-pino';

const app = await NestFactory.create(AppModule, { bufferLogs: true });
app.useLogger(app.get(Logger));
```

## What is the equivalent module registration in logixia?

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
      redact: { paths: ['req.headers.authorization'], autoDetect: true },
      transports: { console: { format: 'json', colorize: false } },
    }),
  ],
})
export class AppModule {}
```

`forRoot` takes the same `LoggerConfig` as `createLogger` (see [configuration](/guide/configuration)). The module is global, provides `LogixiaLoggerService`, and applies a trace middleware to every route. Async configuration works with `forRootAsync` (`useFactory`, `useClass` or `useExisting`), the counterpart of nestjs-pino's `forRootAsync`; the [NestJS guide](/guide/nestjs) has the details.

| nestjs-pino                                          | logixia                                                                                       |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `LoggerModule.forRoot({ pinoHttp })`                 | `LogixiaLoggerModule.forRoot(loggerConfig)`                                                   |
| `pinoHttp.level`                                     | `levelOptions.level`                                                                          |
| `pinoHttp.redact`                                    | `redact` ([redaction guide](/guide/redaction))                                                |
| `pinoHttp.transport` (`pino-pretty`, files, vendors) | `transports` ([overview](/guide/transports/)); default text output is readable in development |
| `pinoHttp.genReqId`                                  | `traceId: { generator, extractor }`                                                           |
| `pinoHttp.customProps`                               | `LogixiaContext.set()` mid-request, or `extraFields` on the HTTP middleware                   |
| `pinoHttp.autoLogging`                               | not automatic: add `createExpressMiddleware` (below)                                          |

## How do I replace PinoLogger and @InjectPinoLogger?

Inject `LogixiaLoggerService` by class and set a context name. The service is transient, so each consumer gets its own instance and its own context label.

```ts
import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService } from 'logixia/nest';

@Injectable()
export class OrderService {
  constructor(private readonly logger: LogixiaLoggerService) {
    this.logger.setContext(OrderService.name);
  }

  async create(orderId: string): Promise<void> {
    await this.logger.info('order created', { orderId });
  }
}
```

Differences from `PinoLogger`:

- **Argument order is reversed**: message first, data second.
- **Methods return promises**; `await` them in async code.
- **No `setContext` string argument on every call**; the context lives on the injected instance.
- **`@InjectLogger()` is not a drop-in for `@InjectPinoLogger(name)`.** It injects the token `LOGIXIA_LOGGER_SERVICE`, which `forRoot()` does not register. If you want per-feature loggers by token, use `LogixiaLoggerModule.forFeature('Orders')` and `@Inject('LOGIXIA_LOGGER_ORDERS')`. Injecting the class is the simpler route.
- **Error logging**: `logger.error('failed', { err })` serializes name, message and stack; so does `logger.error(err)`.

## How does `app.useLogger` change?

It is the same pattern with a different class:

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

`LogixiaLoggerService` implements Nest's `LoggerService`, so Nest's startup and framework logs go through logixia. Outside dependency injection, `LogixiaLoggerModule.getGlobalLogger()` returns the service once the module has booted (and `null` before that).

## How do I get one log line per request, like pino-http?

`nestjs-pino` logs a completion line per request through `pino-http`. logixia's module sets up trace IDs but does not log requests on its own. Add the HTTP middleware, using the underlying logger:

<!-- snippet-check: skip -->

```ts
import { NestFactory } from '@nestjs/core';
import { createExpressMiddleware } from 'logixia/middleware';
import { LogixiaLoggerService } from 'logixia/nest';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  const logger = app.get(LogixiaLoggerService);
  app.useLogger(logger);
  app.use(
    createExpressMiddleware(logger.getLogger(), {
      skip: (req) => req.url === '/health',
      slowRequestThresholdMs: 500,
    })
  );
  await app.listen(3000);
}

void bootstrap();
```

It logs `request started` (at `debug`), `request completed` with `statusCode` and `duration`, and a `slow request detected` warning, with header and query-string redaction. The `autoLogging.ignore` option maps to `skip`. See [HTTP request logging](/guide/http-logging).

## How does request context map?

In `nestjs-pino`, request context is stored with `AsyncLocalStorage` by the HTTP middleware, so `PinoLogger` calls inside a request carry the request fields. In logixia, the module's trace middleware stores a trace ID (reusing `traceparent`, `x-request-id` and similar headers, generating one otherwise) in async context, and every log line inside the request carries it, including from services you never passed a logger to. It also echoes the ID as `X-Trace-Id`.

What you add:

- Extra per-request fields (user ID, tenant): call `LogixiaContext.set({ userId })` inside the request after authentication. See [child loggers and context](/guide/child-loggers-and-context).
- There is **no `req.log`**. Use the injected service; the trace ID is picked up from async context.
- `LogixiaExceptionFilter` can replace ad-hoc error logging; it returns a consistent JSON error body and logs with the trace ID, with sensitive query values redacted in logged URLs.

### What about queues, cron jobs and microservices?

Context outside HTTP is a known sore spot in `nestjs-pino` ([issue #803](https://github.com/iamolegga/nestjs-pino/issues/803)), and logixia is not automatic here either. The trace middleware is HTTP only. The Kafka and WebSocket interceptors continue an ID already present in the message but do not generate one, and they need `traceId` set in `forRoot()`. For cron and other consumers, wrap the handler in `runWithTraceId()` or `LogixiaContext.run()`. Details are in [the NestJS logger comparison](/articles/best-nestjs-logger#does-logixia-handle-context-in-queues-and-cron-jobs).

## How does redaction map?

`pinoHttp.redact` uses pino's path syntax and applies to the serialized `req`, `res` and your log objects. logixia's `redact` runs on the payload and message of every entry before any transport sees it:

```ts
import { LogixiaLoggerModule } from 'logixia/nest';

export const loggingModule = LogixiaLoggerModule.forRoot({
  appName: 'orders-api',
  redact: {
    paths: ['**.password', 'user.creditCard'],
    patterns: [/Bearer\s+\S+/gi],
    autoDetect: 'conservative',
  },
});
```

Notes: there is no `remove: true` (values are replaced, default `[REDACTED]`); wildcard rules use `*` for one segment and `**` for any depth; header and query redaction for logged requests comes from the HTTP middleware's own lists. Test your rules against real payloads, and see [redaction](/guide/redaction).

## What do you lose by switching?

- **pino's speed on simple logs** and its transport ecosystem; see the [benchmarks](/guide/benchmarks).
- **A large, tested community.** `nestjs-pino` has about 4.3M weekly downloads (2026-11-14); logixia has roughly a hundred.
- **`pino-pretty` options.** The built-in text output has no equivalent set of knobs.
- **Automatic `pino-http` request logging.** You add it yourself, as above.

## A safe migration plan

1. Register `LogixiaLoggerModule.forRoot(...)` next to `LoggerModule`; you can run both briefly.
2. Convert one service to `LogixiaLoggerService`, swap argument order and compare output.
3. Switch `app.useLogger(...)` and add the HTTP middleware.
4. Update dashboards for `message`, string levels and ISO `timestamp`.
5. Convert the rest, then remove `nestjs-pino`, `pino-http` and `pino`.

## Key takeaways

- `LoggerModule.forRoot({ pinoHttp })` becomes `LogixiaLoggerModule.forRoot(config)`; `PinoLogger` becomes `LogixiaLoggerService`.
- Message first, data second; `await` the calls.
- Add `createExpressMiddleware` to get per-request completion lines.
- Non-HTTP context needs `runWithTraceId()` or `LogixiaContext.run()`.

## FAQ

**What is a good nestjs-pino alternative?** `nest-winston`, the built-in `ConsoleLogger` for simple apps, or logixia if you want tracing, redaction and transports built in. See [the comparison](/articles/best-nestjs-logger).

**Can I use nestjs-pino and logixia together?** Yes while migrating: register both modules and convert services one at a time.

**Does logixia log every request automatically in NestJS?** Not by itself. Add `createExpressMiddleware` from `logixia/middleware`, as shown above.

**How do I replace `@InjectPinoLogger`?** Inject `LogixiaLoggerService` and call `setContext()`, or use `forFeature('Name')` with `@Inject('LOGIXIA_LOGGER_NAME')`.

**Does logixia work with the Fastify adapter?** logixia has a Fastify plugin (`createFastifyPlugin`) and the trace middleware tolerates Fastify-style responses, but the NestJS examples here were written for the default Express adapter, so test your setup.
