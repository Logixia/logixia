---
title: 'NestJS Logging with Request Tracing and Trace IDs'
description: 'Add structured JSON logging and a trace ID to every request in NestJS with logixia - module setup, header propagation, error logging via an exception filter.'
date: 2026-10-30
tags: [nestjs, tracing, structured-logging, request-id, nodejs]
---

# NestJS Logging with Request Tracing and Trace IDs

**TL;DR:** For NestJS logging with request tracing, you want three things: JSON log lines, a unique trace ID attached to every line a request produces, and that same ID returned to the caller and forwarded to downstream services. With logixia you register `LogixiaLoggerModule.forRoot(...)` from `logixia/nest`, inject `LogixiaLoggerService`, and add `LogixiaExceptionFilter` so unhandled errors are logged with the trace ID. This article explains the concepts, then walks through a complete setup that was run against Nest 11.

When a user reports "my order failed at 14:03", you need to find every log line from that one request across your controller, services and the exception handler. Without a shared identifier you are left matching timestamps. With one, it is a single search.

## What is request tracing in a NestJS app?

A **trace ID** (also called a request ID or correlation ID) is a unique string assigned when a request enters your system. Every log line written while handling that request includes it. If your service calls another service, you pass the same ID along in a header, so one search spans all of them.

The hard part in Node is carrying the ID to every log call without passing it through every function argument. Node solves this with `AsyncLocalStorage`: a store bound to the current asynchronous call chain. A middleware puts the ID in the store at the start of the request, and anything that runs afterwards, including awaited promises and `Promise.all`, can read it. Logging libraries read it for you.

Two standards matter. The W3C **`traceparent`** header (`00-<32 hex trace id>-<16 hex span id>-<flags>`) is what OpenTelemetry and most modern gateways propagate. Many systems also use plain `x-request-id` or `x-correlation-id`. A good setup accepts an incoming ID when one is present, generates a UUID when not, and echoes the result in a response header.

## How do I set up logixia in NestJS?

Install the package. NestJS integration lives in its own entry point since v2, so import from `logixia/nest` (not from `logixia`):

```bash
npm install logixia
```

Register the module in your root module. `forRoot` makes the logger global, so you do not import it in feature modules:

```ts
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia/nest';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'orders-api',
      environment: 'production',
      traceId: true,
      transports: { console: { format: 'json', colorize: false } },
    }),
  ],
})
export class AppModule {}
```

Registering the module also installs `TraceMiddleware` for all routes. For every request it:

1. Looks for an incoming ID in these headers, in order: `traceparent` (parsed down to its 32-hex trace ID), `x-trace-id`, `x-request-id`, `x-correlation-id`, `trace-id`; then in the query parameters `traceId` and `trace_id`.
2. Validates it: 1 to 128 characters from `A-Z a-z 0-9 . _ : -`. Anything else is ignored, so a client cannot inject newlines or huge strings into your logs.
3. Generates a UUID v4 if nothing usable was found.
4. Sets `req.traceId`, writes the ID to the `X-Trace-Id` response header, and runs the rest of the request inside the async context.

Note the `transports` line: when you pass a `transports` object, logixia creates only the destinations you list, so always include `console` explicitly or you will see no console output.

Now wire the logger into Nest itself in `main.ts`, so framework messages go through logixia too:

```ts
import { NestFactory } from '@nestjs/core';
import { LogixiaLoggerService } from 'logixia/nest';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(LogixiaLoggerService));
  await app.listen(3000);
}

void bootstrap();
```

## How do I log with the trace ID in a service?

Inject `LogixiaLoggerService` with normal constructor injection. You do not pass the trace ID anywhere; the logger reads it from the async context on every call. Create a child logger so each class is identifiable by name:

```ts
import { Controller, Get, Injectable, Param } from '@nestjs/common';
import { getCurrentTraceId } from 'logixia';
import { LogixiaLoggerService } from 'logixia/nest';

@Injectable()
export class OrdersService {
  private readonly logger: LogixiaLoggerService;

  constructor(logger: LogixiaLoggerService) {
    this.logger = logger.child('OrdersService');
  }

  async find(id: string) {
    await this.logger.info('looking up order', { orderId: id });
    // forward the same ID to downstream services
    const headers = { 'x-request-id': getCurrentTraceId() ?? '' };
    return { id, forwardedAs: headers['x-request-id'] };
  }
}

@Controller('orders')
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @Get(':id')
  get(@Param('id') id: string) {
    return this.orders.find(id);
  }
}
```

Calling `GET /orders/1` with a `traceparent` header produced this line (trimmed):

```json
{
  "level": "info",
  "message": "looking up order",
  "context": "OrdersService",
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "appName": "orders-api",
  "environment": "production",
  "orderId": "1"
}
```

The trace ID is the 32-hex part of the incoming `traceparent`, so these logs join up with OpenTelemetry traces from the same request (see [OpenTelemetry logs in Node.js](/articles/opentelemetry-logs-nodejs)). Without a header, the same call gets a fresh UUID.

`getCurrentTraceId()` is the building block for propagation: put it in the `x-request-id` (or `traceparent`-compatible) header of outbound HTTP calls and queue messages, and the downstream service will log under the same ID.

### Why use `child()` instead of a shared logger?

Because of the `context` field. With `app.useLogger(...)`, Nest's own internals set a context such as `NestApplication` on the logger they hold, and an injected logger without its own context can show that stale name in your logs. A child logger pins an explicit `context` to every line. In a quick test, a service that injected the logger directly logged with `context: "NestApplication"` after `useLogger` was called, while the child-logger version logged `OrdersService`. Make `child(ClassName)` a habit.

## How do I customize the trace ID?

`traceId` accepts a config object. You can choose which headers to read, rename the response header, and change the generator:

```ts
import { randomUUID } from 'node:crypto';
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia/nest';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'orders-api',
      traceId: {
        enabled: true,
        responseHeader: 'X-Request-Id',
        extractor: { header: ['traceparent', 'x-request-id'] },
        generator: () => `req_${randomUUID()}`,
      },
      transports: { console: { format: 'json', colorize: false } },
    }),
  ],
})
export class AppModule {}
```

`responseHeader` can also be `false` to stop echoing the ID. Supplying `extractor.header` replaces the default header list rather than adding to it, which is useful when you only trust a gateway header. In the run above, a request with `x-request-id: abc-123` was logged under `abc-123` and echoed back as `X-Request-Id: abc-123`.

For configuration that comes from `ConfigService`, use `forRootAsync({ imports, inject, useFactory })`. Full option details are in the [NestJS guide](/guide/nestjs) and the [tracing guide](/guide/tracing).

## How do I log unhandled exceptions with the trace ID?

Register `LogixiaExceptionFilter`. It catches everything, logs it with request method, URL, status and trace ID, and returns a consistent JSON error body that includes the trace ID, so a user can quote it to support. The DI-friendly way is the `APP_FILTER` token:

```ts
import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { LogixiaExceptionFilter, LogixiaLoggerModule } from 'logixia/nest';

@Module({
  imports: [LogixiaLoggerModule.forRoot({ appName: 'orders-api', traceId: true })],
  providers: [{ provide: APP_FILTER, useClass: LogixiaExceptionFilter }],
})
export class AppModule {}
```

(Or, in `main.ts`: `app.useGlobalFilters(new LogixiaExceptionFilter(logger))`.) It handles three kinds of exception: a `LogixiaException`, a Nest `HttpException`, and anything else, which becomes a 500. Server errors (5xx) are logged at `error` with the stack trace; client errors are logged at `warn`. Here is a typed exception and the response it produced:

```ts
import { Injectable } from '@nestjs/common';
import { LogixiaException } from 'logixia';

@Injectable()
export class OrdersLookup {
  find(id: string) {
    if (id === '0') {
      throw new LogixiaException({
        code: 'ORD-404',
        type: 'not_found_error',
        httpStatus: 404,
        message: 'Order not found.',
        metadata: { orderId: id }, // for logging only, never sent to the client
      });
    }
    return { id };
  }
}
```

```json
{
  "success": false,
  "error": { "type": "not_found_error", "code": "ORD-404", "message": "Order not found." },
  "meta": {
    "trace_id": "d3808565-c524-4825-a8e6-11b343646e7a",
    "timestamp": "2026-10-30T14:35:14.670Z",
    "path": "/orders/0",
    "status": 404
  }
}
```

An unexpected `Error('database exploded')` produced a generic `"An unexpected error occurred."` body with the same `meta.trace_id`, while the server-side log carried the real message and stack. Stack traces and causes are only added to responses if you opt in with `exposeDebug` (and `exposeCause`); keep those off in production.

Two quirks worth knowing: the filter's own log line may show a stale `context` such as `NestApplication` (same cause as above), and its trace ID falls back to the `x-trace-id` header or `request.id` only when no async context exists.

## What are the common pitfalls?

- **Importing from the wrong entry.** In v2, `LogixiaLoggerModule`, `LogixiaLoggerService`, `TraceMiddleware`, `LogixiaExceptionFilter`, `InjectLogger` and `LogMethod` come from `logixia/nest`. The migration notes are in the [v2 migration guide](/guide/migration-v2).
- **`@InjectLogger()` needs a provider.** The decorator injects the token `LOGIXIA_LOGGER_SERVICE`, which `forRoot` does not register; in testing, using it with only `forRoot` fails at startup with "Nest can't resolve dependencies". It resolves once you also import `LogixiaLoggerModule.forFeature('service')`, which additionally gives you a logger whose context is `service`. Plain constructor injection of `LogixiaLoggerService` always works, so prefer it unless you want the decorator.
- **No console output.** A `transports` object without `console` creates no console transport.
- **Trusting client IDs blindly.** Incoming IDs are sanitized, but a client can still choose its own trace ID. That is fine for correlation, not for authentication or security decisions.
- **Redaction.** Request metadata and bodies often hold secrets; see [redacting sensitive data](/articles/redact-sensitive-data-in-nodejs-logs).
- **Not awaiting.** Logger methods return promises. In handlers, `await` them; in decorators and filters logixia attaches its own catch.

## Key takeaways

- One trace ID per request, carried by `AsyncLocalStorage`, read automatically by the logger.
- Import NestJS pieces from `logixia/nest`; use constructor injection plus `child(ClassName)`.
- Incoming `traceparent` / `x-request-id` headers are honored and sanitized; the ID is echoed in `X-Trace-Id` (configurable).
- `LogixiaExceptionFilter` logs errors with the trace ID and returns it in the response body.

## FAQ

**How do I add a request ID to NestJS logs?** Register `LogixiaLoggerModule.forRoot({ traceId: true })` from `logixia/nest`. A middleware assigns an ID per request (or reuses `x-request-id` / `traceparent`), and every logixia log line includes it automatically.

**How do I pass the trace ID to other services?** Call `getCurrentTraceId()` (exported from `logixia`) and send it in the `x-request-id` header on outbound calls.

**Can I use logixia as the NestJS app logger?** Yes. `app.useLogger(app.get(LogixiaLoggerService))` routes Nest's framework logs through it as well.

**Does this work with Fastify instead of Express?** The middleware tolerates Fastify-style responses when setting the header, and logixia also has a Fastify plugin; the end-to-end examples in this article were run on the default Express adapter.
