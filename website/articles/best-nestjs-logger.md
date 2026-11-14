---
title: 'Best NestJS Logger: nestjs-pino vs nest-winston vs the built-in Logger vs logixia'
description: 'Compare the NestJS built-in Logger, nestjs-pino, nest-winston and logixia: request context, redaction, transports, known pain points and which to choose.'
date: 2026-11-14
tags: [nestjs, comparison, logging, nestjs-pino, nodejs]
---

# Best NestJS Logger: nestjs-pino vs nest-winston vs the built-in Logger vs logixia

**TL;DR:** Start with Nest's **built-in `ConsoleLogger`** for small apps (it can emit JSON with `json: true`). For production services, **`nestjs-pino`** is the default community choice: pino speed, `pino-http` request logs and the largest user base. **`nest-winston`** fits teams already invested in winston transports and formats. **logixia** is an integrated alternative with a request trace ID, redaction, an exception filter and many transports in one package, but it is young and small. I maintain logixia, so read that part with that in mind; I have only claimed behavior I checked in the code, and I say where logixia does not do something.

## What does Nest's built-in Logger give you?

Nest ships a `ConsoleLogger`, and `Logger` is its injectable facade. You can pass `logger: ['error', 'warn']` to limit levels, set `json: true` for JSON output, set `timestamp`, and replace it with your own `LoggerService`. For structured output and simple setups this may be all you need.

What it does not do is documented by Nest itself: for [transports and redaction](https://docs.nestjs.com/techniques/logger) the docs point you to libraries such as pino or winston. There is no request-scoped correlation ID, no field redaction and no way to ship logs to a destination.

**Choose it when:** the service is small, stdout is collected by your platform, and you do not need correlation IDs.

## Why is nestjs-pino the default choice?

[`nestjs-pino`](https://github.com/iamolegga/nestjs-pino) wraps pino and `pino-http`. You get one request-completion log per request, a request-scoped child logger, and pino's `redact`, `pino-pretty` for development and the whole pino transport ecosystem. It has about 4.3M weekly downloads (npm, 2026-11-14), which means most NestJS problems have already been reported and answered.

Strengths:

- pino's low per-call overhead and JSON output;
- `pino-http` request logging with customizable serializers and `redact`;
- `AsyncLocalStorage`-based `PinoLogger` injection;
- a very large community.

### What are the known pain points?

None of these make it a bad choice, but they are worth knowing, and each is linked so you can judge it yourself:

- **Major-version lag.** Fixes were needed for [pino 10](https://github.com/iamolegga/nestjs-pino/issues/2623) and for [pino-http 11](https://github.com/iamolegga/nestjs-pino/issues/2649). With a wrapper around two libraries you depend on three release schedules.
- **Context outside HTTP.** Request context is created by the HTTP middleware, so logs from queues, cron jobs and microservice handlers do not get a request-scoped context automatically. The long-running thread is [#803](https://github.com/iamolegga/nestjs-pino/issues/803) (38 reactions at the time of writing); the usual workaround is to set up context around those handlers yourself.
- **Fastify adapter context.** There is an [open report](https://github.com/iamolegga/nestjs-pino/issues/546) about request context with `FastifyAdapter`.

If you hit these, you can usually work around them, which is part of why it stays the default.

**Choose it when:** you want pino's performance and ecosystem and are fine assembling correlation outside HTTP.

## What about nest-winston?

[`nest-winston`](https://github.com/gremo/nest-winston) wires a winston logger into Nest as the app logger and an injectable service. You inherit winston's flexibility (the `format` pipeline, a huge list of community transports) and its costs (more configuration, lower throughput than pino in most benchmarks, see [our benchmark page](/guide/benchmarks)). It does not create a per-request context for you; you add that with your own middleware.

**Choose it when:** you already run winston transports in other services, or you need one that only exists for winston.

## What does logixia's NestJS module provide?

`LogixiaLoggerModule` from `logixia/nest` is a global module. The details below come from the [NestJS guide](/guide/nestjs) and the source.

```ts
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia/nest';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'orders-api',
      environment: 'production',
      traceId: true,
      redact: { autoDetect: true },
      transports: { console: { format: 'json', colorize: false } },
    }),
  ],
})
export class AppModule {}
```

What you get:

- **`LogixiaLoggerService`**, injectable and implementing Nest's `LoggerService`, so `app.useLogger(app.get(LogixiaLoggerService))` routes Nest's own logs through it.
- **A trace middleware** applied to routes that reads an incoming `traceparent`, `x-request-id` and similar headers (validated), or generates an ID, echoes it as `X-Trace-Id` and runs the request in an async scope. Every log line inside the request carries the ID without passing a logger around.
- **`LogixiaExceptionFilter`**, which returns a consistent JSON error body and logs with the trace ID, with sensitive query-string values redacted in logged URLs.
- **`@LogMethod()`** to log entry, exit, duration and errors of a method (arguments are not logged unless you opt in).
- **`KafkaTraceInterceptor` and `WebSocketTraceInterceptor`** to continue a trace in message handlers.
- **Redaction, sampling and the transport set** from core logixia: [redaction](/guide/redaction), [sampling](/guide/sampling), [transports](/guide/transports/).

### Does logixia handle context in queues and cron jobs?

Partly, and not automatically. Here is exactly what the code does:

- The trace middleware covers HTTP routes only.
- The Kafka and WebSocket interceptors continue an ID that is already in the message (body or headers). They do **not** generate one: with no ID found, the handler runs untraced. They need `traceId` set in `forRoot()`; otherwise they are created disabled.
- For cron jobs and other queue consumers (Bull, SQS and similar), there is no interceptor. You wrap the handler yourself with `runWithTraceId()` or `LogixiaContext.run()` (see [tracing](/guide/tracing)); the `logixia/correlation` helpers cover extracting an ID from a message.
- Outside any scope, each entry still gets a `traceId`, but it is a UUID generated once per logger instance, not one per job.

So the gap `nestjs-pino` users report for non-HTTP contexts exists in a different shape here: logixia gives you primitives and two interceptors rather than a fully automatic answer. I have not tested logixia with Bull or `@nestjs/schedule` in this article, only checked what the code provides.

```ts
import { Injectable } from '@nestjs/common';
import { generateTraceId, runWithTraceId } from 'logixia';
import { LogixiaLoggerService } from 'logixia/nest';

@Injectable()
export class NightlyJob {
  constructor(private readonly logger: LogixiaLoggerService) {}

  async run(): Promise<void> {
    await runWithTraceId(generateTraceId(), async () => {
      await this.logger.info('nightly job started');
    });
  }
}
```

### What are logixia's drawbacks on NestJS?

- **Young project, tiny community.** About a hundred weekly downloads. You will find fewer blog posts, answers and integrations than for nestjs-pino.
- **Slower on simple log calls than pino**, though it is faster on some structured payloads in our [benchmark](/guide/benchmarks).
- **Methods return promises**, unlike Nest's `Logger`. Await them in handlers, or accept that you are not waiting for transports.
- **`@InjectLogger()` needs a feature import.** `forRoot()` alone does not register its token; inject `LogixiaLoggerService` by class, or add `LogixiaLoggerModule.forFeature(...)`. See the [guide](/guide/nestjs).

**Choose it when:** you want tracing, redaction and several destinations in one package and can accept the maturity trade-off. Coming from nestjs-pino? See the [migration guide](/articles/migrate-from-nestjs-pino-to-logixia).

## Which NestJS logger should you choose?

| Situation                                                    | Pick                                                  |
| ------------------------------------------------------------ | ----------------------------------------------------- |
| Small service, platform collects stdout                      | Built-in `ConsoleLogger`                              |
| Production API, want the community default and pino speed    | `nestjs-pino`                                         |
| Already standardized on winston transports                   | `nest-winston`                                        |
| Want trace IDs, redaction and transports with one dependency | logixia                                               |
| Heavy non-HTTP work (queues, cron) and a zero-config answer  | None is fully automatic; budget for wrapping handlers |

For the tracing setup in detail, see [NestJS logging with request tracing](/articles/nestjs-logging-with-request-tracing). For the wider field, see [the best Node.js logging libraries](/articles/best-nodejs-logging-libraries).

## Key takeaways

- The built-in logger has `json: true` but defers transports and redaction to pino or winston.
- `nestjs-pino` is the default; know its pino 10 and pino-http 11 upgrade issues and its non-HTTP context gap.
- `nest-winston` is for winston loyalists.
- logixia bundles tracing, redaction and transports; its non-HTTP context support is primitives plus Kafka and WebSocket interceptors, not automatic.

## FAQ

**What is the best logger for NestJS?** For most production apps `nestjs-pino`, because of pino's speed and its large community. Use the built-in logger for small apps, and consider logixia if you want built-in tracing, redaction and transports and accept a young project.

**Does the built-in NestJS logger support JSON?** Yes, `ConsoleLogger` accepts `json: true`. For transports and redaction, Nest's docs point to pino or winston.

**Does nestjs-pino support pino 10?** Fixes were needed for it (see the [issue](https://github.com/iamolegga/nestjs-pino/issues/2623)); check the nestjs-pino release notes against your pino version before upgrading.

**How do I add a request ID to NestJS logs?** With `nestjs-pino` it comes from `pino-http`'s request ID; with logixia, register `LogixiaLoggerModule.forRoot({ traceId: true })`. See [request tracing](/articles/nestjs-logging-with-request-tracing).

**Does logixia propagate context to cron jobs and queues?** Not automatically. You wrap handlers in `runWithTraceId()` or `LogixiaContext.run()`; the Kafka and WebSocket interceptors continue an ID already present in the message.

**Can I use logixia as the NestJS app logger?** Yes: `app.useLogger(app.get(LogixiaLoggerService))`.
