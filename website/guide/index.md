---
title: Introduction
description: logixia is an async-first TypeScript logger for Node.js with trace IDs, redaction, sampling, NestJS support and transports for files, databases and clouds.
order: 1
---

# Introduction

logixia is a TypeScript logging library for Node.js. It gives you structured logs with a small API, and it adds the things production services usually bolt on later: request trace IDs, secret redaction, sampling, graceful shutdown and a set of transports for files, databases, cloud log services and chat webhooks.

Every log method returns a `Promise`, so a slow transport never blocks your code unless you choose to `await` it. The package ships ESM and CommonJS builds with type declarations, has three runtime dependencies, and runs on Node.js 16 and later.

## When to use it

logixia is a good fit when you:

- run an HTTP service (Express, Fastify, NestJS) and want every log line tied to a request trace ID without passing the ID around by hand;
- need to keep passwords, tokens and PII out of logs by configuration instead of by discipline;
- ship logs to more than one place (console plus a file plus a cloud service) and want retries, batching and bounded buffers handled for you;
- want typed custom levels, typed log fields and a mock logger for tests.

It is probably not the right tool if you need a logger that runs unchanged in every browser and edge runtime with the full feature set. The `logixia/browser` entry point covers those environments with a smaller logger; see [Browser and edge](/guide/browser-and-edge).

## A first look

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  redact: { autoDetect: true },
});

await logger.info('Server started', { port: 3000 });
await logger.error(new Error('Payment gateway timed out'), { orderId: 'ord_123' });
```

Head to [Getting started](/guide/getting-started) for installation and a runnable setup.

## Feature map

| Area             | What you get                                                                | Read                                                                                                                |
| ---------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Setup            | Install, first logger, transports                                           | [Getting started](/guide/getting-started)                                                                           |
| Options          | Every `LoggerConfig` option and its default                                 | [Configuration](/guide/configuration)                                                                               |
| Levels           | Built-in and custom levels, runtime changes, per-namespace levels           | [Log levels](/guide/log-levels)                                                                                     |
| Context          | Child loggers and fields that follow a request                              | [Child loggers and context](/guide/child-loggers-and-context)                                                       |
| Tracing          | Trace IDs, `traceparent`, correlation IDs across services                   | [Tracing](/guide/tracing)                                                                                           |
| HTTP             | Express middleware and Fastify plugin that replace Morgan                   | [HTTP logging](/guide/http-logging)                                                                                 |
| NestJS           | Module, service, exception filter, decorators, interceptors                 | [NestJS](/guide/nestjs)                                                                                             |
| Safety           | Path and pattern redaction, auto-detection of secrets                       | [Redaction](/guide/redaction)                                                                                       |
| Volume           | Rate, per-level, trace-consistent and adaptive sampling                     | [Sampling](/guide/sampling)                                                                                         |
| Observability    | Prometheus metrics from logs, OpenTelemetry bridge, wide events             | [Metrics](/guide/metrics), [OpenTelemetry](/guide/opentelemetry), [Wide events](/guide/wide-events)                 |
| Delivery         | Console, file, database, cloud, analytics, Slack and Discord, worker thread | [Transports](/guide/transports/)                                                                                    |
| Lifecycle        | Flush on SIGTERM and SIGINT                                                 | [Graceful shutdown](/guide/graceful-shutdown)                                                                       |
| Types            | Typed log fields and schemas                                                | [Typed logger](/guide/typed-logger)                                                                                 |
| Extension        | Plugins and custom transports                                               | [Plugins](/guide/plugins), [Custom transport](/guide/transports/custom)                                             |
| Browser and edge | Small browser-safe logger with a remote batch transport                     | [Browser and edge](/guide/browser-and-edge)                                                                         |
| Analysis         | In-memory log search and the `logixia` command line tool                    | [Log search](/guide/log-search), [CLI](/guide/cli)                                                                  |
| Testing          | Mock logger with assertions                                                 | [Testing](/guide/testing)                                                                                           |
| Reference        | Security notes, upgrade guide, FAQ, export lists                            | [Security](/guide/security), [Migrating to 2.0](/guide/migration-v2), [FAQ](/guide/faq), [API overview](/guide/api) |

## Entry points

logixia exposes several import paths so you only load what you use. The main ones are `logixia` (logger, context, redaction, sampling, metrics), `logixia/nest`, `logixia/middleware`, `logixia/correlation`, `logixia/transports`, `logixia/browser`, `logixia/search` and `logixia/testing`. The [API overview](/guide/api) lists everything each one exports.
