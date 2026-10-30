---
layout: home
title: 'Logixia: structured logging, request tracing and export for Node.js'
titleTemplate: false
description: 'Structured logging, request tracing and multi-destination export for Node.js, NestJS and the edge, in one TypeScript-first library.'

hero:
  name: Logixia
  text: Logging that follows the request
  tagline: Structured logging, request tracing and multi-destination export for Node.js, NestJS and the edge, in one TypeScript-first library.
  image:
    src: /logo.svg
    alt: Logixia logo
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: GitHub
      link: https://github.com/Logixia/logixia

features:
  - icon: 🧵
    title: Request trace IDs across async calls
    details: Express, Fastify and NestJS helpers scope a trace ID to each request, read W3C traceparent and x-trace-id, and attach it to every log line without passing it around.
  - icon: 🛡️
    title: Redaction built in
    details: Mask fields by path (with * and ** wildcards), by regex pattern, or with autoDetect for common secrets and PII. Error objects and cause chains are walked too.
  - icon: 📤
    title: Many destinations, one call
    details: Console, rotating files, Postgres, MySQL, MongoDB, SQLite, CloudWatch, GCP, Azure Monitor, Datadog, OTLP, Mixpanel, Segment, Google Analytics, Slack and Discord webhooks, plus a worker-thread transport.
  - icon: 🔭
    title: OpenTelemetry correlation
    details: Stamp log entries with the active trace and span, and export logs over OTLP with the OtlpLogTransport. No glue code between your logger and your collector.
  - icon: 🎚️
    title: Sampling and runtime levels
    details: Sample or rate-limit noisy logs, set levels per namespace (LOGIXIA_LEVEL_DB=debug), and change them at runtime through a signal or a tiny HTTP handler.
  - icon: 📈
    title: Prometheus metrics
    details: A metrics plugin turns log events into counters and histograms in the Prometheus text exposition format.
  - icon: 🚦
    title: Graceful shutdown
    details: flushOnExit drains buffered entries on SIGTERM and SIGINT, and leaves process exit to your own handlers when you have them.
  - icon: 🌐
    title: Browser and edge build
    details: logixia/browser has no Node globals and runs in browsers, Cloudflare Workers and other edge runtimes, with a batching remote transport.
  - icon: 🔎
    title: CLI and log search
    details: The logixia command can tail, query, analyze and export logs, and the logixia/search API lets you search them from code.
  - icon: 🧩
    title: Typed logger schemas
    details: defineLogSchema and createTypedLogger give you compile-time checked log events and fields.
  - icon: 🔐
    title: Supply-chain conscious
    details: Published with npm provenance, no install scripts, and three runtime dependencies.
  - icon: 🏗️
    title: NestJS first-class
    details: LogixiaLoggerModule.forRoot, an injectable service, an exception filter and a @LogMethod decorator, imported from logixia/nest.
---

## Quick start

```bash
npm install logixia
```

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  traceId: true,
  redact: { paths: ['**.password', '**.authorization'], autoDetect: true },
  transports: {
    console: { format: 'json' },
    file: { filename: 'app.log', dirname: './logs', maxSize: '50MB', maxFiles: 14 },
  },
});

await logger.info('Order created', { orderId: 'ord_42', password: 'hunter2' });
// password is written as "[REDACTED]", a traceId is attached,
// and the entry goes to the console and the rotating file.
```

Continue with the [getting started guide](/guide/getting-started).

## One library instead of five

A typical Node.js service assembles its logging from several packages. Logixia ships those pieces together and tested against each other, so there is less to wire up and keep in sync.

| You usually assemble                           | In Logixia                                         |
| ---------------------------------------------- | -------------------------------------------------- |
| A JSON logger                                  | `createLogger`, with text, JSON and CSV formats    |
| An HTTP request logger and trace-ID middleware | Express, Fastify and NestJS helpers, `traceparent` |
| Redaction configuration                        | `redact: { paths, patterns, autoDetect }`          |
| Log shippers for files, databases and clouds   | Built-in transports with batching and rotation     |
| OpenTelemetry glue code                        | Trace correlation and an OTLP log transport        |

You can still use Logixia next to other tools. It is one more option, not a requirement to replace anything.

## Works with your framework

::: code-group

<<< @/../examples/website/express.ts [Express]

<<< @/../examples/website/fastify.ts [Fastify]

<<< @/../examples/website/nestjs.ts [NestJS]

<<< @/../examples/website/cloudflare-worker.ts [Cloudflare Worker]

:::

<div class="home-cta">

## Ready to try it?

Install the package, add a logger, and ship logs where you need them.

[Read the guide](/guide/getting-started){.cta-primary}
[Browse articles](/articles/){.cta-secondary}

</div>
