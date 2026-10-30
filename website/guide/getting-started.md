---
title: Getting started
description: Install logixia, create a TypeScript logger, add file and console transports, attach request context and flush logs before your Node.js process exits.
order: 2
---

# Getting started

This page takes you from an empty project to a logger that writes to the console and a file, carries context, and flushes cleanly on shutdown.

## Install

::: code-group

```bash [npm]
npm install logixia
```

```bash [pnpm]
pnpm add logixia
```

```bash [yarn]
yarn add logixia
```

:::

logixia needs Node.js 16 or later and has three runtime dependencies (`commander`, `fast-json-stringify`, `picocolors`). Everything else is optional: NestJS (`@nestjs/common`, `reflect-metadata`) and Express are optional peer dependencies, only needed for [`logixia/nest`](/guide/nestjs). Database drivers are only needed for the [database transport](/guide/transports/database).

## Your first logger

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'my-service',
  environment: 'development',
});

await logger.info('Service started', { port: 3000 });
await logger.warn('Cache is cold', { keys: 0 });
await logger.error(new Error('Database connection lost'), { retryIn: 5000 });
```

Every method returns a `Promise<void>`. Passing an `Error` to `error()` logs its message and serializes the name, message, stack and `cause` chain under `error` in the payload.

With no `transports` option, logixia prints one text line per entry to stdout (`error` goes to stderr). The default level is `info`, so `debug` calls are dropped until you change the level; see [Log levels](/guide/log-levels).

## Add transports

Setting `transports` replaces the default output. Add `console` explicitly if you still want terminal output.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'my-service',
  environment: 'production',
  transports: {
    console: { format: 'json' },
    file: {
      filename: 'app.log',
      dirname: './logs',
      format: 'json',
      maxSize: '50MB',
      maxFiles: 5,
    },
  },
});

await logger.info('Order created', { orderId: 'ord_123', total: 49.9 });
await logger.close();
```

::: warning Transports replace the default output
If you set `transports` but leave out `console`, nothing is written to the terminal. See [Configuration](/guide/configuration) for how the two output paths differ.
:::

The [transports overview](/guide/transports/) lists everything available: file, database, CloudWatch, Google Cloud, Azure Monitor, Datadog, OTLP, analytics services, Slack, Discord and a worker-thread transport.

## Redact secrets

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'my-service',
  redact: {
    paths: ['req.headers.authorization', '*.password'],
    autoDetect: true,
  },
});

await logger.info('Login', { user: 'ada', password: 'hunter2' });
// payload.password is replaced with [REDACTED]
```

More in [Redaction](/guide/redaction).

## Add context

A child logger shares the parent's transports and adds a context label plus fields to every entry:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({ appName: 'my-service' });

const orders = logger.child('OrderService', { region: 'eu-west-1' });
await orders.info('Order created', { orderId: 'ord_123' });
```

For request-scoped context that follows async calls without passing a logger around, use `LogixiaContext` and trace IDs. See [Child loggers and context](/guide/child-loggers-and-context) and [Tracing](/guide/tracing).

## Flush before you exit

Batching transports (file, database, cloud) keep entries in memory briefly. Call `close()` when a script or test is done, or turn on graceful shutdown for long-running services:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'my-service',
  transports: { file: { filename: 'app.log', dirname: './logs' } },
  gracefulShutdown: { enabled: true, timeout: 5000 },
});

await logger.info('ready');
```

See [Graceful shutdown](/guide/graceful-shutdown).

::: tip TypeScript and `flush()`
The value returned by `createLogger()` is typed as the logger interface, which has `close()` but not `flush()`, `healthCheck()` or `setNamespaceLevels()`. Those exist at runtime on the `LogixiaLogger` class. If you need them, create the logger with `new LogixiaLogger(config)` instead. The class also adds custom level methods at runtime, but only `createLogger()` types them.
:::

## Next steps

- [Configuration](/guide/configuration) for every option
- [HTTP logging](/guide/http-logging) or [NestJS](/guide/nestjs) to wire logging into a web framework
- [Testing](/guide/testing) to assert on logs without a real transport
