---
title: 'Migrate from Winston to logixia: A Practical Mapping Guide'
description: 'Move a Node.js app from winston to logixia step by step: levels, transports, formats and child loggers with before and after code, plus the gaps.'
date: 2026-10-27
tags: [winston, migration, logging, nodejs, typescript]
---

# Migrate from Winston to logixia: A Practical Mapping Guide

**TL;DR:** To migrate from winston to logixia, map four things: the **level** table (winston's `silly` and `http` become custom levels), **transports** (a transports array becomes a transports object), **formats** (winston's format pipeline becomes a JSON-or-text switch plus optional plugins), and **child loggers** (`child({ meta })` becomes `child('context', { meta })`). The calls themselves look almost the same, except that logixia's methods return promises. This guide shows each mapping with before and after code, and lists what winston does that logixia does not.

Winston is mature and flexible, and there is no need to migrate if it works for you; [the comparison article](/articles/pino-vs-winston-vs-logixia) discusses when each makes sense. If you have decided to move, for tracing, redaction or built-in transports, do it incrementally: the two libraries can run side by side while you convert module by module.

## What does a typical winston setup look like?

This is a common production configuration, and the baseline for the rest of the article:

```ts
import winston from 'winston';

export const logger = winston.createLogger({
  level: 'info',
  levels: winston.config.npm.levels,
  defaultMeta: { service: 'billing' },
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 5_242_880,
      maxFiles: 5,
    }),
  ],
});

logger.info('user signed in', { userId: 42 });
logger.error('charge failed', { orderId: 'o_1' });
logger.log('http', 'GET /health', { status: 200 });

export const requestLogger = logger.child({ requestId: 'r-1' });
requestLogger.warn('slow query', { ms: 840 });
```

## How do I set up the equivalent in logixia?

The same logger in logixia:

```ts
import { createLogger } from 'logixia';

export const logger = createLogger({
  appName: 'billing',
  environment: 'production',
  levelOptions: {
    level: 'info',
    levels: { error: 0, warn: 1, info: 2, http: 3, verbose: 4, debug: 5, silly: 6 },
  },
  transports: {
    console: { format: 'json', colorize: false },
    file: [
      {
        filename: 'error.log',
        dirname: 'logs',
        level: 'error',
        format: 'json',
        maxSize: '5MB',
        maxFiles: 5,
      },
    ],
  },
});

await logger.info('user signed in', { userId: 42 });
await logger.error('charge failed', { orderId: 'o_1' });
await logger.http('GET /health', { status: 200 });

export const requestLogger = logger.child('request', { requestId: 'r-1' });
await requestLogger.warn('slow query', { ms: 840 });
```

The rest of this article explains each line.

## How do winston levels map to logixia levels?

Both libraries use "lower number is more severe", so the npm-style table carries over directly. Winston's default levels are `error 0, warn 1, info 2, http 3, verbose 4, debug 5, silly 6`. logixia's built-in levels are `error, warn, info, debug, trace, verbose`, and you can define your own with `levelOptions.levels`. A custom level becomes a typed method on the logger (`logger.http(...)`), as in the example above.

| winston                    | logixia                                                                         |
| -------------------------- | ------------------------------------------------------------------------------- |
| `level: 'info'`            | `levelOptions: { level: 'info' }`                                               |
| `levels: { ... }` (custom) | `levelOptions: { levels: { ... } }`                                             |
| `logger.log('http', msg)`  | `logger.logLevel('http', msg)` or `logger.http(msg)` with a custom `http` level |
| `silly`                    | custom level, or use `trace` / `verbose`                                        |
| `logger.level = 'debug'`   | `logger.setLevel('debug')`                                                      |

Two behaviors to know before you deploy:

- If the environment variable `LOGIXIA_LEVEL` is set to a known level, it **overrides** the configured level.
- If you do not set a level, logixia picks one from `NODE_ENV`: `debug` for `development`, `warn` for `test`, `info` for `production`. In particular, a test run with `NODE_ENV=test` will hide your `info` logs unless you set a level.

## How do winston transports map to logixia transports?

Winston takes an **array** of transport instances. logixia takes a `transports` **object** with named slots:

| winston                                                                      | logixia                                                                                                            |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `new transports.Console()`                                                   | `transports: { console: { ... } }`                                                                                 |
| `new transports.File({ filename, level, maxsize, maxFiles, zippedArchive })` | `transports: { file: { filename, dirname, level, maxSize, maxFiles, zippedArchive } }` (single object or an array) |
| `new transports.Http(...)`                                                   | a custom transport, or one of the vendor transports                                                                |
| Community transports (Datadog, CloudWatch, Slack...)                         | built-in `logixia/transports` classes, passed in `transports.custom`                                               |
| Your own `Transport` subclass                                                | an object with `name` and `write(entry)`, passed in `transports.custom`                                            |

Key differences:

- **Console is opt-in.** In winston you add a Console transport to get console output. In logixia the same is true once you pass a `transports` object: only the destinations you list exist, so include `console` or you will see nothing.
- **File rotation is built in.** `maxSize` accepts bytes or strings like `'50MB'`; `maxFiles`, `datePattern` and `zippedArchive` cover the rest of the usual `winston-daily-rotate-file` use. New log files get restrictive permissions (`0o600`) by default.
- **Per-transport level** works as in winston: set `level` on the transport config.
- **Custom transport:** implement the small interface.

```ts
import { createLogger } from 'logixia';

const queueTransport = {
  name: 'queue',
  level: 'warn',
  // entry has: timestamp (Date), level, message, data, context, traceId, appName, environment
  write(entry: { level: string; message: string; data?: Record<string, unknown> }) {
    process.stdout.write(`${entry.level}:${entry.message}\n`);
  },
};

export const logger = createLogger({
  appName: 'billing',
  transports: { console: { format: 'json', colorize: false }, custom: [queueTransport] },
});
```

Vendor destinations are covered in [shipping logs to Datadog and CloudWatch](/articles/ship-node-logs-to-datadog-and-cloudwatch), [OTLP export](/articles/opentelemetry-logs-nodejs) and the [transports guide](/guide/transports/).

## How do winston formats map to logixia?

This is the biggest conceptual difference. Winston gives you a composable `format` pipeline. logixia does not have an equivalent pipeline; it has a smaller set of controls:

| winston                               | logixia                                                                                 |
| ------------------------------------- | --------------------------------------------------------------------------------------- |
| `format.json()`                       | `transports.console.format: 'json'` (fields flattened to the top level)                 |
| `format.timestamp()`                  | JSON entries always carry an ISO timestamp                                              |
| `format.errors({ stack: true })`      | `logger.error(err)` serializes name, message and stack                                  |
| `format.colorize()`                   | `colorize: true` on the console transport                                               |
| `format.printf(...)` / custom shaping | a plugin with an `onLog(entry)` hook, or a custom transport that formats entries itself |
| `defaultMeta`                         | a child logger with bound data, or `appName` and `environment` for the common cases     |
| `format.splat()` (`%s` interpolation) | not supported: use template literals and structured fields                              |

If you relied on `printf` to produce a bespoke text line, a plugin is the closest match. It receives the entry after redaction and before transports, and can modify it or return `null` to drop it:

```ts
import { createLogger } from 'logixia';
import type { LogixiaPlugin } from 'logixia';

const logger = createLogger({
  appName: 'billing',
  transports: { console: { format: 'json', colorize: false } },
});

const addRegion: LogixiaPlugin = {
  name: 'add-region',
  onLog(entry) {
    return { ...entry, payload: { region: 'eu-west-1', ...entry.payload } };
  },
};

logger.use(addRegion);

await logger.info('plugin applied');
```

## How do child loggers map?

Winston's `child(meta)` takes an object. logixia's takes a **context name** and optional data:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'billing',
  transports: { console: { format: 'json', colorize: false } },
});

const req = logger.child('request', { requestId: 'r-1' });
await req.info('started'); // includes context: "request" and requestId: "r-1"
```

If you used child loggers mainly to carry a request ID everywhere, logixia can do that without passing the child around, using async context. The Express version is in [request logging with a trace ID](/articles/express-request-logging-trace-id), and the NestJS version in [NestJS request tracing](/articles/nestjs-logging-with-request-tracing).

## What changes in everyday call sites?

- **Methods return promises.** `logger.info(...)` returns `Promise<void>`. In handlers and scripts, `await` them. A search-and-replace that adds `await` is usually enough.
- **Errors:** pass the `Error` as the first argument, `logger.error(err, { extra })`, rather than as metadata. The stack is serialized for you.
- **Metadata** is the second argument in both libraries, and in logixia it is merged at the top level of the JSON line. Field names that collide with core fields (`level`, `message`, `timestamp`, `traceId`, `appName`, `environment`, `context`) are kept under a `data_` prefix, so avoid them.
- **`logger.log(level, ...)`** becomes `logger.logLevel(level, ...)`.
- **Shutdown:** winston flushes on stream end. In logixia, call `await logger.close()` at exit or set `gracefulShutdown: true` so SIGTERM and SIGINT flush buffered transports.

## What does winston do that logixia does not?

Be aware of these before you commit:

- **No format pipeline.** There is no `combine`/`printf`; use plugins or custom transports.
- **No `exceptionHandlers` / `rejectionHandlers`.** logixia does not register `uncaughtException` or `unhandledRejection` handlers; add your own `process.on(...)` that logs and then exits.
- **Far fewer community transports.** Winston's ecosystem is much larger. logixia ships first-party transports for the common destinations and lets you write your own in a few lines.
- **Different semantics for `%s` splat interpolation**, as noted above.

What you gain: [redaction](/guide/redaction), [sampling](/guide/sampling), trace-ID propagation through async context, an HTTP logging middleware, and a [NestJS module](/guide/nestjs). The [v2 migration guide](/guide/migration-v2) is about upgrading logixia itself, not about winston.

## A safe migration plan

1. Add logixia next to winston and create one logger with the same level and transports.
2. Convert one module or service, adding `await`, and compare the output lines against the old ones.
3. Add redaction, and a trace-ID middleware if you want request correlation.
4. Convert the remaining modules, then remove winston and its transports.
5. Run your test suite with an explicit `levelOptions.level`, since `NODE_ENV=test` defaults to `warn`.

## Key takeaways

- Levels carry over (custom `http` and `silly` levels); transports become an object; child loggers take a context name.
- Include `console` explicitly, and remember `LOGIXIA_LEVEL` and `NODE_ENV` affect the level.
- Replace format pipelines with JSON mode, plugins or a custom transport; add your own process-level error handlers.
- Methods return promises: `await` them.

## FAQ

**Can I use winston and logixia together during migration?** Yes. They are independent libraries; run both and convert one module at a time.

**How do I replace `winston.format.printf`?** Use a plugin's `onLog` hook to reshape the entry, or write a custom transport that renders each entry as you like.

**Does logixia support daily rotating files like `winston-daily-rotate-file`?** Yes, the file transport supports `datePattern`, `maxSize`, `maxFiles` and `zippedArchive` without an extra package.

**Is logixia faster than winston?** In one micro-benchmark run it was faster in most scenarios, but results vary by machine and workload; see the [comparison](/articles/pino-vs-winston-vs-logixia) for the numbers and caveats.
