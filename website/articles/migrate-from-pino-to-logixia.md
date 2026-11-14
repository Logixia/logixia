---
title: 'Migrate from pino to logixia: A Practical Mapping Guide and Honest Trade-offs'
description: 'Considering a pino alternative? Map pino levels, options, child loggers, redact, transports, pino-pretty and pino-http to logixia, and see what you give up.'
date: 2026-11-14
tags: [pino, migration, logging, nodejs, typescript]
---

# Migrate from pino to logixia: A Practical Mapping Guide and Honest Trade-offs

**TL;DR:** Moving from pino to logixia comes down to six mappings: **levels** (numeric `30` becomes the name `info`, and there is no built-in `fatal`), **options** (`pino({...})` becomes `createLogger({...})`), **argument order** (`logger.info(obj, msg)` becomes `logger.info(msg, obj)`), **child loggers** (`child({ bindings })` becomes `child('context', { bindings })`), **redaction** (`redact.paths` becomes `redact.paths`, with different wildcard syntax and no `remove`), and **transports** (pino's worker-thread transports become in-process transports). Logixia methods also return promises. Pino is faster on simple string logs and has a much larger ecosystem, so read the last section before you commit. I maintain logixia; there is no obligation to leave pino if it works for you.

If you are choosing rather than migrating, start with [the best Node.js logging libraries](/articles/best-nodejs-logging-libraries) or [pino vs winston vs logixia](/articles/pino-vs-winston-vs-logixia). If you decided to move, do it one module at a time: the two libraries can run side by side.

## What does a typical pino setup look like?

A common production configuration, and the baseline for this guide:

```ts
import pino from 'pino';

export const logger = pino({
  level: 'info',
  base: { service: 'billing' },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: { paths: ['req.headers.authorization', '*.password'], censor: '[Redacted]' },
});

logger.info({ userId: 42 }, 'user signed in');
logger.error({ err: new Error('card declined'), orderId: 'o_1' }, 'charge failed');

export const requestLogger = logger.child({ requestId: 'r-1' });
requestLogger.warn({ ms: 840 }, 'slow query');
```

## How do I set up the equivalent in logixia?

```ts
import { createLogger } from 'logixia';

export const logger = createLogger({
  appName: 'billing',
  environment: 'production',
  levelOptions: { level: 'info' },
  redact: { paths: ['req.headers.authorization', '*.password'], censor: '[Redacted]' },
  transports: { console: { format: 'json', colorize: false } },
});

await logger.info('user signed in', { userId: 42 });
await logger.error('charge failed', { err: new Error('card declined'), orderId: 'o_1' });

export const requestLogger = logger.child('request', { requestId: 'r-1' });
await requestLogger.warn('slow query', { ms: 840 });
```

The rest of the article explains each difference. The line shapes differ too:

| Field        | pino                               | logixia (JSON console transport)                    |
| ------------ | ---------------------------------- | --------------------------------------------------- |
| Level        | `"level": 30` (number)             | `"level": "info"` (name)                            |
| Time         | `"time": 1731585600000` (epoch ms) | `"timestamp": "2026-11-14T12:00:00.000Z"` (ISO)     |
| Message      | `"msg"`                            | `"message"`                                         |
| Process info | `pid` and `hostname` by default    | not added; `appName` and `environment` instead      |
| Trace ID     | not added                          | `traceId` on every entry (`traceId: false` to drop) |

If dashboards or alerts parse `msg`, `level` numbers or `time`, update them (or your log pipeline) as part of the migration. That is usually the largest hidden cost.

## How do pino levels map to logixia levels?

Pino numbers levels upward by severity (`trace` 10, `debug` 20, `info` 30, `warn` 40, `error` 50, `fatal` 60). logixia numbers them downward (`error` 0, `warn` 1, `info` 2, `debug` 3, `trace` 4, `verbose` 5) and stores names, not numbers, in the output.

| pino                                      | logixia                                                 |
| ----------------------------------------- | ------------------------------------------------------- |
| `level: 'info'`                           | `levelOptions: { level: 'info' }`                       |
| `trace`, `debug`, `info`, `warn`, `error` | the same names exist                                    |
| `fatal`                                   | not built in: add a custom level (below) or use `error` |
| `level: 'silent'`                         | `silent: true`                                          |
| `logger.level = 'debug'`                  | `logger.setLevel('debug')`                              |
| `customLevels`                            | `levelOptions.levels`                                   |

To keep a `fatal` method, define it as a custom level; it becomes a typed method:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'billing',
  levelOptions: {
    level: 'info',
    levels: { fatal: 0, error: 0, warn: 1, info: 2, debug: 3, trace: 4, verbose: 5 },
  },
  transports: { console: { format: 'json', colorize: false } },
});

await logger.fatal('database unreachable');
```

Two behaviors to know: the `LOGIXIA_LEVEL` environment variable, if set to a known level, overrides the configured level; and `NODE_ENV=test` can default the level to `warn` when `levelOptions` has no `level`. See [log levels](/guide/log-levels).

## How do `pino({...})` options map to `createLogger`?

| pino option                               | logixia                                                                                 |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `level`                                   | `levelOptions.level`                                                                    |
| `base: { service }`                       | `appName`, `environment`, or a child logger with bound fields                           |
| `name`                                    | `appName`                                                                               |
| `timestamp: isoTime`                      | ISO timestamps are the default (`timestamp: false` on the transport removes it)         |
| `redact`                                  | `redact` (see below)                                                                    |
| `messageKey`, `formatters`, `serializers` | no direct equivalent: use a [plugin](/guide/plugins) `onLog` hook or a custom transport |
| `mixin`                                   | `LogixiaContext.run()` for per-request fields, or a plugin                              |
| `transport`                               | `transports` (see below)                                                                |
| `enabled: false`                          | `silent: true`                                                                          |

There is no `formatters`/`serializers` API. The pino `err` serializer has a counterpart in behavior: an `Error` in a payload field is serialized with its name, message and stack. For other shaping, a plugin receives the entry after redaction and can modify it or drop it by returning `null`.

## What changes at call sites?

Pino puts the merging object first; logixia puts the message first.

```ts
import pino from 'pino';
import { createLogger } from 'logixia';

const pinoLogger = pino();
const logger = createLogger({ appName: 'billing' });

pinoLogger.info({ userId: 42 }, 'user signed in');
await logger.info('user signed in', { userId: 42 });

pinoLogger.error({ err: new Error('boom') }, 'failed');
await logger.error('failed', { err: new Error('boom') });
await logger.error(new Error('boom'));
```

Checklist for a codemod or search-and-replace:

1. **Swap the arguments** when the first argument is an object.
2. **Add `await`** where you want errors and ordering handled; logixia methods return `Promise<void>`. Without `await` the call still logs, but you do not wait for transports.
3. **printf-style interpolation** (`logger.info('hello %s', name)`) is not a logixia feature; use template literals and structured fields.
4. **Do not use field names that collide with core fields** (`level`, `message`, `timestamp`, `traceId`, `appName`, `environment`, `context`); colliding payload keys are kept under a `data_` prefix.

## How do child loggers and bindings map?

Pino's `child(bindings)` takes an object. logixia's takes a **context name** and optional bound data:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'billing',
  transports: { console: { format: 'json', colorize: false } },
});

const req = logger.child('request', { requestId: 'r-1' });
await req.info('started'); // context "request", requestId "r-1"

const payment = req.child('payment', { provider: 'stripe' });
await payment.info('charged'); // requestId and provider bound; context is now "payment"
```

The context name is replaced, not appended, in nested children. If you used `child({ reqId })` mainly to give every log line in a request an ID, logixia can do this without passing a child around, using async context. See [child loggers and context](/guide/child-loggers-and-context) and [tracing](/guide/tracing).

## How does pino's `redact` map to logixia's `redact`?

Both are built in and run before output. The configuration looks similar, but the details differ:

| pino `redact`                    | logixia `redact`                                                                                         |
| -------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `paths: ['a.b', '*.password']`   | `paths: ['a.b', '*.password']`                                                                           |
| array wildcards such as `a[*].b` | not documented as bracket syntax; check your rules against [Path syntax](/guide/redaction) and test them |
| any depth                        | `**.password` matches at any depth                                                                       |
| `censor: '[Redacted]'` (default) | `censor` (default `'[REDACTED]'`)                                                                        |
| `remove: true`                   | not supported; values are replaced, not deleted                                                          |
| paths only                       | also `patterns` (regexes on strings and the message) and `autoDetect`                                    |

The pino documentation is at [getpino.io](https://getpino.io/#/docs/redaction). Because logixia also scans the message and string values with `patterns`, a single `redact: { autoDetect: true }` adds coverage that pino's path rules do not, at the cost of some per-line work. Test redaction against real payloads when you migrate; see [redaction](/guide/redaction) and [redacting sensitive data](/articles/redact-sensitive-data-in-nodejs-logs).

## How do pino transports map to logixia transports?

Pino's design moves slow work off the main thread: [`pino.transport()`](https://getpino.io/#/docs/transports) runs targets (files, pretty printing, vendor shippers) in a worker thread. logixia's transports run **in-process** and batch their I/O:

| pino                                                                   | logixia                                                                                                                         |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| stdout JSON (default)                                                  | `transports: { console: { format: 'json' } }`                                                                                   |
| `pino/file` target                                                     | `transports: { file: { filename, dirname, maxSize, maxFiles, zippedArchive } }`                                                 |
| `pino-datadog-transport`, `pino-cloudwatch`, `pino-elasticsearch`, ... | built-in Datadog, CloudWatch, GCP, Azure Monitor, OTLP, Slack, Discord and database transports ([overview](/guide/transports/)) |
| your own worker-thread target                                          | `transports.custom: [{ name, write(entry) }]`                                                                                   |
| off-main-thread I/O by default                                         | opt in with `WorkerTransport` from `logixia/worker` ([guide](/guide/transports/worker))                                         |

The difference matters for latency: in-process batching is simple, but a slow custom transport shares the event loop with your code unless you use the worker transport. Pino's community transports are also much more numerous than logixia's.

## How does pino-pretty map to logixia's text output?

`pino-pretty` is a separate process (or transport) that turns JSON into readable lines. logixia's default console output is already readable text with colored levels, a timestamp, the context in brackets, the trace ID and the payload; set `format: 'json'` for production. There is no equivalent of `pino-pretty`'s many options (`translateTime`, `ignore`, `messageFormat`); the text format can hide fields through the `fields` option in the default path. See [configuration](/guide/configuration).

## How does pino-http map to logixia's middleware?

| pino-http                    | logixia                                                                                                           |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `pinoHttp({ logger })`       | `createExpressMiddleware(logger, options)` from `logixia/middleware`                                              |
| one "request completed" line | a `request completed` line, plus a `request started` line at `debug` (`requestLevel: 'silent'` removes it)        |
| `autoLogging.ignore`         | `skip: (req) => ...`                                                                                              |
| `customProps`                | `extraFields: (req) => ({ ... })`                                                                                 |
| `genReqId`                   | `traceIdHeader` plus a generated UUID; async context carries it                                                   |
| `customLogLevel`             | `requestLevel`, `responseLevel`, `errorLevel`                                                                     |
| `req.log` child per request  | no `req.log`: logs inside the request pick up the trace ID automatically through `createExpressContextMiddleware` |
| `serializers.req`/`res`      | fixed fields (`method`, `url`, `ip`, `headers`, `statusCode`, `duration`) with header and query redaction         |

```ts
import express from 'express';
import { createExpressContextMiddleware, createLogger } from 'logixia';
import { createExpressMiddleware } from 'logixia/middleware';

const logger = createLogger({ appName: 'api' });
const app = express();

app.use(createExpressContextMiddleware({ responseHeader: 'x-trace-id' }));
app.use(
  createExpressMiddleware(logger, {
    skip: (req) => req.url === '/health',
    slowRequestThresholdMs: 500,
  }) as unknown as express.RequestHandler
);
```

Fastify users have `createFastifyPlugin(logger, options)`. If you use Fastify's built-in pino logger, note that Fastify is built around pino; moving off it means replacing logging on the framework itself, which is rarely worth it.

## What does pino do that logixia does not?

Be clear-eyed about these before committing:

- **Speed on simple logs.** Pino is faster on plain string messages (our own harness measured logixia at about 61% lower throughput in JSON mode; see the [benchmarks](/guide/benchmarks) for why and for where logixia wins).
- **Ecosystem.** Many more transports, integrations and answered questions, and a long production record. logixia is a young project with a tiny community.
- **`pino.destination` sync and async modes.** Pino lets you pick a [synchronous or asynchronous destination](https://getpino.io/#/docs/asynchronous) with buffering for throughput. logixia's console transport writes synchronously, and its file transport batches; there is no equivalent single knob.
- **Worker-thread transports as the default model.** In logixia this is opt-in.
- **`fatal`, `serializers`, `formatters`, `mixin` and `remove`.** See the tables above; each needs a workaround or has none.
- **`flush`/`final` semantics.** logixia shuts down with `await logger.close()` or `gracefulShutdown: true` instead; see [graceful shutdown](/guide/graceful-shutdown).

What you gain: a trace ID in async context, redaction with regexes and presets, sampling, built-in vendor transports, OpenTelemetry export, typed custom levels and a [NestJS module](/guide/nestjs). On NestJS specifically, see [the NestJS logger comparison](/articles/best-nestjs-logger) and [migrating from nestjs-pino](/articles/migrate-from-nestjs-pino-to-logixia).

## A safe migration plan

1. Add logixia beside pino with the same level and a JSON console transport.
2. Convert one module: swap argument order, add `await`, and compare the output lines.
3. Update dashboards and alerts for `message`, string levels and ISO `timestamp`.
4. Add redaction and trace-ID middleware; test redaction on real payloads.
5. Convert the remaining modules and remove pino and its transports.
6. Set an explicit `levelOptions.level` in tests, since `NODE_ENV=test` can default to `warn`.

## Key takeaways

- Swap `logger.info(obj, msg)` to `logger.info(msg, obj)` and add `await`.
- Levels are names in logixia; add a custom `fatal` if you need it.
- `child(bindings)` becomes `child('context', bindings)`.
- Redaction carries over with syntax differences and no `remove`.
- Transports are in-process; worker transports are opt-in.
- Pino remains faster on simple logs and far larger in ecosystem.

## FAQ

**Is logixia a drop-in replacement for pino?** No. The concepts map closely, but argument order, level representation, output field names and the transport model differ, as the tables above show.

**Is logixia faster than pino?** Not on simple strings: pino was about 61% faster in our benchmark. logixia in JSON mode was ahead on some structured payloads. See the [benchmarks](/guide/benchmarks) and run them yourself.

**Can I run pino and logixia together during migration?** Yes. They are independent libraries; convert one module at a time.

**Does logixia have a `fatal` level?** Not built in. Add it with `levelOptions.levels`, as shown above.

**How do I replace pino-pretty?** Use the default text output in development and `format: 'json'` in production. There is no direct equivalent of pino-pretty's formatting options.

**Why migrate from pino at all?** The usual reasons are built-in request tracing, redaction with patterns, sampling and vendor transports in one package. If pino plus a few small libraries already covers you, there is no strong reason to move.
