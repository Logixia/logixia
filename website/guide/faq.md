---
title: FAQ
description: 'Answers to common logixia questions: missing debug logs, no console output with transports, await and flushing, NestJS imports, TypeScript errors and sampling.'
order: 24
---

# FAQ

## My `debug` logs do not appear

The default level is `info`. Set `levelOptions: { level: 'debug' }`, call `logger.setLevel('debug')`, or start the process with `LOGIXIA_LEVEL=debug`. The `NODE_ENV` defaults only apply when you pass `levelOptions` without a `level`; a logger with no `levelOptions` is `info` in every environment. See [Log levels](/guide/log-levels).

## I added a file transport and the console went quiet

Setting `transports` replaces the default output. Add `console: {}` next to `file` if you still want terminal output. See [Configuration](/guide/configuration).

## `format`, `fields` and `colorize` do nothing

Those logger-level options only apply to the default output path, which is used when `transports` is not set. With transports, configure formatting on each transport, for example `transports.console.format` and `transports.console.colorize`.

## Do I need to `await` log calls?

Every log method returns a promise. In a request handler you can call it without `await`; transport failures are handled inside logixia and reported on stderr. Do `await` (or `await logger.close()`) at the end of scripts, jobs and tests, so buffered entries are written before the process ends. For servers, use [graceful shutdown](/guide/graceful-shutdown).

## `logger.flush()` is a TypeScript error

`createLogger()` returns the logger interface, which has `close()` but not `flush()`, `healthCheck()` or `setNamespaceLevels()`. They exist on the `LogixiaLogger` class, so create the logger with `new LogixiaLogger(config)` when you need them.

## Where did the NestJS exports go?

To `logixia/nest`, since 2.0. See [Migrating to 2.0](/guide/migration-v2) and [NestJS](/guide/nestjs).

## `@InjectLogger()` cannot resolve its dependency

The decorator injects the token `LOGIXIA_LOGGER_SERVICE`, which `forRoot()` does not register. Inject `LogixiaLoggerService` by class instead, or import `LogixiaLoggerModule.forFeature('service')`. Details in [NestJS](/guide/nestjs).

## `app.use(createExpressMiddleware(logger))` does not compile

The middleware uses minimal structural request and response types that Express's `RequestHandler` does not accept directly. Cast it: `app.use(mw as unknown as express.RequestHandler)`. It works at runtime without changes. See [HTTP logging](/guide/http-logging).

## I cannot see `request started` entries

They are logged at `debug`. Lower the level, or change them with the `requestLevel` option.

## Why do my trace IDs change between requests?

By design a trace ID belongs to one request. Outside a request scope, entries use one UUID per logger instance. Wrap work in `runWithTraceId()` or use the [context middleware](/guide/tracing) so each request or job gets its own.

## A client sent a trace ID and I got a different one

Incoming IDs are validated: 1 to 128 characters from `[A-Za-z0-9._:-]`. Anything else is replaced with a generated ID, which keeps untrusted text out of your logs. See [Security](/guide/security).

## Are errors and warnings ever sampled away?

No. With [sampling](/guide/sampling), `error`, `warn` and `fatal` entries are always kept unless you set an explicit `perLevel` rate for that level.

## Why does sampling print a JSON line every minute?

It is the sampling stats report, written directly to stdout. Set `sampling.statsIntervalMs: 0` to turn it off.

## Does logixia work in the browser, Cloudflare Workers or Deno?

The `logixia/browser` entry does, with a smaller logger and no Node features. See [Browser and edge](/guide/browser-and-edge). The main entry uses Node APIs such as `AsyncLocalStorage`.

## Which Node.js versions are supported?

The `engines` field in `package.json` requires Node.js 16 or later.

## Can I send logs to a service that has no built-in transport?

Yes. Implement the small transport interface, or use the OTLP, Slack or webhook-style transports. See [Custom transport](/guide/transports/custom) and [OTLP transport](/guide/transports/otlp).

## How do I keep secrets out of logs?

Use `redact` with `paths`, `patterns` and `autoDetect`, and never log credentials on purpose. See [Redaction](/guide/redaction) and [Security](/guide/security).

## Can I query my log files?

Yes: the [`logixia` CLI](/guide/cli) searches, queries and explores NDJSON files, and [`logixia/search`](/guide/log-search) does in-memory search from code.

## How do I report a bug or a vulnerability?

Bugs go to the [GitHub issue tracker](https://github.com/Logixia/logixia/issues). Security problems go through private vulnerability reporting; see [Security](/guide/security).
