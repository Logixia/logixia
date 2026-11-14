---
title: 'Send Node.js Logs and Errors to Sentry from Your Logger'
description: 'Forward handled errors from your Node.js logger to Sentry with the real stack, trace ID and tags, plus breadcrumbs or Sentry Logs. Working logixia setup.'
date: 2026-11-14
tags: [sentry, error-tracking, observability, nodejs, logging]
---

# Send Node.js Logs and Errors to Sentry from Your Logger

**TL;DR:** Sentry already catches uncaught exceptions on its own. What it misses are the errors you catch, log and carry on from. To get those in, route `error`-level log entries to `Sentry.captureException` with the original stack, keep lower levels as breadcrumbs so each event arrives with its trail, and flush before the process exits. logixia's `SentryTransport` does this from your logger without adding a `@sentry/*` dependency: you pass in the Sentry namespace you already initialised.

Most Node.js services end up with two parallel habits: `logger.error(err)` for the log store, and `Sentry.captureException(err)` next to it for the error tracker. They drift apart, one gets forgotten, and the Sentry event has no trace ID to find the matching logs. This article shows the single-call version.

## Do I need a logger transport for Sentry at all?

Maybe not. Be clear about what Sentry does without help:

- The Node SDK captures **uncaught exceptions and unhandled promise rejections** once `Sentry.init` has run.
- Its framework integrations capture errors that reach Express or Fastify error handlers.
- `consoleLoggingIntegration` forwards `console` calls to Sentry Logs, and `createConsolaReporter` does the same for Consola.

If crashes are all you care about, stop here. A transport earns its place when you **handle** errors (a failed payment you retry, a webhook you reject) and still want them in Sentry, with the same trace ID your logs carry, without writing the capture call twice.

## How do I send logixia errors to Sentry?

Initialise Sentry as usual, then add `SentryTransport` and pass it the namespace:

<!-- snippet-check: skip -->

```ts
import * as Sentry from '@sentry/node';
import { createLogger, SentryTransport } from 'logixia';

Sentry.init({ dsn: process.env.SENTRY_DSN, environment: 'production' });

export const logger = createLogger({
  appName: 'checkout-api',
  environment: 'production',
  transports: {
    console: { format: 'json', colorize: false },
    custom: [new SentryTransport({ sentry: Sentry })],
  },
});

await logger.error(new Error('payment provider timed out'), { orderId: 'ord_123' });
```

The transport is typed structurally (it needs `captureException` and `captureMessage`; `addBreadcrumb`, `withScope`, `logger` and `flush` are used when present), so it works with whichever Sentry version you run and adds nothing to your dependency tree. Declare `console` yourself: a `transports` object only creates the destinations you list.

## Will Sentry group by the real stack trace?

Yes. When you log an `Error`, logixia serializes it (name, message, stack, cause) into the entry. The transport rebuilds an `Error` with that exact name, message and stack, then calls `captureException`. Sentry sees the original frames, so issues group the way they would if you had captured the error yourself. A `cause` chain is rebuilt too, so linked errors show up.

If you log a plain message with `logger.error('inventory sync failed', { sku })`, there is no stack to rebuild, so the transport uses `captureMessage` with severity `error`. Prefer passing the error object when you have one.

## How do I find the matching logs for a Sentry issue?

Each event carries a `trace_id` tag (the entry's trace ID) and a `context` tag (the logger namespace, such as a child logger's name), plus a `logixia` context with the app name and environment. The rest of the payload goes in as extra data. Copy the `trace_id` value from the Sentry issue and search your log store for it; see [request tracing in NestJS](/articles/nestjs-logging-with-request-tracing) or [Express](/articles/express-request-logging-trace-id) for getting that ID onto every line.

The trace ID is deliberately a tag, not Sentry's trace context: logixia IDs are not always 32-character hex, and overwriting Sentry's own trace would break its tracing.

## What happens to info and debug logs?

They become **breadcrumbs** by default. A breadcrumb is a short note Sentry buffers and attaches to the next event, so an error arrives with "cache miss, retry 1, retry 2" before it. Breadcrumbs work on every SDK version and cost nothing extra; the trade-off is that they are not searchable on their own.

If you want those entries as standalone, searchable logs, set `logs: true`:

<!-- snippet-check: skip -->

```ts
import * as Sentry from '@sentry/node';
import { SentryTransport } from 'logixia';

Sentry.init({ dsn: process.env.SENTRY_DSN, enableLogs: true });

export const sentryTransport = new SentryTransport({
  sentry: Sentry,
  logs: true,
  minLevel: 'error',
});
```

This calls `Sentry.logger.info`, `warn` and the rest. It needs Sentry JavaScript SDK 9.41 or later with `enableLogs: true` (on by default from 10.71), and it counts against your Sentry log quota. If `Sentry.logger` is not there, the transport warns once and falls back to breadcrumbs. Choose the Logs API when you want Sentry to be a log store too; stay with breadcrumbs when Sentry is only your error tracker and your logs live elsewhere.

## Can secrets leak to Sentry through my logs?

Only if they got past redaction. Transports receive entries after the logger's `redact` config has run, so a field removed by a path rule never reaches Sentry, and the same goes for the message and the error stack:

```ts
import { createLogger, SentryTransport, type SentryLike } from 'logixia';

declare const Sentry: SentryLike;

export const logger = createLogger({
  appName: 'checkout-api',
  transports: { custom: [new SentryTransport({ sentry: Sentry })] },
  redact: { paths: ['password', '**.token', 'error.stack'], patterns: [/sk_live_\w+/g] },
});
```

This covers what logixia sends. Sentry's own SDK also attaches request data and its own breadcrumbs, which this config does not touch; use `beforeSend` in `Sentry.init` for those. See [redacting sensitive data in Node.js logs](/articles/redact-sensitive-data-in-nodejs-logs) for what each rule catches.

## How do I make sure the last error is delivered?

The Sentry SDK sends in the background, so an error logged just before `process.exit` can be lost. The transport's `flush()` and `close()` call `Sentry.flush` with a bounded timeout (2 seconds by default, `flushTimeoutMs` to change it), so a dead network cannot hang shutdown. Call `await logger.close()` in your shutdown handler, or enable `gracefulShutdown` on the logger. `close()` does not close the Sentry client; your app owns that.

## What about custom levels and noise?

Built-in levels map to Sentry severities (`warn` becomes `warning`, `trace` and `verbose` become `debug`). A custom level is treated as `info` unless you map it:

```ts
import { SentryTransport, type SentryLike } from 'logixia';

declare const Sentry: SentryLike;

export const sentryTransport = new SentryTransport({
  sentry: Sentry,
  minLevel: 'warn',
  levelMap: { audit: 'warning', page: 'fatal' },
  filter: (entry) => entry.context !== 'HealthCheck',
});
```

Alerting on `warn` is rarely worth the issue volume. Keep `minLevel` at `error` unless you have a reason, and use `filter` to drop known noisy namespaces.

## Pitfalls

- **Double reporting.** If Sentry's framework integration already captures an error and you also `logger.error` it, you get two events. Log handled errors only, or filter by `context`.
- **Logging errors as strings.** `logger.error(String(err))` throws away the stack. Pass the error object.
- **Forgetting `Sentry.init`.** The transport only calls the namespace you give it; before `init` the calls do nothing.
- **Event volume.** Every `error` entry is an event. A tight retry loop can burn your quota, so sample or `filter` it.

For other destinations see the [Sentry transport guide](/guide/transports/sentry) and the [transports overview](/guide/transports/).

## Key takeaways

- Sentry catches crashes on its own; the transport is for errors you handle and log.
- `error` and above become events with the real stack, a `trace_id` tag and the logger namespace.
- Lower levels are breadcrumbs by default; `logs: true` sends them to the Sentry Logs API instead.
- Redaction runs before the transport, and `close()` flushes with a bounded timeout.

## FAQ

**How do I send Node.js errors to Sentry from my logger?** Initialise Sentry, then add `new SentryTransport({ sentry: Sentry })` to `transports.custom`. Entries at `error` and above are sent as Sentry events.

**Does the Sentry transport need `@sentry/node` installed by logixia?** No. You pass in the Sentry namespace you already initialised, and logixia only calls functions on it, so there is no `@sentry/*` dependency.

**Will Sentry show the original stack trace?** Yes. The transport rebuilds an `Error` with the logged name, message and stack (and the cause chain) before calling `captureException`, so issues group by the real stack.

**What happens to info and debug logs?** They become breadcrumbs attached to the next event. Set `logs: true` to send them to the Sentry Logs API instead (SDK 9.41 or later with `enableLogs: true`).

**Can I keep secrets out of Sentry?** Yes for anything logged through logixia: entries are redacted before they reach the transport. Use Sentry's `beforeSend` for data its own SDK collects.
