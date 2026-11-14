---
title: Sentry Transport
description: Send logixia errors to Sentry as events with the real stack, trace ID and tags, and lower levels as breadcrumbs or Sentry Logs. No @sentry dependency.
order: 11.5
---

# Sentry Transport

`SentryTransport` forwards logixia entries to Sentry. Entries at `error` and above become Sentry events, with the original error stack, a trace ID tag and the logger namespace. Lower levels become breadcrumbs (or Sentry Logs, if you opt in) and ride along on the next event.

It has no dependency on `@sentry/*`. You pass your own initialised Sentry namespace, and logixia only calls the functions it needs. It is exported from `logixia` and `logixia/transports`.

## Quick start

Initialise Sentry first, then hand the namespace to the transport:

<!-- snippet-check: skip -->

```ts
import * as Sentry from '@sentry/node';
import { createLogger, SentryTransport } from 'logixia';

Sentry.init({ dsn: process.env.SENTRY_DSN, environment: 'production' });

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    console: { format: 'json', colorize: false },
    custom: [new SentryTransport({ sentry: Sentry })],
  },
});

await logger.error(new Error('payment provider timed out'), { orderId: 'o_1' });
await logger.close();
```

`SentryTransport` leaves its own `level` unset so the logger hands it every level; `minLevel` (below) decides what becomes an event. Declare `console` yourself when you add other transports, because a `transports` object only creates the destinations you list.

## Options

| Option           | Type                             | Default   | Description                                                                                          |
| ---------------- | -------------------------------- | --------- | ---------------------------------------------------------------------------------------------------- |
| `sentry`         | `SentryLike`                     | required  | Your Sentry namespace. Needs `captureException` and `captureMessage`; the rest is used when present. |
| `minLevel`       | `string`                         | `'error'` | Lowest level sent as an event. An unknown name throws when the transport is created.                 |
| `logs`           | `boolean`                        | `false`   | Send levels below `minLevel` to the Sentry Logs API instead of breadcrumbs.                          |
| `breadcrumbs`    | `boolean`                        | `true`    | Record levels below `minLevel` as breadcrumbs (when they are not sent as logs). `false` drops them.  |
| `levelMap`       | `Record<string, SentrySeverity>` | unset     | Level name to Sentry severity, for custom levels or to override a built-in mapping.                  |
| `flushTimeoutMs` | `number`                         | `2000`    | Longest `flush()` and `close()` wait for `Sentry.flush`.                                             |
| `filter`         | `(entry) => boolean`             | unset     | Return `false` to skip an entry.                                                                     |

## Levels

Each logixia level maps to a Sentry severity: `fatal` to `fatal`, `error` to `error`, `warn` to `warning`, `info` to `info`, `log` to `log`, and `debug`, `verbose` and `trace` to `debug`. A level it does not know (a custom level) is treated as `info`, so it becomes a breadcrumb. Add it to `levelMap` to change that:

```ts
import { SentryTransport, type SentryLike } from 'logixia';

declare const Sentry: SentryLike;

export const sentryTransport = new SentryTransport({
  sentry: Sentry,
  minLevel: 'warn',
  levelMap: { audit: 'warning', page: 'fatal' },
});
```

`minLevel` is compared by Sentry severity, so `minLevel: 'warn'` sends `warn`, `error`, `fatal` and any custom level you mapped to `warning` or higher.

## What an event contains

- **Errors.** `logger.error(err)` stores a serialized error (`name`, `message`, `stack`, `cause`) under `data.error`. The transport rebuilds a real `Error` with that name, message and stack (and the `cause` chain), then calls `captureException`. Sentry groups by the real stack, not by the transport's. If the stack was removed by redaction, the event has only `Name: message`.
- **Everything else.** An entry without a serialized error is sent with `captureMessage` and the mapped severity.
- **Tags.** `trace_id` (the entry's trace ID), `context` (the logger namespace, such as a child logger name) and `logixia_level`.
- **Context.** A `logixia` context with the level, trace ID, namespace, app name and environment.
- **Extra.** The rest of the payload. If the log message differs from the error message, it is kept as `logMessage`.

The trace ID is a tag and a context field, not Sentry's own trace context. That is deliberate: logixia IDs are not always 32-character hex, and overwriting Sentry's trace would break its tracing. Search by `trace_id:<value>` in Sentry and by the same value in your logs.

## Breadcrumbs or the Logs API

By default levels below `minLevel` become **breadcrumbs**. They work on every SDK version, cost nothing extra, and show up on the next event as the trail that led to it, which is what most teams want from `info` and `debug` lines. They are not searchable on their own and are dropped if no event follows.

Set `logs: true` to send those entries to the **Sentry Logs API** (`Sentry.logger.info`, `warn`, and so on) instead. They become searchable, standalone logs. It needs Sentry JavaScript SDK 9.41 or later, with `enableLogs: true` in `Sentry.init` (logs are on by default from 10.71). Logs count against your Sentry log quota, so keep `minLevel` and the logger level where you want them. If `Sentry.logger` is missing, the transport warns once and falls back to breadcrumbs. Object values in the payload are sent as JSON text, because log attributes are primitives.

<!-- snippet-check: skip -->

```ts
import * as Sentry from '@sentry/node';
import { SentryTransport } from 'logixia';

Sentry.init({ dsn: process.env.SENTRY_DSN, enableLogs: true });

export const sentryTransport = new SentryTransport({ sentry: Sentry, logs: true });
```

## Redaction

Transports receive entries after the logger's `redact` config has run, and the Sentry transport sends only what it receives: the payload, the message and the error stack. A path rule such as `error.stack` removes the stack before Sentry sees it. Note that Sentry's own SDK also attaches request data and breadcrumbs from its integrations, which logixia does not control; use `beforeSend` for those.

## Flushing on shutdown

The Sentry SDK sends events in the background. `flush()` and `close()` call `Sentry.flush(flushTimeoutMs)` and never wait longer than that, so a blocked network cannot hang shutdown. `close()` does not close the Sentry client, because your application owns it. Call `await logger.close()` on shutdown or enable `gracefulShutdown` so the last error before exit is delivered.

## Failure behaviour

`write()` never throws. If a Sentry call fails, the error is reported on stderr as a logixia internal error and the entry is skipped; other transports are unaffected.

## When you do not need it

Sentry already captures uncaught exceptions and unhandled rejections, and its `consoleLoggingIntegration` can forward `console` calls as logs. If you only want crashes in Sentry, you do not need this transport. Use it when you log handled errors through logixia and want them in Sentry with their trace ID and namespace, without calling `Sentry.captureException` next to every `logger.error`.
