---
title: Transports Overview
description: Choose a logixia transport for console, file, database, CloudWatch, GCP, Azure, Datadog, OTLP, Slack or workers, and learn level, filter and retry options.
order: 1
---

# Transports Overview

A transport is where a log entry ends up. logixia sends every entry that passes the logger's level check to all configured transports, and one transport failing does not stop the others.

If you set no `transports` key, logs go to stdout and stderr. Add a `transports` key when you want files, a database, a cloud service or anything else.

## The transports at a glance

| Transport                                                           | Import from                              | Typical use                                            | Batching and failure handling                                                  | Page                                                 |
| ------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------ | ---------------------------------------------------- |
| `ConsoleTransport`                                                  | `logixia/transports`                     | Terminal output, container stdout                      | None. Writes synchronously; `warn` and `error` go to stderr                    | [Console](/guide/transports/console)                 |
| `FileTransport`                                                     | `logixia/transports`                     | Local log files with rotation                          | Batches of 100 or every 5 s; in-memory queue capped at 10,000                  | [File](/guide/transports/file)                       |
| `DatabaseTransport`                                                 | `logixia/transports`                     | PostgreSQL, MySQL, MongoDB, SQLite                     | Batches of 100 or every 5 s; failed batches re-buffered, cap 10,000            | [Database](/guide/transports/database)               |
| `CloudWatchTransport`                                               | `logixia/cloudwatch`                     | AWS CloudWatch Logs, EMF metrics                       | Batches of 100 or every 5 s; retried with backoff; cap 10,000                  | [CloudWatch](/guide/transports/cloudwatch)           |
| `GCPTransport`                                                      | `logixia/gcp`                            | Google Cloud Logging                                   | Batches of 200 or every 5 s; retried with backoff; cap 10,000                  | [GCP](/guide/transports/gcp)                         |
| `AzureMonitorTransport`                                             | `logixia/azure`                          | Azure Monitor Logs Ingestion                           | Batches of 200 or every 5 s; retried with backoff; cap 10,000                  | [Azure](/guide/transports/azure)                     |
| `DataDogTransport`                                                  | `logixia/transports`                     | Datadog Logs (and optional metrics)                    | Batches of 50 or every 10 s; failed batches re-buffered, cap 10,000            | [Datadog](/guide/transports/datadog)                 |
| `OtlpLogTransport`                                                  | `logixia` or `logixia/transports`        | Any OTLP/HTTP logs backend                             | Batches of 100 or every 5 s; retried with backoff; cap 10,000                  | [OTLP](/guide/transports/otlp)                       |
| `MixpanelTransport`, `SegmentTransport`, `GoogleAnalyticsTransport` | `logixia/transports`                     | Product analytics events                               | Batches of 50 or every 10 s; failed batches re-buffered, cap 10,000            | [Analytics](/guide/transports/analytics)             |
| `SlackTransport`, `DiscordTransport`                                | `logixia` or `logixia/transports`        | Alerts in a chat channel                               | Entries within 1 s share one message; one retry after HTTP 429; queue of 1,000 | [Slack and Discord](/guide/transports/slack-discord) |
| `WorkerTransport`                                                   | `logixia/worker` or `logixia/transports` | Move file, database or console I/O off the main thread | Restarts a crashed worker up to 3 times                                        | [Worker thread](/guide/transports/worker)            |
| Your own class                                                      | n/a                                      | Anything else                                          | Whatever you implement, plus optional `retry`                                  | [Custom](/guide/transports/custom)                   |

## Where each transport goes in `LoggerConfig`

`LoggerConfig.transports` has five keys:

| Key         | Accepts                                                                                            | Used for                            |
| ----------- | -------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `console`   | One `ConsoleTransportConfig`                                                                       | Terminal output                     |
| `file`      | One `FileTransportConfig` or an array                                                              | Local files                         |
| `database`  | One `DatabaseTransportConfig` or an array                                                          | PostgreSQL, MySQL, MongoDB, SQLite  |
| `analytics` | An object with `datadog`, `mixpanel`, `segment` and `googleAnalytics`, each one config or an array | Datadog and the analytics providers |
| `custom`    | An array of transport instances                                                                    | Everything else                     |

Cloud, OTLP, Slack, Discord and worker transports have no config key of their own. Create an instance and put it in `transports.custom`:

```ts
import { createLogger, OtlpLogTransport, SlackTransport } from 'logixia';
import { FileTransport } from 'logixia/transports';

const logger = createLogger({
  appName: 'api',
  transports: {
    file: { filename: 'app.log', dirname: './logs' },
    custom: [
      new OtlpLogTransport({ url: 'http://localhost:4318/v1/logs', serviceName: 'api' }),
      new SlackTransport({ webhookUrl: process.env.SLACK_WEBHOOK_URL!, level: 'error' }),
      new FileTransport({ filename: 'audit.log', dirname: './logs', level: 'warn' }),
    ],
  },
});
```

Datadog, Mixpanel, Segment and Google Analytics go through `transports.analytics`:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    analytics: {
      datadog: { apiKey: process.env.DD_API_KEY!, service: 'api', env: 'production' },
    },
  },
});
```

::: tip
Arrays work for `file`, `database` and each analytics provider, so you can write to two files or two databases at once.
:::

## Options every transport shares

Every transport has the `ITransport` shape, so these three options work on all of them.

### `level`

A transport can have its own minimum level on top of the logger's global level. The order is `error`, `warn`, `info`, `debug`, `trace`, `verbose`. A transport with `level: 'warn'` receives `error` and `warn` entries only. Entries with a level that is not in that list (a custom level, or `fatal`) are always passed through.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    file: [
      { filename: 'app.log', dirname: './logs' },
      { filename: 'error.log', dirname: './logs', level: 'error' },
    ],
  },
});
```

::: warning
`ConsoleTransportConfig` has a `level` field, but the console transport ignores it. Use the logger's `levelOptions.level` or a `filter` instead. See [Console](/guide/transports/console).
:::

You can also change what a running transport receives with `setTransportLevels(id, levels)` on the logger. That list replaces the transport's own `level` check. IDs are `console`, `file-0`, `database-0`, `datadog-0`, `mixpanel-0`, `google-analytics-0`, `segment-0` and `custom-0` (the number is the index in its array).

```ts
import { LogixiaLogger } from 'logixia';

const logger = new LogixiaLogger({
  appName: 'api',
  transports: {
    file: [
      { filename: 'app.log', dirname: './logs' },
      { filename: 'error.log', dirname: './logs' },
    ],
  },
});

logger.setTransportLevels('file-1', ['error', 'warn']);
console.log(logger.getAvailableTransports()); // ['file-0', 'file-1']
```

### `filter`

A predicate that runs after the level check. Return `false` to skip the entry for that transport only.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    file: {
      filename: 'payments.log',
      dirname: './logs',
      filter: (entry) => entry.context === 'payments',
    },
  },
});
```

The entry is a `TransportLogEntry`:

| Field         | Type                                 |
| ------------- | ------------------------------------ |
| `timestamp`   | `Date`                               |
| `level`       | `string`                             |
| `message`     | `string`                             |
| `data`        | `Record<string, unknown>` (optional) |
| `context`     | `string` (optional)                  |
| `traceId`     | `string` (optional)                  |
| `appName`     | `string` (optional)                  |
| `environment` | `string` (optional)                  |

### `retry`

`retry` is a property of the transport object, not a config option of the built-in classes. The `TransportManager` reads it and retries `write()` when it throws or rejects. See [Custom transports](/guide/transports/custom#retry-and-fallback) for the options and an example.

## Flushing and closing

Transports that buffer (file, database, cloud, analytics, OTLP, chat) send their buffer on a timer, when it fills, and when you close the logger. Call `await logger.flush()` to push buffers out without closing, and `await logger.close()` before the process exits. For signal handling, see [Graceful shutdown](/guide/graceful-shutdown).

`await logger.healthCheck()` returns `{ healthy, details }` with a `ready` flag and write metrics per transport. Transports without an `isReady()` method count as ready; the database transport's `isReady()` tries to connect.

## TransportManager basics

`createLogger` builds a `TransportManager` for you from `LoggerConfig.transports`. You rarely need to touch it, but it is exported from `logixia/transports` if you want one on its own.

```ts
import { ConsoleTransport, TransportManager } from 'logixia/transports';

const manager = new TransportManager({ console: { format: 'json' } });

manager.addTransport(new ConsoleTransport({ format: 'text' }), 'debug-console');
manager.onError((error, transportId) => {
  console.error(`transport ${transportId} failed`, error.message);
});

console.log(manager.getTransports()); // ['console', 'debug-console']
console.log(manager.getMetrics().map((m) => m.logsWritten));

await manager.close();
```

What it does on each `write()`:

1. Skips transports whose `level` (or `setTransportLevels` list) rejects the entry.
2. Skips transports whose `filter` returns `false`.
3. Calls `transport.write(entry)`, with retry and fallback if `retry.maxRetries` is set.
4. Records per-transport metrics (`logsWritten`, `errors`, `lastWrite`, `averageWriteTime`) and emits `log` or `error` events.

It also has `removeTransport(id)`, `flush()` (calls `flush()` on every transport that has one), `close()`, `getTransport(id)`, `getMetricsForTransport(id)` and `isTransportReady(id)`. Events are `log`, `error`, `flush`, `transport:added`, `transport:removed`, `transport:retry` and `transport:fallback`.

## Secrets in transport config

Credentials in transport config (API keys, passwords, webhook URLs, tokens) are kept out of `JSON.stringify` and `util.inspect` output, and scrubbed from error messages the transports raise. Read the values from `process.env` rather than hard-coding them. See [Security](/guide/security) for the wider picture.

## Related

- [Configuration](/guide/configuration) for the rest of `LoggerConfig`
- [Redaction](/guide/redaction) to mask fields before they reach any transport
- [Sampling](/guide/sampling) to thin out noisy entries before they reach any transport
