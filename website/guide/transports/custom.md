---
title: Custom Transports
description: Write your own logixia transport with ITransport, add flush, close and readiness hooks for batching, and configure retry, backoff and fallback transports.
order: 13
---

# Custom Transports

A transport is any object with a `name` and a `write(entry)` method. Put instances in `transports.custom` and logixia calls them for every entry that passes the level and filter checks.

## The type names

The interfaces live in logixia's source (`ITransport`, `IAsyncTransport`, `IBatchTransport`, `TransportLogEntry`), but they are not exported by name from `logixia` or `logixia/transports`. You can derive them from `LoggerConfig` instead:

```ts
import type { LoggerConfig } from 'logixia';

type ITransport = NonNullable<NonNullable<LoggerConfig['transports']>['custom']>[number];
type TransportLogEntry = Parameters<ITransport['write']>[0];

export type { ITransport, TransportLogEntry };
```

The snippets below use these two aliases.

## A minimal transport

```ts
import type { LoggerConfig } from 'logixia';
import { createLogger } from 'logixia';

type ITransport = NonNullable<NonNullable<LoggerConfig['transports']>['custom']>[number];
type TransportLogEntry = Parameters<ITransport['write']>[0];

class JsonLinesTransport implements ITransport {
  readonly name = 'json-lines';
  readonly level = 'info';

  write(entry: TransportLogEntry): void {
    const line = JSON.stringify({
      time: entry.timestamp.toISOString(),
      level: entry.level,
      msg: entry.message,
      ...entry.data,
    });
    process.stdout.write(`${line}\n`);
  }
}

const logger = createLogger({
  appName: 'api',
  transports: { custom: [new JsonLinesTransport()] },
});

await logger.info('Ready');
```

The `ITransport` members:

| Member   | Type                               | Required | Description                                                     |
| -------- | ---------------------------------- | -------- | --------------------------------------------------------------- |
| `name`   | `string`                           | yes      | Identifies the transport and sets its metrics type (see below). |
| `write`  | `(entry) => void \| Promise<void>` | yes      | Handle one entry. Return a promise if the work is asynchronous. |
| `level`  | `string`                           | no       | Minimum level. Checked by logixia before `write()`.             |
| `filter` | `(entry) => boolean`               | no       | Return `false` to skip an entry. Runs after the level check.    |
| `close`  | `() => Promise<void>`              | no       | Called on shutdown. Release connections and timers here.        |
| `retry`  | `TransportRetryConfig`             | no       | Retry and fallback. See [below](#retry-and-fallback).           |

The entry fields are `timestamp` (a `Date`), `level`, `message`, and optional `data`, `context`, `traceId`, `appName` and `environment`.

::: tip
A synchronous `write()` that returns nothing is the fastest path. logixia only awaits transports that return a promise, so do not mark `write` as `async` unless you need to.
:::

## Batching and readiness

logixia recognizes two optional methods by name:

- **`flush(): Promise<void>`.** If your transport has it, `logger.flush()` and `logger.close()` call it, so buffered entries are sent before shutdown. This is the `IBatchTransport` shape; `IBatchTransport` also lists `addToBatch(entry)`, `batchSize` and `flushInterval`, but logixia only calls `flush()`.
- **`isReady(): Promise<boolean>`.** This makes it an `IAsyncTransport`. It is used by `healthCheck()` and `isTransportReady()`.

Here is a transport that batches entries and posts them over HTTP:

```ts
import type { LoggerConfig } from 'logixia';
import { createLogger } from 'logixia';

type ITransport = NonNullable<NonNullable<LoggerConfig['transports']>['custom']>[number];
type TransportLogEntry = Parameters<ITransport['write']>[0];

class HttpBatchTransport implements ITransport {
  readonly name = 'http-batch';
  private buffer: TransportLogEntry[] = [];
  private timer: NodeJS.Timeout;

  constructor(
    private readonly url: string,
    private readonly batchSize = 50,
    flushIntervalMs = 5000
  ) {
    this.timer = setInterval(() => void this.flush().catch(() => {}), flushIntervalMs);
    this.timer.unref();
  }

  write(entry: TransportLogEntry): void {
    this.buffer.push(entry);
    if (this.buffer.length >= this.batchSize) void this.flush().catch(() => {});
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    const batch = this.buffer.splice(0, this.batchSize);
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(batch),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (error) {
      this.buffer.unshift(...batch);
      throw error;
    }
  }

  async isReady(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    clearInterval(this.timer);
    await this.flush();
  }
}

const logger = createLogger({
  appName: 'api',
  transports: { custom: [new HttpBatchTransport('https://logs.example.com/ingest')] },
});

await logger.info('Batched');
await logger.close();
```

::: warning
Bound your buffer. The example above keeps failed batches forever. For a real transport, drop the oldest entries past a cap, as the built-in transports do with `maxBufferSize`.
:::

## Retry and fallback

The `TransportManager` can retry a transport's `write()` and fall back to another transport when retries run out. Set `retry` on the transport object:

| Option        | Type                                   | Default         | Description                                                                                                         |
| ------------- | -------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------- |
| `maxRetries`  | `number`                               | none            | Retries after the first attempt, so `maxRetries + 1` tries in total. Retry is off unless this is a positive number. |
| `backoff`     | `'fixed' \| 'linear' \| 'exponential'` | `'exponential'` | How the wait grows between attempts.                                                                                |
| `delay`       | `number` (ms)                          | `500`           | Base wait.                                                                                                          |
| `maxDelay`    | `number` (ms)                          | `30000`         | Cap for the exponential wait only.                                                                                  |
| `fallback`    | transport                              | none            | Receives the entry after the last failed attempt.                                                                   |
| `onExhausted` | `(error, entry) => void`               | none            | Called when retries and the fallback both failed. The error is then thrown to the logger.                           |

The wait before attempt `n + 1` is `delay` for `fixed`, `delay * (n + 1)` for `linear`, and `min(delay * 2^n, maxDelay)` for `exponential`, where `n` counts from 0.

```ts
import type { LoggerConfig } from 'logixia';
import { createLogger } from 'logixia';
import { FileTransport } from 'logixia/transports';

type ITransport = NonNullable<NonNullable<LoggerConfig['transports']>['custom']>[number];
type TransportLogEntry = Parameters<ITransport['write']>[0];

class WebhookTransport implements ITransport {
  readonly name = 'webhook';
  readonly retry = {
    maxRetries: 3,
    backoff: 'exponential' as const,
    delay: 200,
    maxDelay: 5000,
    fallback: new FileTransport({
      filename: 'webhook-fallback.log',
      dirname: './logs',
      batchSize: 1,
    }),
    onExhausted: (error: Error, entry: TransportLogEntry) => {
      console.error(`gave up on "${entry.message}": ${error.message}`);
    },
  };

  constructor(private readonly url: string) {}

  async write(entry: TransportLogEntry): Promise<void> {
    const res = await fetch(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(entry),
    });
    if (!res.ok) throw new Error(`Webhook returned ${res.status}`);
  }
}

const logger = createLogger({
  appName: 'api',
  transports: { custom: [new WebhookTransport('https://hooks.example.com/logs')] },
});

await logger.error('Disk almost full');
```

The manager also emits `transport:retry` (name, attempt, max retries, wait) and `transport:fallback` (name, fallback name) events if you listen to a `TransportManager` yourself.

::: warning
Retry only sees what `write()` reports. A transport that buffers and returns right away, like the built-in file, database, cloud, analytics, OTLP and chat transports, never throws from `write()` for a delivery problem, so `retry` does nothing for them. They re-buffer failed batches on their own. Use `retry` for transports whose `write()` does the network call itself, as above.
:::

## Transport IDs and metrics

Transports from `custom` get the IDs `custom-0`, `custom-1` and so on, which you can use with `setTransportLevels`. In metrics, a transport is typed by its `name`: `console`, `file` and `database` map to those types, `mixpanel`, `datadog`, `google-analytics` and `segment` map to `analytics`, and everything else is `custom`.

## Related

- [Transports overview](/guide/transports/)
- [Testing](/guide/testing) for capturing log entries in tests
- [Customization](/guide/customization)
