---
title: Browser and edge runtimes
description: 'Use logixia/browser in web pages, Cloudflare Workers, Vercel Edge and Deno: a Node-free logger with console and batched remote transports.'
order: 17
---

# Browser and edge runtimes

`logixia/browser` is a small logger with no references to Node built-ins (`node:fs`, `node:crypto`, `node:async_hooks` and so on), so it bundles for browsers, Cloudflare Workers, Vercel Edge Functions and Deno. It also works in Node.

```ts
import { createBrowserLogger } from 'logixia/browser';

const logger = createBrowserLogger({ appName: 'checkout', level: 'debug' });
logger.info('cart updated', { itemCount: 3, total: 49.99 });
```

::: warning A smaller feature set
The browser logger is separate from the Node logger. It has no redaction, sampling, plugins, trace context or file, database and cloud transports, and its methods are synchronous (they return `void`). Do not log secrets from the browser; anything you log can be read by the user.
:::

## Configuration

| Option       | Type                      | Default  | Description                                                                |
| ------------ | ------------------------- | -------- | -------------------------------------------------------------------------- |
| `appName`    | `string`                  | `'App'`  | Name written into every entry.                                             |
| `level`      | `BrowserLogLevel`         | `'info'` | Minimum level.                                                             |
| `json`       | `boolean`                 | `false`  | `true` for one compact JSON string per entry; `false` for devtools groups. |
| `transports` | `IBrowserTransport[]`     | none     | Extra transports. The console transport is always added.                   |
| `silent`     | `boolean`                 | `false`  | No output at all, console included (useful in tests).                      |
| `context`    | `Record<string, unknown>` | none     | Static fields merged into every payload.                                   |

Levels, from least to most severe: `verbose`, `debug`, `info`, `warn`, `error`, `critical`. There is no `trace` level. Methods: `verbose`, `debug`, `info`, `log` (same as `info`), `warn`, `error`, `critical`, each as `(message, payload?)`.

`logger.child({ context: 'AuthService', userId: '42' })` returns a logger whose payload always includes those fields. The argument is a fields object, not a name string.

The package also exports a ready-made `browserLogger` (app name `App`, info level), `BrowserConsoleTransport`, the OpenTelemetry helpers (`initOtelBridge`, `getActiveOtelContext`, `getOtelMetaFields`, `disableOtelBridge`) and the [typed logger](/guide/typed-logger) utilities.

## Send logs to a server

`BrowserRemoteTransport` batches entries and POSTs them as JSON with `fetch`.

```ts
import { BrowserRemoteTransport, createBrowserLogger } from 'logixia/browser';

const remote = new BrowserRemoteTransport({
  url: '/api/logs',
  batchSize: 50,
  flushIntervalMs: 10_000,
  level: 'warn',
  onError: () => {
    // Route failures somewhere that is not this logger.
    console.warn('log delivery failed');
  },
});

const logger = createBrowserLogger({ appName: 'web', transports: [remote] });
logger.error('payment widget failed', { code: 'E_WIDGET' });
```

Call `remote.destroy()` when the page is going away (for example from a `pagehide` listener) so the last entries are flushed.

| Option            | Default                                    | Description                                                                              |
| ----------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `url`             | required                                   | Endpoint. Must be `http:` or `https:`, or a same-origin path starting with a single `/`. |
| `headers`         | `{}`                                       | Extra request headers, for example `Authorization`.                                      |
| `batchSize`       | `100`                                      | Flush when this many entries are queued.                                                 |
| `flushIntervalMs` | `5000`                                     | Timer interval. `0` disables the timer, so you flush manually or by batch size.          |
| `maxBufferSize`   | `1000`                                     | Oldest entries are dropped past this size and counted.                                   |
| `level`           | none                                       | Minimum level for this transport.                                                        |
| `silent`          | `true` in browser pages, `false` elsewhere | Hide the console report of failed flushes. `onError` still runs.                         |
| `onError`         | none                                       | Called on every failed flush (network error or non-OK status) with the raw error.        |

Behaviour worth knowing:

- Requests use `keepalive` when the body is under 60,000 bytes, so a flush during page unload can complete. If the runtime rejects `keepalive`, the transport retries without it.
- A network error, a 5xx or a 429 keeps the entries queued for the next flush. Other 4xx responses drop the batch and count it.
- Failure reports to the console are throttled to one per minute and never include the URL or error text, because runtimes embed URLs and header values in error messages. The raw error is only given to `onError`.
- Anything written to the transport from inside `onError` is dropped, to prevent loops.
- Counters: `remote.dropped`, `remote.failedFlushes` and `remote.lastError` (the raw error; do not log it blindly).
- `destroy()` stops the timer and flushes what remains. `flush()` returns a promise.
- The `headers` and `url` are hidden from serialization and inspection so a credential in them does not leak when the transport is printed.

## Custom transports

A browser transport implements `IBrowserTransport`:

```ts
import { createBrowserLogger } from 'logixia/browser';
import type { BrowserLogEntry, IBrowserTransport } from 'logixia/browser';

class AnalyticsTransport implements IBrowserTransport {
  readonly name = 'analytics';
  readonly level = 'warn' as const;

  write(entry: BrowserLogEntry): void {
    console.debug('queued for analytics', entry.message);
  }
}

const logger = createBrowserLogger({ transports: [new AnalyticsTransport()] });
logger.warn('slow render', { ms: 480 });
```

## Cloudflare Workers

Workers forbid timers at global scope and cancel outstanding `fetch` calls when the response returns. Create the transport lazily, set `flushIntervalMs: 0`, and flush inside `ctx.waitUntil`:

```ts
import { BrowserRemoteTransport, createBrowserLogger } from 'logixia/browser';
import type { BrowserLogger } from 'logixia/browser';

interface Env {
  LOG_ENDPOINT?: string;
  LOG_TOKEN?: string;
}

interface WorkerContext {
  waitUntil(promise: Promise<unknown>): void;
}

let remote: BrowserRemoteTransport | undefined;
let base: BrowserLogger | undefined;

function getLogger(env: Env): BrowserLogger {
  if (!base) {
    if (env.LOG_ENDPOINT) {
      remote = new BrowserRemoteTransport({
        url: env.LOG_ENDPOINT,
        flushIntervalMs: 0,
        ...(env.LOG_TOKEN ? { headers: { Authorization: `Bearer ${env.LOG_TOKEN}` } } : {}),
      });
    }
    base = createBrowserLogger({
      appName: 'edge-worker',
      json: true,
      ...(remote ? { transports: [remote] } : {}),
    });
  }
  return base;
}

export default {
  async fetch(request: Request, env: Env, ctx: WorkerContext): Promise<Response> {
    const logger = getLogger(env).child({ requestId: request.headers.get('cf-ray') ?? 'unknown' });
    logger.info('request received', { url: new URL(request.url).pathname });
    if (remote) ctx.waitUntil(remote.flush());
    return new Response('ok');
  },
};
```

With `flushIntervalMs: 0` the buffer survives between requests, so a failed batch is retried by the next request's flush. A complete Worker with delivery-problem reporting is in `examples/cloudflare-worker` in the repository.

Store the token as a secret (`wrangler secret put LOG_TOKEN`), not in `wrangler.toml`.
