---
title: Hono
description: 'Log Hono requests with logixia/hono on Node, Bun and Cloudflare Workers: trace ID per request, response header, completion entry and query redaction.'
order: 7.2
---

# Hono

`createHonoMiddleware()` from `logixia/hono` gives a [Hono](https://hono.dev) app a trace ID per request and one log entry when the request completes. It uses structural types only, so it adds no dependency on `hono` and works with any version.

```ts
import { Hono } from 'hono';
import { createLogger } from 'logixia';
import { createHonoMiddleware } from 'logixia/hono';

const logger = createLogger({ appName: 'api' });

const app = new Hono<{ Variables: { traceId: string } }>();
app.use(createHonoMiddleware(logger));

app.get('/orders/:id', async (c) => {
  await logger.info('loading order', { orderId: c.req.param('id') });
  return c.json({ traceId: c.get('traceId') });
});
```

For each request the middleware:

1. Reads the trace ID from the first present header of `traceparent`, `x-trace-id`, `x-request-id`, `x-correlation-id`, `trace-id` (validated like everywhere else in logixia: [Tracing](/guide/tracing)), or generates a UUID.
2. Sets it on the response as `x-trace-id` and on the context as `c.get('traceId')`.
3. Runs the rest of the request inside `runWithTraceId()`, so logs written through the Node logger in a handler carry it as their `traceId`.
4. Logs one entry when the request completes.

The completion entry is `request completed` with `traceId`, `method`, `path`, `status` and `duration` (milliseconds). `path` includes the query string with secret parameters replaced by `[REDACTED]` (`token`, `code`, `password`, `api_key` and the [other defaults](/guide/http-logging#what-is-redacted)).

| Outcome                                  | Message             | Level   |
| ---------------------------------------- | ------------------- | ------- |
| Response below 500                       | `request completed` | `info`  |
| Response of 500 or above                 | `request completed` | `error` |
| Handler threw, final status 500 or above | `request failed`    | `error` |
| Handler threw, final status below 500    | `request failed`    | `warn`  |

A failed request also has an `error` field with the name, message, stack and `cause` chain, already serialized so it works with any logger. A client error such as `HTTPException(403)` is expected traffic and logs at `warn`.

Hono passes a handler's error to `app.onError()` and then resolves `next()`, so the middleware reads `c.error` instead of relying on a `try`/`catch`. An error that does escape `next()` is logged and rethrown.

## Options

| Option              | Type                             | Default                 | Description                                               |
| ------------------- | -------------------------------- | ----------------------- | --------------------------------------------------------- |
| `skip`              | `(c) => boolean`                 | none                    | Skip tracing and logging, for example for `/health`.      |
| `traceIdHeader`     | `string \| readonly string[]`    | `DEFAULT_TRACE_HEADERS` | Header or ordered list to read the trace ID from.         |
| `responseHeader`    | `string \| false`                | `'x-trace-id'`          | Response header carrying the trace ID. `false` sets none. |
| `redactQueryParams` | `string[]`                       | none                    | Extra query parameter names redacted from `path`.         |
| `extraFields`       | `(c) => Record<string, unknown>` | none                    | Fields added to the entry, for example a tenant ID.       |

A log call that throws or rejects never fails the request.

## Node

```ts
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createLogger } from 'logixia';
import { createHonoMiddleware } from 'logixia/hono';

const logger = createLogger({
  appName: 'hono-node',
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = new Hono();
app.use(createHonoMiddleware(logger, { skip: (c) => c.req.url.endsWith('/health') }));
app.get('/health', (c) => c.text('ok'));
app.get('/', (c) => c.json({ ok: true }));

serve({ fetch: app.fetch, port: 3000 });
```

## Bun

Bun implements `node:async_hooks` and `node:crypto`, so the same code runs there: export the app and Bun serves its `fetch`.

```ts
import { Hono } from 'hono';
import { createLogger } from 'logixia';
import { createHonoMiddleware } from 'logixia/hono';

const logger = createLogger({ appName: 'hono-bun' });

const app = new Hono();
app.use(createHonoMiddleware(logger));
app.get('/', (c) => c.text('hello'));

export default { port: 3000, fetch: app.fetch };
```

## Cloudflare Workers

`logixia/hono` imports only `node:async_hooks` and `node:crypto`, which Workers provide when the `nodejs_compat` compatibility flag is on. Add it to `wrangler.toml`:

```toml
compatibility_date = "2025-01-01"
compatibility_flags = ["nodejs_compat"]
```

The Node logger (`createLogger`) needs Node APIs that Workers do not have, so pass the [browser logger](/guide/browser-and-edge) instead. The middleware accepts it because it only needs `info`, `warn` and `error` methods. Entries from the middleware include `traceId` explicitly, since the browser logger cannot read it from the async context. Use `c.get('traceId')` to put it on your own entries:

```ts
import { Hono } from 'hono';
import { createBrowserLogger } from 'logixia/browser';
import { createHonoMiddleware } from 'logixia/hono';

const logger = createBrowserLogger({ appName: 'edge-api', json: true });

const app = new Hono<{ Variables: { traceId: string } }>();
app.use(createHonoMiddleware(logger));

app.get('/', (c) => {
  logger.child({ traceId: c.get('traceId') }).info('handling index');
  return c.json({ ok: true });
});

export default app;
```

Two Workers behaviours to know. Timers (`Date.now()`) only advance across I/O, so `duration` shows the time spent waiting on `fetch` and storage, not CPU time. And to ship logs off the Worker, create a `BrowserRemoteTransport` and flush it in `ctx.waitUntil()`; [Browser and edge runtimes](/guide/browser-and-edge#cloudflare-workers) has the full pattern.

Importing `logixia/hono` does not load the Node logger, file transports or any other Node API, and the built file is checked in CI inside a sandbox that has only those two modules.
