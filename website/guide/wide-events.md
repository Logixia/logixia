---
title: Wide events
description: Emit one dense canonical log line per request or job with logixia wide events - accumulate fields anywhere in the call tree and log once, even when the handler throws.
order: 13
---

# Wide events

A wide event, also called a canonical log line, is one structured entry per unit of work (usually a request) that holds everything you would want to know about it: who called, what they asked for, which database calls ran, how long it took and how it ended. You build it up as the request flows through your code and emit it once at the end.

## withWideEvent

```ts
import { addEventFields, createLogger, withWideEvent } from 'logixia';

const logger = createLogger({ appName: 'api' });

async function loadPlan(): Promise<string> {
  addEventFields({ dbQueries: 4, cacheHit: false });
  return 'pro';
}

await withWideEvent(logger, { route: '/checkout' }, async () => {
  addEventFields({ userId: 'u_9' });
  const plan = await loadPlan();
  addEventFields({ planTier: plan });
});
```

When the callback settles, one entry is logged at `info` with message `request`. The payload holds the initial fields, everything added with `addEventFields`, `durationMs`, and the active `traceId`. If the callback throws, the entry also gets `error: true` and `errorMessage`, and the error is rethrown.

## Helpers

| Function                    | Description                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------- |
| `addEventFields(fields)`    | Merge fields into the current event. A no-op outside a scope, so it is safe to call anywhere. |
| `setEventField(key, value)` | Set a single field.                                                                           |
| `getEventFields()`          | A copy of the fields so far, or `undefined` outside a scope.                                  |

## Express middleware

`wideEventMiddleware(logger, options)` opens a scope for each request and emits on response `finish` or `close`, exactly once, with `statusCode` and the duration added. It pre-fills `method`, `url` and `ip`.

```ts
import express from 'express';
import { addEventFields, createLogger, wideEventMiddleware } from 'logixia';

const logger = createLogger({ appName: 'api' });
const app = express();

app.use(
  wideEventMiddleware(logger, {
    skip: (req) => req.url === '/health',
    enrich: (req) => ({ userAgent: String(req.headers?.['user-agent'] ?? '') }),
  }) as unknown as express.RequestHandler
);

app.get('/orders', (_req, res) => {
  addEventFields({ handler: 'orders.list' });
  res.json([]);
});
```

## Options

| Option          | Default        | Description                                                   |
| --------------- | -------------- | ------------------------------------------------------------- |
| `level`         | `'info'`       | Level of the emitted event.                                   |
| `message`       | `'request'`    | Message text.                                                 |
| `includeTrace`  | `true`         | Add `traceId` from the active trace context.                  |
| `durationField` | `'durationMs'` | Field name for the duration.                                  |
| `enrich`        | none           | Middleware only: derive more initial fields from the request. |
| `skip`          | none           | Middleware only: skip a request.                              |

`withWideEvent` takes the first four as its fourth argument.

::: warning The URL is logged as received
The middleware records `originalUrl` or `url` verbatim, including the query string, and the request headers are not logged at all. If your query strings can carry tokens, use the [HTTP logging](/guide/http-logging) middleware, which redacts sensitive query parameters, or add a `url` rule to your `redact` patterns. Fields you add are subject to the logger's [`redact`](/guide/redaction) rules.
:::

Pair wide events with [tracing](/guide/tracing) so each event carries the trace ID.
