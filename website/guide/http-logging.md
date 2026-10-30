---
title: HTTP request logging
description: 'Log Express and Fastify requests with logixia/middleware: start and finish entries, slow request warnings, header and query redaction and trace IDs.'
order: 7
---

# HTTP request logging

`logixia/middleware` logs each HTTP request: one entry when it starts, one when it completes with status and duration, and a warning when it is slow. It is a drop-in replacement for Morgan that writes structured entries through your logger.

## Express

```ts
import express from 'express';
import { createLogger } from 'logixia';
import { createExpressMiddleware } from 'logixia/middleware';

const logger = createLogger({ appName: 'api', levelOptions: { level: 'debug' } });
const app = express();

const httpLogger = createExpressMiddleware(logger, {
  skip: (req) => req.url === '/health',
  slowRequestThresholdMs: 500,
  redactHeaders: ['x-session-id'],
  redactQueryParams: ['invite'],
});

app.use(httpLogger as unknown as express.RequestHandler);
```

::: tip Typing with Express
The middleware is typed against minimal structural request and response shapes, which Express's own `RequestHandler` type does not accept directly. The `as unknown as express.RequestHandler` cast above is a type-only workaround; the runtime behaviour is unaffected. Plain JavaScript needs nothing.
:::

The middleware logs:

| Message                 | Level (default)            | When                                            |
| ----------------------- | -------------------------- | ----------------------------------------------- |
| `request started`       | `debug`                    | The request arrives.                            |
| `request completed`     | `info`, or `error` for 5xx | The response finishes or the connection closes. |
| `slow request detected` | `warn`                     | Duration exceeds `slowRequestThresholdMs`.      |

Completion is logged once even though both `finish` and `close` fire. Because the start entry is at `debug`, you will not see it at the default `info` level.

Each entry has `traceId`, `method`, `url`, `ip` and `headers`. The completion entry adds `statusCode` and `duration` (milliseconds).

## Fastify

```ts
import Fastify from 'fastify';
import { createLogger } from 'logixia';
import { createFastifyPlugin } from 'logixia/middleware';

const logger = createLogger({ appName: 'api' });
const fastify = Fastify();

await fastify.register(createFastifyPlugin(logger, { slowRequestThresholdMs: 500 }));
```

The plugin uses the `onRequest` and `onResponse` hooks and is registered without Fastify's encapsulation, so it applies to every route. It supports the same options as the Express middleware except body logging: `logBody` and `bodyMaxBytes` are Express only.

## Options

| Option                   | Type                               | Default                 | Description                                                                   |
| ------------------------ | ---------------------------------- | ----------------------- | ----------------------------------------------------------------------------- |
| `skip`                   | `(req) => boolean`                 | none                    | Skip logging a request, for example health checks.                            |
| `logBody`                | `boolean`                          | `false`                 | Include the request body in the start entry (Express only).                   |
| `bodyMaxBytes`           | `number`                           | `4096`                  | Cap for the captured body, measured in characters for strings (Express only). |
| `slowRequestThresholdMs` | `number`                           | `1000`                  | Emit a `warn` when a request takes longer than this.                          |
| `extraFields`            | `(req) => Record<string, unknown>` | none                    | Fields added to every entry, for example a tenant ID.                         |
| `traceIdHeader`          | `string \| readonly string[]`      | `DEFAULT_TRACE_HEADERS` | Header or ordered list to read the trace ID from.                             |
| `redactHeaders`          | `string[]`                         | none                    | Extra header names to redact, merged with the defaults.                       |
| `redactQueryParams`      | `string[]`                         | none                    | Extra query parameter names to redact, merged with the defaults.              |
| `requestLevel`           | `string`                           | `'debug'`               | Level for request-start entries; `'silent'` turns them off.                   |
| `responseLevel`          | `string`                           | `'info'`                | Level for completed requests.                                                 |
| `errorLevel`             | `string`                           | `'error'`               | Level for responses with status 500 or above.                                 |

## What is redacted

Header values listed below are replaced with `[REDACTED]` (case-insensitive). Your `redactHeaders` are added to this list:

`authorization`, `cookie`, `set-cookie`, `x-api-key`, `proxy-authorization`, `x-auth-token`, `x-access-token`, `x-csrf-token`, `x-amz-security-token`.

In the logged URL, the values of these query parameters are replaced with `[REDACTED]` (names are matched case-insensitively, and `name[]` style keys are recognised). Your `redactQueryParams` are added:

`token`, `access_token`, `refresh_token`, `code`, `password`, `secret`, `api_key`, `apikey`, `key`, `signature`, `sig`, `auth`.

When `logBody` is on, the body is passed through your logger's [`redact`](/guide/redaction) rules. Oversized bodies are pruned structurally (extra keys dropped, long strings cut and marked `…[truncated]`) rather than turned into a string first, so path rules such as `*.password` still match.

::: warning Body logging
Leave `logBody` off unless you need it, and configure `redact` on the logger when you turn it on. Request bodies often hold credentials and personal data.
:::

## Trace IDs

The middleware resolves the trace ID the same way as the [context helpers](/guide/tracing): the first present header in `traceIdHeader`, then a non-counter `request.id`, then a generated UUID that is shared with the other helpers for that request. The entry's `traceId` field carries it. The middleware does not open a `LogixiaContext` scope itself; combine it with `createExpressContextMiddleware()` or `createFastifyContextHook()` when you want other logs inside the handler to carry the same ID.

```ts
import express from 'express';
import { createLogger, createExpressContextMiddleware } from 'logixia';
import { createExpressMiddleware } from 'logixia/middleware';

const logger = createLogger({ appName: 'api' });
const app = express();

app.use(createExpressContextMiddleware({ responseHeader: 'x-trace-id' }));
app.use(createExpressMiddleware(logger) as unknown as express.RequestHandler);
```

## Wide events instead

If you prefer one dense entry per request over start and finish entries, see [Wide events](/guide/wide-events).
