---
title: Tracing and correlation IDs
description: Propagate trace IDs and correlation IDs through Node.js services with logixia - traceparent parsing, runWithTraceId, LogixiaContext, Express and Fastify helpers, fetch and Kafka.
order: 6
---

# Tracing and correlation IDs

logixia attaches a trace ID to every entry and can carry it across async calls, HTTP hops and message queues. There are two related identifiers:

- the **trace ID**, stored in `TraceContext` and written as the top-level `traceId` of each entry;
- the **correlation ID**, a field in `LogixiaContext` (`correlationId`) that the `logixia/correlation` helpers read, write and forward as the `x-correlation-id` header.

## Where an entry's trace ID comes from

For each log call, in order:

1. the trace ID of the active `TraceContext` scope (`runWithTraceId`, the NestJS middleware, or `LogixiaContext.run({ traceId })`);
2. the `traceId` of an active `LogixiaContext` scope;
3. a UUID generated once per logger instance.

Set `traceId: false` in the logger config to drop the field.

## runWithTraceId

```ts
import { createLogger, generateTraceId, getCurrentTraceId, runWithTraceId } from 'logixia';

const logger = createLogger({ appName: 'worker' });

async function handleJob(jobId: string): Promise<void> {
  await runWithTraceId(
    generateTraceId(),
    async () => {
      await logger.info('job started'); // top-level traceId is set
      console.log(getCurrentTraceId());
    },
    { jobId }
  );
}

await handleJob('job-1');
```

`runWithTraceId(traceId, fn, data?)` runs `fn` in a new async scope. The optional third argument adds extra fields to the scope. `generateTraceId()` returns a UUID v4, and `getCurrentTraceId()` returns the active ID or `undefined`.

::: warning Avoid setTraceId
`setTraceId()` is deprecated. It mutates the current async context and can leak an ID into other in-flight requests. Use `runWithTraceId()`.
:::

## Reading incoming IDs

Request helpers look for an incoming ID in `DEFAULT_TRACE_HEADERS`, in this order:

`traceparent`, `x-trace-id`, `x-request-id`, `x-correlation-id`, `trace-id`.

A W3C `traceparent` header (`00-<32 hex trace id>-<16 hex span id>-<flags>`) is parsed down to its 32-hex trace ID. Other formats are used as they are.

Incoming IDs are untrusted input. logixia accepts only 1 to 128 characters from `[A-Za-z0-9._:-]`; anything else (too long, control characters, newlines) is discarded and a fresh ID is generated. `extractTraceId(request, config)` applies the same validation to the header, query, body and params locations you configure.

## Express and Fastify

`createExpressContextMiddleware()` and `createFastifyContextHook()` open a `LogixiaContext` scope per request with the resolved trace ID. The ID is the first present header, then a usable `request.id`, then a generated UUID. Fastify's default counter IDs (`req-1`, `req-2`) are never used as trace IDs.

```ts
import express from 'express';
import { createExpressContextMiddleware, createLogger } from 'logixia';

const logger = createLogger({ appName: 'api' });
const app = express();

app.use(
  createExpressContextMiddleware({
    traceIdHeader: ['traceparent', 'x-request-id'],
    responseHeader: 'x-trace-id',
    enrich: (req) => ({ tenantId: String(req.headers['x-tenant-id'] ?? 'unknown') }),
  })
);

app.get('/orders', async (_req, res) => {
  await logger.info('listing orders'); // traceId and tenantId included
  res.json({ ok: true });
});
```

```ts
import Fastify from 'fastify';
import { createFastifyContextHook } from 'logixia';

const fastify = Fastify();
fastify.addHook('onRequest', createFastifyContextHook({ responseHeader: 'x-trace-id' }));
```

| Option           | Default                 | Description                                                         |
| ---------------- | ----------------------- | ------------------------------------------------------------------- |
| `traceIdHeader`  | `DEFAULT_TRACE_HEADERS` | A header name or an ordered list of names.                          |
| `responseHeader` | `false`                 | Echo the trace ID on the response under this name.                  |
| `enrich`         | none                    | Return extra fields to store. A `traceId` returned here is ignored. |

The [HTTP logging](/guide/http-logging) middleware resolves its trace ID with the same rules, so the two agree on a request even when registered in either order. For NestJS, see [NestJS](/guide/nestjs).

## Correlation IDs across services

`logixia/correlation` (Node.js only) carries a correlation ID between services.

```ts
import express from 'express';
import { createLogger } from 'logixia';
import {
  childFromRequest,
  correlationFetch,
  correlationMiddleware,
  getCurrentCorrelationId,
} from 'logixia/correlation';

const logger = createLogger({ appName: 'gateway' });
const app = express();

app.use(correlationMiddleware({ trustIncoming: false }) as unknown as express.RequestHandler);

app.get('/checkout', async (req, res) => {
  const log = childFromRequest(req as unknown as Record<string, unknown>, logger);
  await log.info('calling payments', { correlationId: getCurrentCorrelationId() });
  const response = await correlationFetch('https://payments.internal/charge', {
    method: 'POST',
  });
  res.status(response.status).end();
});
```

### Middleware options

`correlationMiddleware(options)` and the Fastify `correlationFastifyHook(options)` share these options:

| Option                | Default               | Description                                                                |
| --------------------- | --------------------- | -------------------------------------------------------------------------- |
| `header`              | `'x-correlation-id'`  | Header to read and write.                                                  |
| `originServiceHeader` | `'x-origin-service'`  | Header naming the calling service (stored as `originService`).             |
| `generate`            | `crypto.randomUUID()` | Create an ID when none arrives.                                            |
| `trustIncoming`       | `true`                | Set `false` at the edge to ignore client-supplied IDs and always generate. |
| `setResponseHeader`   | `true`                | Write the ID to the response so clients can log it.                        |

### Helpers

| Function                                         | Purpose                                                                     |
| ------------------------------------------------ | --------------------------------------------------------------------------- |
| `generateCorrelationId()`                        | A new UUID v4.                                                              |
| `getCurrentCorrelationId()`                      | The ID in the current `LogixiaContext`, or `undefined`.                     |
| `withCorrelationId(id, fn)`                      | Run `fn` with a correlation ID (generated when `id` is `undefined`).        |
| `correlationFetch(input, init?, { header? })`    | `fetch` that adds the current ID as a request header.                       |
| `createCorrelationAxiosInterceptor({ header? })` | Axios request interceptor that adds the same header.                        |
| `childFromRequest(req, logger, options?)`        | A child logger with `correlationId`, `method`, `url`, `userAgent` and `ip`. |
| `extractMessageCorrelationId(message)`           | Read the ID from a Kafka, SQS or AMQP-style message.                        |
| `buildKafkaCorrelationHeaders()`                 | Kafka headers carrying the current correlation ID and trace ID.             |

`childFromRequest` options: `correlationHeader`, `childContext` (context name; defaults to `'request'` for logixia loggers) and `trustProxy`. Leave `trustProxy` off unless a proxy you control overwrites `X-Forwarded-For`; otherwise a client can choose the logged IP.

### Message queues

```ts
import { createLogger } from 'logixia';
import {
  buildKafkaCorrelationHeaders,
  extractMessageCorrelationId,
  withCorrelationId,
} from 'logixia/correlation';

const logger = createLogger({ appName: 'consumer' });

export async function onMessage(message: Record<string, unknown>): Promise<void> {
  const correlationId = extractMessageCorrelationId(message);
  await withCorrelationId(correlationId, async () => {
    await logger.info('message received'); // correlationId is in the payload
    const headers = buildKafkaCorrelationHeaders(); // forward downstream
    console.log(headers);
  });
}
```

Message IDs go through the same validation as HTTP headers.

## Related

- [Child loggers and context](/guide/child-loggers-and-context) for `LogixiaContext`
- [OpenTelemetry](/guide/opentelemetry) to add the active span's IDs to entries
- [Sampling](/guide/sampling) for `traceConsistent` sampling
