---
title: 'Express Request Logging with a Trace ID (Correlation ID)'
description: 'Log every Express request with a trace ID that follows the request through async code. Covers traceparent, x-request-id, AsyncLocalStorage and logixia.'
date: 2026-10-28
tags: [express, request-id, correlation-id, asynclocalstorage, logging]
---

# Express Request Logging with a Trace ID (Correlation ID)

**TL;DR:** To do Express request logging with a trace ID, assign every request an ID in the first middleware (reuse `traceparent` or `x-request-id` if the caller sent one), store it in `AsyncLocalStorage`, and make your logger read it. Then every log line from that request, however deep in your code, carries the same ID, and you can send it back in a response header and forward it to other services. This article builds the mechanism from scratch so you understand it, then shows the two-line version with logixia.

"Which log lines belong to the failed request?" is the question trace IDs answer. Without one, concurrent requests interleave in your logs and the only link between lines is a timestamp.

## How do I add a request ID to Express logs?

The naive approach is to attach an ID to `req` and pass `req` (or `req.log`) to every function. It works, but it spreads a logging concern through every function signature, and it breaks the moment code runs outside a handler (a queue consumer, a timer, a utility three layers down).

The better approach is to keep the ID in storage bound to the current asynchronous call chain and have the logger look it up. Node ships exactly that: `AsyncLocalStorage`.

### How does AsyncLocalStorage work?

`AsyncLocalStorage` (from `node:async_hooks`) gives you a store that follows the logical flow of asynchronous work. You call `als.run(value, callback)`; inside `callback`, and in everything it awaits, schedules with `setTimeout`, or resolves through promises, `als.getStore()` returns `value`. A different request, running at the same time, has its own store. Here is the whole idea in about twenty lines:

```ts
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import express from 'express';

const als = new AsyncLocalStorage<{ requestId: string }>();
const app = express();

app.use((req, res, next) => {
  const requestId = req.header('x-request-id') ?? randomUUID();
  res.setHeader('x-request-id', requestId);
  als.run({ requestId }, next); // everything downstream runs inside the store
});

function log(message: string) {
  console.log(JSON.stringify({ message, requestId: als.getStore()?.requestId }));
}

async function loadUser() {
  await new Promise((resolve) => setTimeout(resolve, 5));
  log('user loaded'); // no request object in sight, but the ID is still here
}

app.get('/users/:id', async (_req, res) => {
  log('handling request');
  await loadUser();
  res.json({ ok: true });
});
```

That is a working correlation-ID system. A logging library just does the lookup for you on every call, and adds the other things you need: validating incoming IDs, parsing `traceparent`, request/response lines with durations, and shipping to a log backend.

## Which header should carry the trace ID?

| Header             | Format                                          | Notes                                                                            |
| ------------------ | ----------------------------------------------- | -------------------------------------------------------------------------------- |
| `traceparent`      | `00-<32 hex trace id>-<16 hex span id>-<flags>` | W3C Trace Context. Sent by OpenTelemetry and most gateways.                      |
| `x-request-id`     | Any string                                      | De facto standard; many proxies and platforms (Heroku's router, for one) add it. |
| `x-correlation-id` | Any string                                      | Common in enterprise stacks.                                                     |

Pick one convention across services. If you use OpenTelemetry, use `traceparent` so your logs and traces share an ID (see [OpenTelemetry logs in Node.js](/articles/opentelemetry-logs-nodejs)). Whatever you accept, **validate it**: an incoming header is attacker-controlled, and an unvalidated value can inject newlines into text logs or megabytes into your storage.

## How do I do this with logixia?

Install `logixia`. Two pieces work together: the **context middleware** from `logixia` stores the ID in async context, and the **HTTP logger** from `logixia/middleware` writes the request-completed line (a Morgan replacement).

```ts
import express from 'express';
import {
  createExpressContextMiddleware,
  createLogger,
  getCurrentTraceId,
  LogixiaContext,
} from 'logixia';
import { createExpressMiddleware } from 'logixia/middleware';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: { console: { format: 'json', colorize: false } },
});

const app = express();

app.use(createExpressContextMiddleware({ responseHeader: 'x-request-id' }));
app.use(
  createExpressMiddleware(logger, {
    skip: (req) => req.url === '/health',
    slowRequestThresholdMs: 500,
  })
);

async function loadUser(id: string) {
  await new Promise((resolve) => setTimeout(resolve, 5));
  await logger.info('user loaded', { userId: id });
}

app.get('/users/:id', async (req, res) => {
  LogixiaContext.set({ userId: req.params.id }); // add fields for the rest of the request
  await loadUser(req.params.id);
  res.json({ ok: true, traceId: getCurrentTraceId() });
});

app.listen(3000);
```

Calling it with a W3C `traceparent` header produced these two lines (headers trimmed), followed by the response:

```json
{"level":"info","message":"user loaded","traceId":"4bf92f3577b34da6a3ce929d0e0e4736","appName":"api","environment":"production","userId":"7"}
{"level":"info","message":"request completed","traceId":"4bf92f3577b34da6a3ce929d0e0e4736","appName":"api","environment":"production","userId":"7","method":"GET","url":"/users/7?token=[REDACTED]&x=1","ip":"::1","statusCode":200,"duration":9}
```

What happened:

- `createExpressContextMiddleware` resolved the trace ID. It tries these headers in order: `traceparent`, `x-trace-id`, `x-request-id`, `x-correlation-id`, `trace-id`. For `traceparent` it keeps only the 32-hex trace ID. If none is usable it falls back to `req.id` (when it is a real ID, not a framework counter), and otherwise generates a UUID. It then opened an async context and echoed the ID in the `x-request-id` response header, because we asked for it with `responseHeader`. No response header is set by default.
- The deeper function `loadUser` logged without being handed the request, yet carries the ID.
- `LogixiaContext.set` added `userId` to the context, so later lines (including `request completed`) include it.
- The HTTP logger recorded method, URL, status and duration. It redacted the `token` query parameter by default, and it redacts sensitive headers such as `authorization` and `cookie`. Without a `traceparent` the ID is a UUID.

By default the HTTP logger writes a `request started` line at `debug` level and `request completed` at `info`, or `error` for 5xx. Slow requests (over `slowRequestThresholdMs`, default 1000 ms) also get a `warn`. Tune these with `requestLevel`, `responseLevel` and `errorLevel`; see [HTTP request logging](/guide/http-logging) and [tracing](/guide/tracing) for every option.

### Which middleware order is correct?

Context first, then the HTTP logger, then your body parsers and routes. The context middleware must run before anything that logs, so `LogixiaContext.run` wraps the rest of the chain. If you also use `express.json()`, put it after the logger when you want request lines for requests that fail parsing.

### How do I forward the trace ID to other services?

Read it with `getCurrentTraceId()` and put it in an outbound header:

```ts
import { getCurrentTraceId } from 'logixia';

export async function callBilling(orderId: string) {
  const traceId = getCurrentTraceId();
  const res = await fetch(`https://billing.internal/orders/${orderId}`, {
    headers: traceId ? { 'x-request-id': traceId } : {},
  });
  return res.json();
}
```

If both services use logixia, the downstream one picks the ID up from `x-request-id` automatically, and one search finds the request in both logs.

### How do I log errors with the trace ID?

Use a standard Express error handler. Because it runs inside the same async context, the trace ID is attached automatically:

```ts
import type { ErrorRequestHandler } from 'express';
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: { console: { format: 'json', colorize: false } },
});

export const errorHandler: ErrorRequestHandler = async (err, req, res, _next) => {
  await logger.error(err instanceof Error ? err : new Error(String(err)), {
    method: req.method,
    path: req.path,
  });
  res.status(500).json({ error: 'Internal Server Error' });
};
```

Register it last, with `app.use(errorHandler)`. Return a generic body to clients, and expose the trace ID in the response header so a user can quote it.

## Pitfalls

- **Lost context.** `AsyncLocalStorage` follows promises and timers, but can lose the context when a callback is registered outside the request and invoked later: a shared connection pool, a callback-style library with its own queue, or an event emitter listener created at startup. If `getCurrentTraceId()` returns `undefined` somewhere, that is where to look. Check it in a test.
- **Outside a request, you still get an ID.** A log call with no active context gets a stable per-logger fallback ID, so unrelated background logs share one value. Do not read that as a request.
- **Do not use `setTraceId`.** It is deprecated and uses `enterWith`, which can leak an ID between concurrent requests. Use `runWithTraceId` or the context middleware.
- **Trust.** A caller chooses its own ID. That is fine for correlation, not for security decisions. logixia sanitizes incoming IDs to 1 to 128 safe characters.
- **Partial W3C support.** logixia keeps the trace ID from `traceparent` but not the span ID or flags; if you need full span linkage, use the OpenTelemetry SDK for spans.
- **Log PII deliberately.** The HTTP logger records request headers (sensitive ones redacted). Add [redaction](/articles/redact-sensitive-data-in-nodejs-logs) for anything custom.
- **A field called `traceId`.** The ID is also visible to your code as a field; in JSON console output a payload key named `traceId` is renamed `data_traceId`. You will see this duplicate in lines that merge the async context. It is harmless; filter on the top-level `traceId`.

If you use NestJS rather than bare Express, [the NestJS article](/articles/nestjs-logging-with-request-tracing) covers the equivalent module. For the one-event-per-request style, see [structured logging in TypeScript](/articles/structured-logging-typescript).

## Key takeaways

- A trace ID per request plus `AsyncLocalStorage` removes the need to pass loggers or IDs through your code.
- Accept `traceparent` or `x-request-id`, validate it, generate a UUID otherwise, and echo it back.
- With logixia: `createExpressContextMiddleware` for the ID, `createExpressMiddleware` for request lines, `getCurrentTraceId()` for propagation.
- Watch for places where async context can be lost.

## FAQ

**What is a correlation ID?** A unique identifier attached to a request and to every log line it produces, passed along to downstream services, so you can find all related logs with one search. It is the same idea as a trace ID or request ID.

**Should I use `x-request-id` or `traceparent`?** Use `traceparent` if you use OpenTelemetry or your gateway sends it, because logs and traces then share an ID. Use `x-request-id` if your proxy already adds one. logixia reads both.

**Does logixia add the trace ID to every log automatically?** Inside a request wrapped by the context middleware, yes: the logger reads it from async context. Outside a request there is no request ID, only a per-logger fallback.

**Can I replace Morgan with this?** `createExpressMiddleware` from `logixia/middleware` is designed as a Morgan replacement: it logs status code and duration on response finish, and writes structured JSON through your logger instead of a text format.
