---
title: Child loggers and context
description: Attach request IDs and user IDs to every log entry with logixia child loggers and AsyncLocalStorage-based LogixiaContext, without passing fields around.
order: 5
---

# Child loggers and context

There are two ways to attach fields to log entries: bind them to a logger with `child()`, or store them in an async context with `LogixiaContext` so every logger picks them up automatically.

## Child loggers

`logger.child(context, data?)` returns a new logger that shares the parent's configuration, transports, sampler and plugins. `context` becomes the entry's `context` label and the namespace used for [per-namespace levels](/guide/log-levels). `data` is merged into every entry the child writes.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({ appName: 'shop' });

const checkout = logger.child('Checkout', { requestId: 'r-42' });
await checkout.info('started'); // payload includes requestId

const payment = checkout.child('Payment', { provider: 'stripe' });
await payment.info('charged'); // requestId and provider, context 'Payment'
```

Things to know:

- A child inherits the parent's bound fields, and fields passed to a nested child are added on top.
- The context is replaced, not appended: the `Payment` logger above has context `Payment`, not `Checkout.Payment`.
- Closing a child does not close the shared transports; only the root logger closes them.
- A child's `setLevel()` affects that child only.

`setContext(name)` and `getContext()` read and change the context label of an existing logger.

## LogixiaContext

`LogixiaContext` stores fields in `AsyncLocalStorage`. Inside `run()`, every log call made by any logger, in any function called from there (including after `await`, in `Promise.all` and in timers), merges those fields into its payload.

```ts
import { createLogger, LogixiaContext } from 'logixia';

const logger = createLogger({ appName: 'shop' });

async function processOrder(orderId: string): Promise<void> {
  await logger.info('processing', { orderId }); // also carries requestId and userId
}

await LogixiaContext.run({ requestId: 'req-1', userId: 'u-9' }, async () => {
  await processOrder('ord_1');
});
```

| Method                 | Description                                                                               |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `run(store, callback)` | Run `callback` with `store` merged over any outer context. Returns the callback's result. |
| `get()`                | The current fields, or `undefined` outside any `run()`.                                   |
| `set(fields)`          | Merge fields into the current scope. A no-op outside `run()`.                             |
| `getStorage()`         | The underlying `AsyncLocalStorage`, for advanced use.                                     |

`LogContext` is the field type: `traceId`, `spanId`, `userId`, `tenantId`, `sessionId`, plus any other keys.

Payload fields passed to a log call win over context fields with the same name.

::: tip Setting a traceId
If the store contains a string `traceId`, `run()` also makes it the current trace ID, so `getCurrentTraceId()` and the logger's top-level `traceId` agree. See [Tracing](/guide/tracing).
:::

## Request middleware helpers

Two helpers open a context per request and fill it with a trace ID:

```ts
import express from 'express';
import { createExpressContextMiddleware } from 'logixia';

const app = express();

app.use(
  createExpressContextMiddleware({
    enrich: (req) => ({ userId: String(req.headers['x-user-id'] ?? '') }),
    responseHeader: 'x-trace-id',
  })
);
```

`createFastifyContextHook()` is the Fastify equivalent for `addHook('onRequest', ...)`. Both are described in [Tracing](/guide/tracing). For correlation IDs that travel between services, see `withCorrelationId()` and friends there too.

## Which one to use

| Need                                               | Use                     |
| -------------------------------------------------- | ----------------------- |
| A label for a module or class (`OrderService`)     | `child('OrderService')` |
| Fields known when you create the logger            | `child(ctx, data)`      |
| Fields that belong to one request or job, set once | `LogixiaContext.run()`  |
| Add a field mid-request                            | `LogixiaContext.set()`  |
