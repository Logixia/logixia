---
title: 'Structured Logging in TypeScript: Wide Events and Typed Fields'
description: 'A practical guide to structured logging in TypeScript - JSON logs, child loggers, canonical log lines (wide events) and typed log fields, with logixia examples.'
date: 2026-10-26
tags: [typescript, structured-logging, wide-events, json, observability]
---

# Structured Logging in TypeScript: Wide Events and Typed Fields

**TL;DR:** Structured logging in TypeScript means every log entry is a record of named fields, not a sentence you later parse with regexes. Emit JSON, attach context once with child loggers, prefer one rich "wide event" per request over a dozen thin lines, and use the type system to stop field names drifting. logixia supports all four; this article explains the ideas first and then shows the code.

If you have ever tried to answer "how many checkouts failed for the pro plan in the last hour?" by grepping a log file, you already know why. A line like `Payment failed for user 42 (plan=pro)` is readable by a person and almost unreadable by a machine. A record like `{"message":"payment failed","userId":"42","plan":"pro"}` can be filtered, grouped and graphed by any log platform.

## What is structured logging?

Structured logging means each entry has a fixed shape: a timestamp, a level, a message, and a bag of key-value fields. It is usually serialized as one JSON object per line (JSON Lines), because every log platform and shipper understands that.

The practical rules:

- **Keep the message constant.** Use `"payment failed"` and put the variable bits in fields. A constant message groups well; a message with an embedded user ID creates a million distinct strings.
- **One name per concept, everywhere.** `userId` in one service and `user_id` in another doubles your queries. Decide on a convention and enforce it (more on that below).
- **Prefer flat or shallow fields.** Deeply nested objects are harder to index and query.
- **Never build the JSON yourself.** Pass objects to the logger and let it serialize, so circular references and `Error` objects are handled.

## How do I get JSON logs in logixia?

By default the console output is human-readable text. Switch the console transport to JSON for production:

```ts
import { createLogger } from 'logixia';

export const logger = createLogger({
  appName: 'checkout-api',
  environment: 'production',
  transports: { console: { format: 'json', colorize: false } },
});

await logger.info('payment failed', { userId: '42', plan: 'pro', amount: 4900 });
```

That prints a single line like:

```json
{
  "timestamp": "2026-10-30T14:23:14.172Z",
  "level": "info",
  "message": "payment failed",
  "traceId": "f84b86e8-42c7-4a11-80ff-172b96a1fdce",
  "appName": "checkout-api",
  "environment": "production",
  "userId": "42",
  "plan": "pro",
  "amount": 4900
}
```

Your fields are merged at the top level next to the core ones. If a field name collides with a core name (`timestamp`, `level`, `message`, `traceId`, `appName`, `environment`, `context`), the core field wins and yours is kept under a `data_` prefix, for example `data_level`. Avoid those names and you never see it.

Note the `transports` rule: when you pass a `transports` object, only the destinations you list are created, so include `console` explicitly. Errors passed as the first argument are serialized with name, message and stack:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'checkout-api',
  transports: { console: { format: 'json', colorize: false } },
});

await logger.error(new Error('boom'), { orderId: 'o_1' });
```

The [configuration guide](/guide/configuration) covers every option, including level control and `gracefulShutdown`.

## How do I add context to every log line?

There are two mechanisms, and they solve different problems.

**Child loggers** bind context to a _logger instance_. `child(context, data)` returns a logger whose entries carry the context name and any extra fields:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'checkout-api',
  transports: { console: { format: 'json', colorize: false } },
});

const billing = logger.child('billing', { tenant: 'acme' });
await billing.warn('card declined', { code: 'insufficient_funds' });
// {"level":"warn","message":"card declined","context":"billing","tenant":"acme","code":"insufficient_funds",...}
```

Use a child per module or per long-lived component.

**Async context** binds fields to a _unit of work_ without passing a logger around. `LogixiaContext.run` stores fields for the duration of a callback and everything it awaits; any logger call inside merges them in automatically:

```ts
import { createLogger, LogixiaContext } from 'logixia';

const logger = createLogger({
  appName: 'checkout-api',
  transports: { console: { format: 'json', colorize: false } },
});

async function handleJob(jobId: string, tenantId: string) {
  await LogixiaContext.run({ jobId, tenantId }, async () => {
    await logger.info('job started'); // carries jobId and tenantId
    await Promise.all([logger.info('step a'), logger.info('step b')]);
  });
}

await handleJob('j_9', 'acme');
```

Under the hood this is Node's `AsyncLocalStorage`; [the Express article](/articles/express-request-logging-trace-id) explains how it works and how to use it per HTTP request. Rule of thumb: child loggers for _where_ the code lives, async context for _which request or job_ it is serving.

## What is a wide event (canonical log line)?

The usual way to log a request is to scatter lines through the code: "request received", "user loaded", "cart priced", "payment sent", "request done". To debug one failure you must find all the lines and join them by request ID in your head.

A **wide event**, also called a **canonical log line**, is the opposite: one dense record per unit of work, built up as the work proceeds and emitted once at the end, with everything you could want to filter on: route, user, plan, cache hit, number of database queries, status, duration. Stripe popularized the canonical log line; the idea is also central to the "observability 2.0" argument. One record means no joins during an incident, and the wide row is what you group and graph.

logixia has this built in. `withWideEvent` opens a scope, `addEventFields` adds fields from anywhere in the call tree, and the event is emitted exactly once when the callback settles, even if it throws:

```ts
import { addEventFields, createLogger, withWideEvent } from 'logixia';

const logger = createLogger({
  appName: 'checkout-api',
  transports: { console: { format: 'json', colorize: false } },
});

async function priceCart(items: number) {
  addEventFields({ cartItems: items, cacheHit: false });
  return items * 1200;
}

export async function checkout(userId: string) {
  return withWideEvent(
    logger,
    { route: 'POST /checkout', userId },
    async () => {
      const total = await priceCart(3);
      addEventFields({ total, paymentProvider: 'stripe' });
      return { total };
    },
    { message: 'checkout' }
  );
}

await checkout('u_42');
```

You get one `checkout` entry containing `route`, `userId`, `cartItems`, `cacheHit`, `total`, `paymentProvider` and an auto-computed `durationMs`. If the callback throws, the event is still emitted with `error: true` and `errorMessage`, then the error is rethrown. When a trace is active the event also includes `traceId`. `addEventFields` is a safe no-op outside a scope, so library code can call it unconditionally.

For HTTP servers, `wideEventMiddleware(logger)` does the scoping for you and emits on response `finish` or `close`, adding method, URL, IP, `statusCode` and duration:

<!-- snippet-check: skip -->

```ts
import express from 'express';
import { addEventFields, createLogger, wideEventMiddleware } from 'logixia';

const logger = createLogger({
  appName: 'checkout-api',
  transports: { console: { format: 'json', colorize: false } },
});

const app = express();
app.use(wideEventMiddleware(logger, { skip: (req) => req.url === '/health' }));

app.get('/orders/:id', (req, res) => {
  addEventFields({ orderId: req.params.id, source: 'cache' });
  res.json({ ok: true });
});
```

Wide events do not replace all other logging. Keep ad hoc `debug` lines for local development and keep error logs with stack traces; the canonical line is the one you query. For the HTTP-specific alternative that emits start and finish lines, see [HTTP request logging](/guide/http-logging).

## How do I get typed log fields in TypeScript?

`logger.info('x', { userID: '1' })` compiles whether or not anyone ever uses `userID`. `createTypedLogger` constrains the second argument to an interface you define, so typos and wrong types fail at compile time with autocomplete:

```ts
import { createLogger, createTypedLogger, defineLogSchema } from 'logixia';

type OrderFields = {
  orderId: string;
  userId: string;
  amount?: number;
  currency?: string;
};

const schema = defineLogSchema<OrderFields>({
  orderId: { type: 'string', required: true },
  userId: { type: 'string', required: true },
  amount: { type: 'number' },
  currency: { type: 'string' },
});

const base = createLogger({
  appName: 'orders',
  transports: { console: { format: 'json', colorize: false } },
});
export const orderLogger = createTypedLogger<OrderFields>(base, schema);

await orderLogger.info('order created', { orderId: 'o_1', userId: 'u_1', amount: 4900 });
// orderLogger.info('order created', { orderID: 'o_1' }); // compile error: unknown property
```

Be precise about what this guarantees. At compile time, the fields object is a `Partial<OrderFields>`: extra or mistyped properties are rejected, but **omitting** a field is allowed. The `required: true` flag is a **runtime** check: when `NODE_ENV` is not `production`, a missing required field or a wrong type logs a warning to stderr (`[logixia/schema] Required field "orderId" is missing`). In production the validation is skipped so it costs nothing. Think of the schema as a development-time guard rail, not a runtime contract.

Declare the field shape as a `type` alias, as above, not an `interface`: `createTypedLogger` constrains its type parameter to `Record<string, unknown>`, and TypeScript interfaces do not satisfy that constraint (they lack an implicit index signature).

Make one typed logger per domain (orders, payments, auth) so each has a small, focused field list, and keep those interfaces in one shared module so every service names fields the same way.

## Pitfalls

- **High-cardinality fields in the wrong place.** User IDs and trace IDs are fine as log fields; do not use them as metric labels.
- **Logging objects you do not control.** Passing a whole request or an ORM entity can leak secrets and bloat entries. Pick fields explicitly and configure [redaction](/articles/redact-sensitive-data-in-nodejs-logs).
- **Inconsistent units.** Put the unit in the name (`durationMs`, `amountCents`).
- **Reserved names.** Fields called `level`, `message`, `timestamp` or `traceId` get a `data_` prefix in JSON output.
- **Forgetting to await.** Logger methods return promises. Awaiting is the safe default in request handlers and scripts.

## Key takeaways

- Constant messages, named fields, JSON output.
- Child loggers carry _component_ context; `LogixiaContext` carries _request or job_ context.
- A wide event gives you one queryable record per request. `withWideEvent` and `wideEventMiddleware` emit it exactly once.
- `createTypedLogger` catches field typos at compile time; `defineLogSchema` adds dev-time runtime warnings.

## FAQ

**What is structured logging in Node.js?** Logging each event as a record of key-value fields (usually one JSON object per line) instead of free-form text, so logs can be filtered and aggregated by field.

**What is a canonical log line?** A single, wide log record per request or job that accumulates all the relevant fields and is emitted once at the end. logixia calls it a wide event.

**Does logixia validate log fields at runtime?** Only in development, and only as warnings: `defineLogSchema` reports missing required fields and type mismatches when `NODE_ENV` is not `production`. Compile-time checking comes from `createTypedLogger`.

**Should I log JSON in development too?** Many teams use text locally and JSON in production. In logixia that is a one-line switch on the console transport format.
