---
title: Fastify
description: 'Use logixia as the Fastify logger: pass createFastifyLogger() as loggerInstance for request logs, serializers, per-request child loggers and trace IDs.'
order: 7.1
---

# Fastify

Fastify logs through any object shaped like a [pino](https://getpino.io) logger. `logixia/fastify` wraps a logixia logger in that shape, so `fastify.log`, `request.log` and every Fastify plugin write through logixia: with its redaction, transports, sampling and trace IDs.

```ts
import Fastify from 'fastify';
import { createLogger } from 'logixia';
import { createFastifyLogger } from 'logixia/fastify';

const logger = createLogger({
  appName: 'api',
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = Fastify({ loggerInstance: createFastifyLogger(logger) });

app.get('/orders/:id', async (request) => {
  request.log.info({ orderId: 42 }, 'loading order %s', 42);
  return { ok: true };
});

await app.listen({ port: 3000 });
```

Pass it as `loggerInstance`. The `logger` option takes pino options or `true`, and Fastify throws if you give it a logger object there.

It adds no dependency: nothing is imported from `fastify` or `pino`, and the facade satisfies Fastify's `FastifyBaseLogger` type without a cast.

::: tip loggerInstance or the plugin?
`createFastifyLogger()` makes Fastify's own request log (`incoming request`, `request completed`, errors, 404s) go through logixia. [`createFastifyPlugin()`](/guide/http-logging#fastify) adds logixia's own request entries with headers, slow-request warnings and redaction options. Use one of them: with both, every request is logged twice. If you register the plugin, set `disableRequestLogging: true` on Fastify.
:::

## Call shapes

Every level method returns `void` and accepts pino's call shapes. A rejected log call is caught and reported on stderr, never as an unhandled rejection.

| Call                                         | Logged as                                                              |
| -------------------------------------------- | ---------------------------------------------------------------------- |
| `log.info('listening on %d', 3000)`          | Message `listening on 3000`.                                           |
| `log.info({ orderId: 7 }, 'order saved')`    | Message `order saved`, fields in the payload.                          |
| `log.info({ orderId: 7 })`                   | Empty message, fields in the payload.                                  |
| `log.error(err)`                             | Message `err.message`, `error` field with name, message, stack, cause. |
| `log.error(err, 'query %s failed', 'users')` | Message `query users failed`, same `error` field.                      |
| `log.error({ err, orderId: 7 }, 'failed')`   | Message `failed`, `orderId` and the `error` field.                     |

Interpolation supports `%s`, `%d`, `%i`, `%f`, `%j`, `%o`, `%O` and `%%`. Arguments beyond the placeholders are ignored, as in pino.

An `Error` under the `err` key (pino's convention, and what Fastify uses) is logged under `error`, the key `logger.error(err)` uses, so Fastify errors look like the rest of your logs. It goes through logixia's error serialization, so the `cause` chain, `code` and other own properties are kept and your `redact` rules apply to the stack.

## Levels

`level` reads and writes the logger's level, so `app.log.level = 'debug'` works at runtime.

| pino level                                | logixia                                                    |
| ----------------------------------------- | ---------------------------------------------------------- |
| `trace`, `debug`, `info`, `warn`, `error` | The same level.                                            |
| `fatal`                                   | Logged at `error`. Setting `level = 'fatal'` sets `error`. |
| `silent`                                  | Mutes the facade. `log.silent()` is a no-op, as in pino.   |

`levelVal` and `levels` use pino's numeric scale (10 to 60), and `isLevelEnabled(level)` compares against the configured level. A per-route `logLevel` is applied to that route's request logger only; other routes keep their level.

## Serializers

Fastify logs raw requests and replies (`{ req }`, `{ res }`) and relies on serializers to cut them down. The facade ships pino-standard ones, so a socket, header set or body never reaches your logs:

| Field | Serialized to                                                                        |
| ----- | ------------------------------------------------------------------------------------ |
| `req` | `method`, `url`, `hostname`, `remoteAddress`, `remotePort`, `reqId`.                 |
| `res` | `statusCode`.                                                                        |
| `err` | logixia's error serialization (`name`, `message`, `stack`, `cause`, own properties). |

The `req.url` has secret query parameters (`token`, `code`, `password`, `api_key` and the [other defaults](/guide/http-logging#what-is-redacted)) replaced with `[REDACTED]`. Add more with `redactQueryParams`. Replace or add serializers with `serializers`:

```ts
import Fastify from 'fastify';
import { createLogger } from 'logixia';
import { createFastifyLogger, createFastifySerializers } from 'logixia/fastify';

const logger = createLogger({ appName: 'api' });
const defaults = createFastifySerializers({ redactQueryParams: ['session'] });

const app = Fastify({
  loggerInstance: createFastifyLogger(logger, {
    redactQueryParams: ['session'],
    serializers: {
      // Keep the default fields and add the user agent.
      req: (req) => ({
        ...(defaults.req(req) as Record<string, unknown>),
        userAgent: (req as { headers?: Record<string, string> }).headers?.['user-agent'],
      }),
      user: (user) => ({ id: (user as { id: string }).id }),
    },
  }),
});
```

A serializer that throws is replaced by `[serializer failed]` and reported on stderr; the log call still goes through. Fastify merges its own serializers underneath yours, so yours win for `req`, `res` and `err`. Routes can add serializers too (`logSerializers` route option), and they apply to that route only.

## Child loggers

Fastify calls `child({ reqId })` for every request. The facade turns that into `logger.child(context, { reqId })`: the bindings become fields on every entry, nested children add to them, and the child shares the root's transports. It starts no transports and registers nothing for shutdown, so creating one per request does not leak; creating 50,000 of them, each with one log call, left the heap and the shutdown registry unchanged and took about 10 microseconds per child.

Close the logixia logger yourself when the server stops, so buffered transports flush:

```ts
import Fastify from 'fastify';
import { createLogger } from 'logixia';
import { createFastifyLogger } from 'logixia/fastify';

const logger = createLogger({ appName: 'api' });
const app = Fastify({ loggerInstance: createFastifyLogger(logger) });

app.addHook('onClose', async () => {
  await logger.close();
});
```

## Trace IDs

Fastify names a request with `reqId`. logixia has a trace ID, the top-level `traceId` of each entry. To make them one value:

1. Generate `reqId` from the incoming trace header with `genReqId`.
2. Add `createFastifyContextHook()` so code that logs through logixia directly (not through `request.log`) sees the same ID.

```ts
import Fastify from 'fastify';
import {
  createFastifyContextHook,
  createLogger,
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
} from 'logixia';
import { createFastifyLogger } from 'logixia/fastify';

const logger = createLogger({ appName: 'api' });

const app = Fastify({
  loggerInstance: createFastifyLogger(logger),
  genReqId: (req) => extractTraceId(req, { header: DEFAULT_TRACE_HEADERS }) ?? generateTraceId(),
});

app.addHook('onRequest', createFastifyContextHook({ responseHeader: 'x-trace-id' }));
```

With that setup every entry of a request, including Fastify's `incoming request` entry that is written before any hook runs, has `traceId` equal to `reqId`. This works because a request logger whose `reqId` is a usable ID (1 to 128 characters of `[A-Za-z0-9._:-]`) uses it as the trace ID for entries written outside a trace scope. Inside a scope opened by `createFastifyContextHook()` or `runWithTraceId()` the scope's ID wins, and it is the same value here.

Fastify's default IDs (`req-1`, `req-2`) are counters that repeat after every restart, so they are never used as trace IDs. Without `genReqId`, `reqId` stays in the payload as a field, the hook's ID is the `traceId` for handler entries, and Fastify's own first entry carries a different `traceId`. Join on `reqId` in that case.

If you changed Fastify's `requestIdLogLabel`, pass the same name as `traceIdBinding`. Pass `traceIdBinding: false` to never touch trace IDs.

## Options

| Option              | Type                                 | Default   | Description                                                              |
| ------------------- | ------------------------------------ | --------- | ------------------------------------------------------------------------ |
| `serializers`       | `Record<string, (value) => unknown>` | none      | Serializers by field name; replace the defaults for `req`, `res`, `err`. |
| `redactQueryParams` | `string[]`                           | none      | Extra query parameter names redacted from `req.url`.                     |
| `traceIdBinding`    | `string \| false`                    | `'reqId'` | Binding whose value is used as the trace ID. `false` disables it.        |

## A complete server

```ts
import Fastify from 'fastify';
import {
  createFastifyContextHook,
  createLogger,
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
} from 'logixia';
import { createFastifyLogger } from 'logixia/fastify';

const logger = createLogger({
  appName: 'orders-api',
  environment: 'production',
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = Fastify({
  loggerInstance: createFastifyLogger(logger, { redactQueryParams: ['session'] }),
  genReqId: (req) => extractTraceId(req, { header: DEFAULT_TRACE_HEADERS }) ?? generateTraceId(),
});

app.addHook('onRequest', createFastifyContextHook({ responseHeader: 'x-trace-id' }));
app.addHook('onClose', async () => {
  await logger.close();
});

app.get<{ Params: { id: string } }>('/orders/:id', async (request) => {
  const { id } = request.params;
  request.log.info({ orderId: id }, 'loading order');
  // Plain logixia calls inside the request carry the same trace ID.
  await logger.debug('cache miss', { orderId: id });
  return { orderId: id, status: 'shipped' };
});

// A verbose route: only this route's request logger runs at debug.
app.get('/debug', { logLevel: 'debug' }, async (request) => {
  request.log.debug('only logged for this route');
  return 'ok';
});

app.get('/boom', async () => {
  throw new Error('Something broke', { cause: new Error('database unreachable') });
});

await app.listen({ port: 3000 });
```

Requesting `/orders/42?token=abc` with an `x-trace-id: abc-123` header logs `incoming request` with `url: "/orders/42?token=[REDACTED]"`, then your entries, then `request completed` with `res: { statusCode: 200 }` and `responseTime`, all with `traceId: "abc-123"` and `reqId: "abc-123"`. `/boom` logs the thrown error at `error` with its stack and `cause`.
