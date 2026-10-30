---
title: 'Logging in Cloudflare Workers: Structured Logs and ctx.waitUntil'
description: 'Structured logging in Cloudflare Workers: JSON console logs, per-request context, and flushing batched logs with ctx.waitUntil, using logixia/browser.'
date: 2026-10-30
tags: [cloudflare-workers, edge, logging, serverless]
---

# Logging in Cloudflare Workers: Structured Logs and ctx.waitUntil

**TL;DR:** Logging in Cloudflare Workers is different from logging in a Node server, because a Worker has no long-lived process, no filesystem and no background timers at global scope. Write one JSON line per event with `console`, attach a request ID to every line, and if you ship logs to a remote endpoint, flush with `ctx.waitUntil()` so delivery is not cancelled when the response returns. logixia's `logixia/browser` entry works on Workers because it has no Node built-ins; this article shows a full Worker built on it.

Most Node logging libraries assume things a Worker does not offer: `fs` for files, `process.on('SIGTERM')` for a final flush, and a process that lives long enough for a `setInterval` to fire. Using one of them unmodified either fails to bundle or silently loses logs. This is the general shape of the problem on any edge runtime, not just Cloudflare.

## What is different about logging at the edge?

- **Request-scoped lifetime.** There is no "shutdown" to hook. When your handler returns a response, the runtime may stop executing your code, including a `fetch` you started but did not await.
- **No files, no processes.** File and database transports do not apply. Output goes to the runtime's log stream (`wrangler tail`, Workers Logs, a Logpush destination) or to an HTTP endpoint you call.
- **Timers are restricted.** A `setInterval` at module scope is rejected by the Workers runtime, so a transport that starts a flush timer in its constructor breaks at startup.
- **State may be shared across requests, or not.** Module-scope variables persist while an isolate stays warm, but you cannot rely on that. A buffer in module scope is a best-effort cache, never storage.
- **Secrets live in `env`.** Bindings and secrets arrive per request through the `env` argument, not through `process.env`, so a logger that needs a token has to be created lazily.

## What does `console.log` give you, and when is that enough?

On Workers, `console.log` output is collected by the platform and viewable live with `wrangler tail` or in the dashboard's logs. If you emit **one JSON object per line**, you get structured, filterable logs with no extra moving parts. For many Workers that is the whole answer: log JSON to the console and let the platform handle collection.

You need an explicit remote transport only when you want logs delivered to a system the platform does not feed for you, such as your own ingest API or a log vendor with an HTTP endpoint.

## How do I do structured logging in a Worker with logixia?

Import from `logixia/browser`. It has no Node built-ins, no `AsyncLocalStorage` and no file access, so it bundles for Workers, browsers and other edge runtimes. Its logger is synchronous and fire-and-forget:

```ts
import { createBrowserLogger } from 'logixia/browser';

const logger = createBrowserLogger({
  appName: 'edge-api',
  level: 'info',
  json: true, // one JSON line per entry
});

logger.info('request received', { method: 'GET', path: '/orders' });
logger.error('upstream failed', { status: 502 });
```

Levels are `verbose`, `debug`, `info`, `warn`, `error` and `critical`. Each call builds an entry of `{ timestamp, level, appName, message, payload }` and writes it to every transport. The built-in console transport prints it as JSON when `json: true`.

To attach a request ID to every line from one request, use `child`, which on the browser logger takes an object of context fields:

```ts
import { createBrowserLogger } from 'logixia/browser';

const base = createBrowserLogger({ appName: 'edge-api', json: true });

export function requestLogger(request: Request) {
  const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
  return base.child({ requestId });
}
```

There is no `AsyncLocalStorage`-based automatic context on this entry point, so you pass the child logger down explicitly. That is the honest trade-off of running on the edge: a little more plumbing in exchange for a runtime-neutral logger. If you want the automatic version on Node, see [request tracing in Express](/articles/express-request-logging-trace-id).

## How do I ship Worker logs to a remote endpoint?

Add `BrowserRemoteTransport`. It buffers entries and POSTs them as a JSON array to a URL you control. Three details matter on Workers:

1. **Create it lazily.** `env` is not available at module scope, so build the transport on the first request.
2. **Set `flushIntervalMs: 0`.** That disables the internal timer, so nothing calls `setInterval` at global scope. Flushing becomes manual (or size-triggered).
3. **Flush inside `ctx.waitUntil()`.** This tells the runtime to keep the Worker alive until the promise settles, so the POST is not cancelled when the response is sent.

Here is a complete Worker:

```ts
import { BrowserRemoteTransport, createBrowserLogger } from 'logixia/browser';
import type { BrowserLogger } from 'logixia/browser';

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

interface Env {
  LOG_ENDPOINT?: string;
  LOG_TOKEN?: string;
}

let remote: BrowserRemoteTransport | undefined;
let baseLogger: BrowserLogger | undefined;

function getLogger(env: Env) {
  if (!baseLogger) {
    if (env.LOG_ENDPOINT) {
      remote = new BrowserRemoteTransport({
        url: env.LOG_ENDPOINT,
        flushIntervalMs: 0,
        ...(env.LOG_TOKEN ? { headers: { Authorization: `Bearer ${env.LOG_TOKEN}` } } : {}),
      });
    }
    baseLogger = createBrowserLogger({
      appName: 'edge-api',
      json: true,
      ...(remote ? { transports: [remote] } : {}),
    });
  }
  return { logger: baseLogger, remote };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { logger: base, remote: transport } = getLogger(env);
    const logger = base.child({ requestId: request.headers.get('cf-ray') ?? crypto.randomUUID() });

    try {
      logger.info('request received', {
        method: request.method,
        path: new URL(request.url).pathname,
      });
      return Response.json({ ok: true });
    } catch (error) {
      logger.error('request failed', {
        message: error instanceof Error ? error.message : 'unknown',
      });
      return Response.json({ error: 'Internal Server Error' }, { status: 500 });
    } finally {
      if (transport) ctx.waitUntil(transport.flush());
    }
  },
};
```

In a real project, import `ExecutionContext` from `@cloudflare/workers-types` instead of declaring it, and set `LOG_ENDPOINT` under `[vars]` in `wrangler.toml` and `LOG_TOKEN` with `npx wrangler secret put LOG_TOKEN`. The repository ships a runnable version of this in `examples/cloudflare-worker`.

### What does the remote transport do when delivery fails?

- A network error or an HTTP 5xx or 429 puts the batch back in the buffer, so the **next request's flush** retries it. That only helps while the isolate stays warm; do not treat the buffer as durable.
- Any other 4xx is treated as permanent: the batch is dropped and counted.
- The buffer is capped (`maxBufferSize`, default `1000`); when full the oldest entries are dropped and counted.
- `transport.dropped` and `transport.failedFlushes` expose the counters, and an `onError` callback fires on each failed flush. Check them after flushing, as the example in the repository does, and route problems somewhere other than the same transport (writes made to the transport from inside `onError` are dropped, to prevent a feedback loop).
- The URL is validated: it must be `http:` or `https:` (or a same-origin relative path), and the transport keeps URL and headers out of its own error text.
- If a runtime rejects the `keepalive` fetch option, the transport detects that and retries the batch without it.

Your endpoint receives a JSON array of entries shaped like `{ "timestamp", "level", "appName", "message", "payload" }`, so it must accept an array body.

## Pitfalls

- **Batch size and un-awaited flushes.** When the buffer reaches `batchSize` (default `100`), `write()` starts a flush that nobody awaits. On a Worker that promise can be cancelled with the response. Raise `batchSize` above what one request logs, and always finish with a `ctx.waitUntil(transport.flush())`.
- **No redaction on this entry point.** The browser logger has no `redact` option. Do not log request headers, cookies or bodies, and strip secrets yourself before logging. The [redaction article](/articles/redact-sensitive-data-in-nodejs-logs) explains what to look out for.
- **Module state is not a database.** The buffer survives only as long as the isolate does.
- **Don't import the Node entry.** `import { createLogger } from 'logixia'` pulls in Node modules. Use `logixia/browser` on the edge; the [browser and edge guide](/guide/browser-and-edge) lists what is available.
- **Log volume costs money and CPU.** A subrequest per log line is expensive. Batch, and set `level: 'warn'` on the remote transport if you only need problems shipped (the console keeps everything).

## Key takeaways

- On Workers, JSON on `console` is a complete logging solution for many apps.
- For remote delivery, create the transport lazily, disable the timer with `flushIntervalMs: 0`, and flush in `ctx.waitUntil()`.
- Pass a `child({ requestId })` logger through your handlers; there is no automatic async context on this entry point.
- There is no redaction in `logixia/browser`; keep secrets out of log calls.

## FAQ

**How do I log in Cloudflare Workers?** Write one JSON object per line with `console.log` (or a logger such as `logixia/browser` with `json: true`) and read it with `wrangler tail` or the dashboard. Add a remote transport only if you need logs delivered elsewhere.

**Why are my Worker logs missing when I send them with `fetch`?** The runtime can cancel work that is still running after the response is returned. Wrap the send in `ctx.waitUntil(...)`.

**Can I use `setInterval` to flush logs in a Worker?** Not at global scope; the runtime rejects it. Disable the transport's timer with `flushIntervalMs: 0` and flush per request.

**Does logixia work on Deno, Vercel Edge and other runtimes?** `logixia/browser` has no Node built-ins and is designed for edge runtimes generally. The Cloudflare example in the repository is the one that is exercised end to end.
