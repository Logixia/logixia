# Cloudflare Worker with `logixia/browser`

A Worker that logs structured JSON with `logixia/browser` and optionally ships batches to a remote endpoint.

```bash
cd examples/cloudflare-worker
npm install
npx wrangler dev
curl localhost:8787/        # one JSON log line per request in the wrangler output
curl localhost:8787/boom    # error path
```

To ship logs, set `LOG_ENDPOINT` under `[vars]` in `wrangler.toml` (and optionally `npx wrangler secret put LOG_TOKEN`).

Things the example gets right:

- **No timers at global scope.** Workers reject `setInterval` outside a request handler, and `BrowserRemoteTransport` normally starts one in its constructor. The transport is created inside `fetch()` with `flushIntervalMs: 0`, so no timer is ever started.
- **Flush with `ctx.waitUntil`.** A `fetch` started after the response returns is cancelled, so `ctx.waitUntil(remote.flush())` keeps the Worker alive until the batch is delivered.
- **Per-request context.** `logger.child({ requestId })` adds the request ID to every line.
- Only `logixia/browser` is imported; it has no Node built-ins and no `AsyncLocalStorage`.

The browser logger has no redaction, so do not log headers or bodies that may hold secrets.

Typecheck from the repo root: `npm run typecheck:examples` (`worker-types.d.ts` stands in for `@cloudflare/workers-types`, which you should install in a real project).
