# Next.js App Router route handler

`app/api/orders/route.ts` is a single route handler using logixia on the Node.js runtime.

1. `npm install logixia` in your Next.js app.
2. Copy `app/api/orders/route.ts` into your project's `app/api/orders/`.
3. Run `next dev` and call `curl -H 'x-trace-id: abc' 'localhost:3000/api/orders?customerId=42'`. Add `customerId=broken` to see the error path. Log lines print in the dev server output and carry the trace ID.

Notes:

- `export const runtime = 'nodejs'` is required. logixia uses `AsyncLocalStorage` and other Node built-ins, which the Edge runtime does not provide. For Edge, use `logixia/browser`.
- If bundling causes trouble, list the package in `serverExternalPackages` in `next.config.js`: `{ serverExternalPackages: ['logixia'] }`.
- The handler only uses the standard `Request` / `Response` types, so this repo typechecks it (`npm run typecheck:examples`) without depending on `next`.
- JSON output is switched on in production (`format.json`), and `redact` masks `authorization`, `cookie` and `password` fields.
