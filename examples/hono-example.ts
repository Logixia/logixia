/**
 * Hono example (Node.js): trace ID, response header and request logging via logixia/hono.
 *
 * Run:   npm run dev:hono
 * Try:   curl -H 'x-trace-id: abc' localhost:3000/
 *        curl localhost:3000/boom
 */
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { createLogger } from 'logixia';
import { createHonoMiddleware } from 'logixia/hono';

const logger = createLogger({
  appName: 'hono-example',
  environment: 'development',
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = new Hono<{ Variables: { traceId: string } }>();

// Resolves or generates a trace ID, echoes it as `x-trace-id`, runs the request inside
// that trace scope and logs one "request completed" (or "request failed") entry with
// method, path (secret query params redacted), status and duration.
app.use(createHonoMiddleware(logger, { skip: (c) => c.req.url.endsWith('/health') }));

app.get('/health', (c) => c.text('ok'));

app.get('/', async (c) => {
  await logger.info('Handling index', { userId: 'u_42', plan: 'pro' });
  return c.json({ ok: true });
});

app.get('/boom', () => {
  throw new Error('Something broke');
});

app.get('/forbidden', () => {
  throw new HTTPException(403, { message: 'Forbidden' });
});

// The middleware already logs the failure (error for 5xx, warn for a 403), so the error
// handler only builds the response.
app.onError((err, c) => {
  const status = err instanceof HTTPException ? err.status : 500;
  return c.json({ error: status >= 500 ? 'Internal Server Error' : err.message }, status);
});

const port = Number(process.env['PORT'] ?? 3000);
serve({ fetch: app.fetch, port }, () => logger.info(`Listening on http://localhost:${port}`));
