/**
 * Hono example (Node.js): per-request trace ID via runWithTraceId.
 *
 * Run:   npm run dev:hono
 * Try:   curl -H 'x-trace-id: abc' localhost:3000/
 *        curl localhost:3000/boom
 */
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import {
  createLogger,
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
  runWithTraceId,
} from 'logixia';

const logger = createLogger({
  appName: 'hono-example',
  environment: 'development',
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = new Hono();

app.use(async (c, next) => {
  // Header names from c.req.header() are lower-cased, which is what extractTraceId expects.
  const traceId =
    extractTraceId({ headers: c.req.header() }, { header: DEFAULT_TRACE_HEADERS }) ??
    generateTraceId();
  const start = Date.now();
  c.header('x-trace-id', traceId);

  await runWithTraceId(traceId, async () => {
    await next();
    await logger.info('request completed', {
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      duration: Date.now() - start,
    });
  });
});

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

app.onError(async (err, c) => {
  const status = err instanceof HTTPException ? err.status : 500;
  // Client errors (4xx) are expected traffic; only 5xx are actual failures.
  if (status >= 500) await logger.error(err);
  else await logger.warn(err.message, { status });
  return c.json({ error: status >= 500 ? 'Internal Server Error' : err.message }, status);
});

const port = Number(process.env['PORT'] ?? 3000);
serve({ fetch: app.fetch, port }, () => logger.info(`Listening on http://localhost:${port}`));
