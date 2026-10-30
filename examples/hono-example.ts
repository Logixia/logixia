/**
 * Hono example (Node.js): per-request context via LogixiaContext.
 *
 * Run:   npm run dev:hono
 * Try:   curl -H 'x-trace-id: abc' localhost:3000/
 *        curl localhost:3000/boom
 */
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createLogger, generateTraceId, LogixiaContext } from 'logixia';

const logger = createLogger({
  appName: 'hono-example',
  environment: 'development',
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = new Hono();

app.use(async (c, next) => {
  const traceId = c.req.header('x-trace-id') || generateTraceId();
  const start = Date.now();
  c.header('x-trace-id', traceId);

  await LogixiaContext.run({ traceId, method: c.req.method, path: c.req.path }, async () => {
    await next();
    await logger.info('request completed', { status: c.res.status, duration: Date.now() - start });
  });
});

app.get('/', async (c) => {
  await logger.info('Handling index', { userId: 'u_42', plan: 'pro' });
  return c.json({ ok: true });
});

app.get('/boom', () => {
  throw new Error('Something broke');
});

app.onError(async (err, c) => {
  await logger.error(err);
  return c.json({ error: 'Internal Server Error' }, 500);
});

const port = Number(process.env['PORT'] ?? 3000);
serve({ fetch: app.fetch, port }, () => logger.info(`Listening on http://localhost:${port}`));
