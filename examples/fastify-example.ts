/**
 * Fastify example: request logging, per-request trace ID and secret redaction.
 *
 * Run:   npm run dev:fastify
 * Try:   curl -H 'x-trace-id: abc' localhost:3000/orders/42
 *        curl localhost:3000/boom
 */
import Fastify from 'fastify';
import { createFastifyContextHook, createLogger, generateTraceId } from 'logixia';
import { createFastifyPlugin } from 'logixia/middleware';

const logger = createLogger({
  appName: 'fastify-example',
  environment: 'development',
  // Mask secrets in every log entry, whichever field they arrive in.
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = Fastify({
  // One ID per request: the caller's x-trace-id, or a generated one.
  genReqId: (req) => {
    const incoming = req.headers['x-trace-id'];
    return typeof incoming === 'string' && incoming !== '' ? incoming : generateTraceId();
  },
});

// Puts { traceId } in async context, so every logger call in a handler carries it.
const contextHook = createFastifyContextHook();
app.addHook('onRequest', (request, reply, done) =>
  contextHook(request as unknown as Record<string, unknown>, reply, done)
);

// Logs "request started" / "request completed" with status and duration.
// Authorization, Cookie and similar headers are redacted by default.
void app.register(
  createFastifyPlugin(logger, {
    redactHeaders: ['x-session'],
    redactQueryParams: ['session'],
    extraFields: (req) => ({ traceId: (req as { id?: string }).id }),
  })
);

app.get('/', async () => ({ ok: true }));

app.get<{ Params: { id: string } }>('/orders/:id', async (request) => {
  const { id: orderId } = request.params;
  await logger.info('Loading order', { orderId });
  return { orderId, status: 'shipped' };
});

app.get('/boom', async () => {
  throw new Error('Something broke');
});

app.setErrorHandler(async (error, _request, reply) => {
  await logger.error(error instanceof Error ? error : new Error(String(error)));
  return reply.status(500).send({ error: 'Internal Server Error' });
});

const port = Number(process.env['PORT'] ?? 3000);
app.listen({ port }).then(() => logger.info(`Listening on http://localhost:${port}`));
