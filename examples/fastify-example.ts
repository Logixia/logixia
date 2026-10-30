/**
 * Fastify example: request logging, per-request trace ID and secret redaction.
 *
 * Run:   npm run dev:fastify
 * Try:   curl -H 'x-trace-id: abc' localhost:3000/orders/42
 *        curl localhost:3000/boom
 */
import Fastify from 'fastify';
import {
  createFastifyContextHook,
  createLogger,
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
} from 'logixia';
import { createFastifyPlugin } from 'logixia/middleware';

const logger = createLogger({
  appName: 'fastify-example',
  environment: 'development',
  // Mask secrets in every log entry, whichever field they arrive in.
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = Fastify({
  // One ID per request: a validated incoming trace header, or a generated one.
  genReqId: (req) => extractTraceId(req, { header: DEFAULT_TRACE_HEADERS }) ?? generateTraceId(),
});

// Runs the rest of the request inside a context carrying the trace ID, so every
// logger call in a handler carries it as its top-level traceId.
app.addHook('onRequest', createFastifyContextHook());

// Logs "request started" / "request completed" with status and duration.
// Authorization, Cookie and similar headers are redacted by default.
void app.register(
  createFastifyPlugin(logger, {
    redactHeaders: ['x-session'],
    redactQueryParams: ['session'],
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

app.setErrorHandler(async (error: Error & { statusCode?: number }, _request, reply) => {
  const statusCode = error.statusCode ?? 500;
  // Client errors (4xx) are expected traffic; only 5xx are actual failures.
  if (statusCode >= 500) await logger.error(error);
  else await logger.warn(error.message, { statusCode });
  return reply
    .status(statusCode)
    .send({ error: statusCode >= 500 ? 'Internal Server Error' : error.message });
});

const port = Number(process.env['PORT'] ?? 3000);
app.listen({ port }).then(() => logger.info(`Listening on http://localhost:${port}`));
