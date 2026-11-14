/**
 * Fastify example: logixia as Fastify's logger (`loggerInstance`), with the request ID
 * as the trace ID and secret redaction.
 *
 * Run:   npm run dev:fastify
 * Try:   curl -H 'x-trace-id: abc' 'localhost:3000/orders/42?token=secret'
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
import { createFastifyLogger } from 'logixia/fastify';

const logger = createLogger({
  appName: 'fastify-example',
  environment: 'development',
  // Mask secrets in every log entry, whichever field they arrive in.
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

const app = Fastify({
  // Fastify's own logs (incoming request, request completed, errors) go through logixia.
  // Its `req`/`res` serializers keep sockets and headers out, and redact `token` in the URL.
  loggerInstance: createFastifyLogger(logger, { redactQueryParams: ['session'] }),
  // One ID per request: a validated incoming trace header, or a generated one. It is
  // `reqId` on every entry and, with the hook below, the entry's top-level `traceId`.
  genReqId: (req) => extractTraceId(req, { header: DEFAULT_TRACE_HEADERS }) ?? generateTraceId(),
});

// Runs the rest of the request inside a context carrying the trace ID, so plain
// `logger.info()` calls in a handler carry it too.
app.addHook('onRequest', createFastifyContextHook({ responseHeader: 'x-trace-id' }));

// Flush buffered transports when the server stops.
app.addHook('onClose', async () => {
  await logger.close();
});

app.get('/', async () => ({ ok: true }));

app.get<{ Params: { id: string } }>('/orders/:id', async (request) => {
  const { id: orderId } = request.params;
  // User input goes in fields, not the message text, so it can't shape the log line.
  request.log.info({ orderId }, 'loading order');
  await logger.info('Loading order', { orderId });
  return { orderId, status: 'shipped' };
});

// Only this route's request logger runs at debug; other routes keep the configured level.
app.get('/verbose', { logLevel: 'debug' }, async (request) => {
  request.log.debug('visible only on this route');
  return { ok: true };
});

app.get('/boom', async () => {
  throw new Error('Something broke', { cause: new Error('database unreachable') });
});

const port = Number(process.env['PORT'] ?? 3000);
app.listen({ port }).catch((error: unknown) => {
  logger.error(error instanceof Error ? error : new Error(String(error)));
  process.exit(1);
});
