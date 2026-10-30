/**
 * The code snippets shown on the documentation home page (website/index.md).
 * Kept here so `npm run typecheck:examples` fails if the public API drifts.
 */
import express from 'express';
import Fastify from 'fastify';
import { createExpressContextMiddleware, createFastifyContextHook, createLogger } from 'logixia';
import { createBrowserLogger } from 'logixia/browser';
import { createFastifyPlugin } from 'logixia/middleware';
import { LogixiaLoggerModule } from 'logixia/nest';

// --- Quick start ---------------------------------------------------------
export const logger = createLogger({
  appName: 'api',
  environment: 'production',
  traceId: true,
  redact: { paths: ['**.password', '**.authorization'], autoDetect: true },
  transports: {
    console: { format: 'json' },
    file: { filename: 'app.log', dirname: './logs', maxSize: '50MB', maxFiles: 14 },
  },
});

export async function quickStart(): Promise<void> {
  await logger.info('Order created', { orderId: 'ord_42', password: 'hunter2' });
  // password -> "[REDACTED]", traceId attached, written to console and file
}

// --- Express -------------------------------------------------------------
export function expressApp() {
  const app = express();
  app.use(createExpressContextMiddleware({ responseHeader: 'x-trace-id' }));
  app.get('/orders/:id', async (req, res) => {
    await logger.info('Loading order', { id: req.params.id }); // carries the request trace id
    res.json({ ok: true });
  });
  return app;
}

// --- Fastify -------------------------------------------------------------
export function fastifyApp() {
  const app = Fastify();
  app.addHook('onRequest', createFastifyContextHook());
  void app.register(createFastifyPlugin(logger));
  return app;
}

// --- NestJS --------------------------------------------------------------
export const nestModule = LogixiaLoggerModule.forRoot({
  appName: 'nestjs-api',
  environment: 'production',
  traceId: true,
  transports: { console: {} },
});

// --- Cloudflare Worker ---------------------------------------------------
const edgeLogger = createBrowserLogger({ appName: 'edge-worker', json: true });

export default {
  fetch(request: Request): Response {
    const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
    edgeLogger.child({ requestId }).info('request received', { url: request.url });
    return Response.json({ ok: true, requestId });
  },
};
