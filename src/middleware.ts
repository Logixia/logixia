/**
 * logixia/middleware — HTTP request/response logging (Morgan replacement).
 *
 * @example Express
 * ```ts
 * import { createExpressMiddleware } from 'logixia/middleware';
 * import { createLogger } from 'logixia';
 *
 * const logger = createLogger({ appName: 'api' });
 * app.use(createExpressMiddleware(logger, {
 *   skip: (req) => req.url === '/health',
 *   slowRequestThresholdMs: 500,
 * }));
 * ```
 *
 * @example Fastify
 * ```ts
 * import { createFastifyPlugin } from 'logixia/middleware';
 * await fastify.register(createFastifyPlugin(logger));
 * ```
 */

export type {
  FastifyInstance,
  HttpLoggerOptions,
  IncomingRequest,
  OutgoingResponse,
} from './middleware/http-logger';
export { createExpressMiddleware, createFastifyPlugin } from './middleware/http-logger';
