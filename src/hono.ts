/**
 * logixia/hono — request logging and trace IDs for Hono on Node, Bun and Cloudflare Workers.
 *
 * Imports only `node:async_hooks` and `node:crypto` (both provided under the Workers
 * `nodejs_compat` flag) and no Node file, network or process APIs.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { createHonoMiddleware } from 'logixia/hono';
 *
 * const app = new Hono();
 * app.use(createHonoMiddleware(logger));
 * ```
 */

export type {
  HonoContextLike,
  HonoLoggerLike,
  HonoMiddlewareOptions,
  HonoNext,
} from './hono/middleware';
export { createHonoMiddleware } from './hono/middleware';
