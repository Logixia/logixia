/**
 * logixia/fastify — a pino-compatible facade so a logixia logger can be Fastify's `loggerInstance`.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import { createLogger } from 'logixia';
 * import { createFastifyLogger } from 'logixia/fastify';
 *
 * const logger = createLogger({ appName: 'api' });
 * const app = Fastify({ loggerInstance: createFastifyLogger(logger) });
 * ```
 */

export type {
  FastifyLoggerOptions,
  FastifySerializerOptions,
  PinoChildOptions,
  PinoCompatibleLogFn,
  PinoCompatibleLogger,
  PinoLevelName,
  SerializerFn,
} from './fastify/pino-facade';
export { createFastifyLogger, createFastifySerializers } from './fastify/pino-facade';
