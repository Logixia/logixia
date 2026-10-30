// Compiled by `npm run typecheck:consumer` the way an application sees the public
// API: strict + exactOptionalPropertyTypes with real express and fastify types.
import express from 'express';
import Fastify from 'fastify';

import {
  createExpressContextMiddleware,
  createFastifyContextHook,
  createLogger,
  wideEventMiddleware,
} from '../../src';
import { createExpressMiddleware, createFastifyPlugin } from '../../src/middleware';

const logger = createLogger({ appName: 'consumer', environment: 'development' });

const app = express();
app.use(createExpressMiddleware(logger));
app.use(wideEventMiddleware(logger));
app.use(createExpressContextMiddleware());

const fastify = Fastify();
fastify.addHook('onRequest', createFastifyContextHook());
void fastify.register(createFastifyPlugin(logger));

logger.setLevel('debug');
const level: string = logger.getLevel();
logger.setNamespaceLevels({ 'db.*': 'debug', '*': 'info' });
logger.patchNamespaceLevels({ http: 'warn' });
const namespaces: Record<string, string> = logger.getNamespaceLevels();
logger.enableField('traceId');
void logger.flush();
void logger.healthCheck();

const custom = createLogger({
  appName: 'consumer',
  levelOptions: { level: 'info', levels: { error: 0, info: 1, audit: 1 } },
});
custom.setNamespaceLevels({ '*': 'info' });
void custom.audit('ok');

export { level, namespaces };
