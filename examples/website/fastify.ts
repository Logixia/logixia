import Fastify from 'fastify';
import { createLogger, createFastifyContextHook } from 'logixia';
import { createFastifyPlugin } from 'logixia/middleware';

const logger = createLogger({ appName: 'api', traceId: true });
const app = Fastify();
app.addHook('onRequest', createFastifyContextHook());
app.register(createFastifyPlugin(logger)); // logs request start and completion
