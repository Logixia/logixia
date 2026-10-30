// ESM consumer: resolves the `import` conditions of the exports map to dist/*.d.mts.
import { createLogger, wideEventMiddleware } from 'logixia';
import { createExpressMiddleware } from 'logixia/middleware';

const logger = createLogger({ appName: 'esm-consumer' });
logger.setNamespaceLevels({ '*': 'info' });

export const middleware = [createExpressMiddleware(logger), wideEventMiddleware(logger)];
