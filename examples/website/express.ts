import express from 'express';
import { createLogger, createExpressContextMiddleware } from 'logixia';

const logger = createLogger({ appName: 'api', traceId: true });
const app = express();

app.use(createExpressContextMiddleware({ responseHeader: 'x-trace-id' }));

app.get('/orders/:id', async (req, res) => {
  await logger.info('Loading order', { id: req.params.id }); // carries the request trace id
  res.json({ ok: true });
});
