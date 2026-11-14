// `logixia/nest` adds `traceId` to Express's Request type (TraceMiddleware sets it).
// The augmentation is appended at build time, so this guards that it still ships.
import express from 'express';
import type {} from 'logixia/nest';

const app = express();
app.get('/', (req, res) => {
  const traceId: string | undefined = req.traceId;
  res.send(traceId ?? '');
});
