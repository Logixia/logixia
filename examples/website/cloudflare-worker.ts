import { createBrowserLogger } from 'logixia/browser';

const logger = createBrowserLogger({ appName: 'edge-worker', json: true });

export default {
  fetch(request: Request): Response {
    const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
    logger.child({ requestId }).info('request received', { url: request.url });
    return Response.json({ ok: true, requestId });
  },
};
