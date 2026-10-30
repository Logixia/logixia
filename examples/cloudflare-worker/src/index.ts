import { BrowserRemoteTransport, createBrowserLogger } from 'logixia/browser';

interface Env {
  /** Optional: URL that receives batched JSON logs (see wrangler.toml / `wrangler secret`). */
  LOG_ENDPOINT?: string;
  LOG_TOKEN?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Created per request: Workers forbid timers at global scope, and with
    // flushIntervalMs: 0 the transport never starts one.
    const remote = env.LOG_ENDPOINT
      ? new BrowserRemoteTransport({
          url: env.LOG_ENDPOINT,
          flushIntervalMs: 0,
          ...(env.LOG_TOKEN ? { headers: { Authorization: `Bearer ${env.LOG_TOKEN}` } } : {}),
        })
      : undefined;

    const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
    const logger = createBrowserLogger({
      appName: 'edge-worker',
      json: true, // one JSON line per entry, easy to read in `wrangler tail`
      ...(remote ? { transports: [remote] } : {}),
    }).child({ requestId });

    const { pathname } = new URL(request.url);
    logger.info('request received', { method: request.method, pathname });

    try {
      if (pathname === '/boom') throw new Error('Something broke');
      return Response.json({ ok: true, requestId });
    } catch (error) {
      logger.error('request failed', { message: error instanceof Error ? error.message : 'unknown' });
      return Response.json({ error: 'Internal Server Error', requestId }, { status: 500 });
    } finally {
      // fetch-based delivery is dropped when the response returns unless it is kept alive.
      if (remote) ctx.waitUntil(remote.flush());
    }
  },
};
