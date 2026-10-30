import { BrowserRemoteTransport, createBrowserLogger } from 'logixia/browser';
import type { BrowserLogger } from 'logixia/browser';

interface Env {
  /** Optional: URL that receives batched JSON logs (see wrangler.toml / `wrangler secret`). */
  LOG_ENDPOINT?: string;
  LOG_TOKEN?: string;
}

// Module scope, created lazily on the first request (env is not available earlier).
// With flushIntervalMs: 0 the transport never starts a timer, which Workers forbid at
// global scope, and it keeps its buffer across requests, so a failed batch is retried
// by the next request's flush instead of being lost.
let remote: BrowserRemoteTransport | undefined;
let baseLogger: BrowserLogger | undefined;

function getLogger(env: Env): { logger: BrowserLogger; remote: BrowserRemoteTransport | undefined } {
  if (!baseLogger) {
    if (env.LOG_ENDPOINT) {
      remote = new BrowserRemoteTransport({
        url: env.LOG_ENDPOINT,
        flushIntervalMs: 0,
        ...(env.LOG_TOKEN ? { headers: { Authorization: `Bearer ${env.LOG_TOKEN}` } } : {}),
      });
    }
    baseLogger = createBrowserLogger({
      appName: 'edge-worker',
      json: true, // one JSON line per entry, easy to read in `wrangler tail`
      ...(remote ? { transports: [remote] } : {}),
    });
  }
  return { logger: baseLogger, remote };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
    const base = getLogger(env);
    const logger = base.logger.child({ requestId });

    const { pathname } = new URL(request.url);
    logger.info('request received', { method: request.method, pathname });

    try {
      if (pathname === '/boom') throw new Error('Something broke');
      return Response.json({ ok: true, requestId });
    } catch (error) {
      logger.error('request failed', {
        message: error instanceof Error ? error.message : 'unknown',
      });
      return Response.json({ error: 'Internal Server Error', requestId }, { status: 500 });
    } finally {
      if (base.remote) {
        const transport = base.remote;
        // fetch-based delivery is cancelled when the response returns unless it is kept alive.
        ctx.waitUntil(
          transport.flush().then(() => {
            if (transport.dropped > 0 || transport.failedFlushes > 0) {
              logger.warn('log delivery problems', {
                dropped: transport.dropped,
                failedFlushes: transport.failedFlushes,
              });
            }
          })
        );
      }
    }
  },
};
