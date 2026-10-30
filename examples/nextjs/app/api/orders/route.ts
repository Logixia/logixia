import {
  createLogger,
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
  runWithTraceId,
} from 'logixia';

// logixia uses AsyncLocalStorage and Node built-ins, so this route must not run on the Edge runtime.
export const runtime = 'nodejs';

// Module level: created once per server process and reused across requests.
const logger = createLogger({
  appName: 'orders-api',
  environment: process.env['NODE_ENV'] === 'production' ? 'production' : 'development',
  format: { json: process.env['NODE_ENV'] === 'production' },
  redact: { paths: ['**.authorization', '**.cookie', '**.password'] },
});

async function loadOrders(customerId: string | null) {
  if (customerId === 'broken') throw new Error('orders database unavailable');
  return [{ id: 'ord_1', customerId: customerId ?? 'anonymous', total: 42 }];
}

export async function GET(request: Request): Promise<Response> {
  // Validated incoming trace header (traceparent, x-trace-id, ...), or a new ID.
  const traceId =
    extractTraceId({ headers: Object.fromEntries(request.headers) }, { header: DEFAULT_TRACE_HEADERS }) ??
    generateTraceId();

  return runWithTraceId(traceId, async () => {
    const customerId = new URL(request.url).searchParams.get('customerId');
    try {
      const orders = await loadOrders(customerId);
      await logger.info('Orders loaded', { customerId, count: orders.length });
      return Response.json({ orders }, { headers: { 'x-trace-id': traceId } });
    } catch (error) {
      await logger.error(error instanceof Error ? error : new Error(String(error)), {
        customerId,
      });
      return Response.json(
        { error: 'Internal Server Error' },
        { status: 500, headers: { 'x-trace-id': traceId } }
      );
    }
  });
}
