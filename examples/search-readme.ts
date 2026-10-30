import { SearchManager } from '../src/search';
import type { LogEntry } from '../src/types';

async function main() {
  const search = new SearchManager({ maxIndexSize: 10_000 });

  const logEntries: LogEntry[] = [
    {
      timestamp: new Date().toISOString(),
      level: 'info',
      appName: 'api',
      traceId: 'req-001',
      message: 'Checkout started',
    },
    {
      timestamp: new Date().toISOString(),
      level: 'error',
      appName: 'api',
      traceId: 'req-001',
      message: 'Payment failed: card declined',
    },
  ];

  await search.indexLogs(logEntries);

  const results = await search.search(
    'payment failed',
    { levels: ['error'], timeRange: { start: new Date('2025-01-01'), end: new Date() } },
    { limit: 50 }
  );
  console.log(results.map((r) => `${r.score.toFixed(2)} ${r.log.message}`));

  const nl = await search.naturalLanguageSearch('payment errors');
  console.log(nl.length, 'natural language results');

  const trace = await search.correlateByTraceId('req-001');
  console.log(trace.logs.length, 'logs in trace req-001');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
