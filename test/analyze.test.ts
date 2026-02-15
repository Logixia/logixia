import { analyzeFileContents } from '../src/cli/commands/analyze';

describe('analyzeFileContents', () => {
  test('returns level counts and respects --last (24h)', async () => {
    const now = Date.now();
    const recent = new Date(now - 2 * 60 * 60 * 1000).toISOString(); // 2 hours ago
    const old = new Date(now - 3 * 24 * 60 * 60 * 1000).toISOString(); // 3 days ago

    const raw = [
      JSON.stringify({ timestamp: recent, level: 'info', message: 'ok' }),
      JSON.stringify({ timestamp: recent, level: 'error', message: 'fail' }),
      JSON.stringify({ timestamp: old, level: 'error', message: 'oldfail' }),
    ].join('\n');

  const res = await analyzeFileContents(raw, { last: '24h', format: 'json' });
  const r: any = res as any;
  expect(r).toHaveProperty('total', 2);
  expect(r.byLevel).toHaveProperty('INFO', 1);
  expect(r.byLevel).toHaveProperty('ERROR', 1);
  });

  test('empty input returns zero totals', async () => {
  const res = await analyzeFileContents('', { format: 'json' });
  const r2: any = res as any;
  expect(r2).toHaveProperty('total', 0);
  expect(r2.byLevel).toEqual({});
  });
});
