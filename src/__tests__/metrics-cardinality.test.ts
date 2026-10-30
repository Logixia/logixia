import { createMetricsPlugin } from '../metrics';
import type { LogEntry } from '../types/index';

const entry = (payload: Record<string, unknown>): LogEntry =>
  ({ level: 'info', message: 'm', payload, timestamp: new Date().toISOString() }) as LogEntry;

describe('MetricsPlugin label cardinality cap', () => {
  it('folds label sets beyond the cap into an __overflow__ series', () => {
    const m = createMetricsPlugin(
      { req: { type: 'counter', labels: ['user'] } },
      { maxLabelSets: 3 }
    );
    for (let i = 0; i < 10; i++) m.onLog(entry({ user: `u${i}` }));
    const out = m.render();
    expect(out).toContain('logixia_req{user="u0"} 1');
    expect(out).toContain('logixia_req{user="u2"} 1');
    expect(out).not.toContain('user="u3"');
    expect(out).toContain('logixia_req{user="__overflow__"} 7');
  });

  it('keeps counting existing label sets after the cap is reached', () => {
    const m = createMetricsPlugin({ req: { type: 'counter', labels: ['u'] } }, { maxLabelSets: 1 });
    m.onLog(entry({ u: 'a' }));
    m.onLog(entry({ u: 'b' }));
    m.onLog(entry({ u: 'a' }));
    const out = m.render();
    expect(out).toContain('logixia_req{u="a"} 2');
    expect(out).toContain('logixia_req{u="__overflow__"} 1');
  });

  it('applies to histograms and gauges', () => {
    const m = createMetricsPlugin(
      {
        h: { type: 'histogram', field: 'd', labels: ['k'], buckets: [10] },
        g: { type: 'gauge', field: 'd', labels: ['k'] },
      },
      { maxLabelSets: 2 }
    );
    for (let i = 0; i < 5; i++) m.onLog(entry({ k: `k${i}`, d: 1 }));
    const out = m.render();
    expect(out).not.toContain('k="k4"');
    expect(out).toContain('logixia_h_count{k="__overflow__"} 3');
    expect(out).toContain('logixia_g{k="__overflow__"} 1');
  });

  it('defaults to 1000 label sets and truncates long label values', () => {
    const m = createMetricsPlugin({ req: { type: 'counter', labels: ['u'] } });
    for (let i = 0; i < 1100; i++) m.onLog(entry({ u: `u${i}` }));
    const lines = m
      .render()
      .split('\n')
      .filter((l) => l.startsWith('logixia_req{'));
    expect(lines).toHaveLength(1001);

    const m2 = createMetricsPlugin({ req: { type: 'counter', labels: ['u'] } });
    m2.onLog(entry({ u: 'x'.repeat(5000) }));
    expect(m2.render()).toContain(`u="${'x'.repeat(256)}"`);
    expect(m2.render()).not.toContain('x'.repeat(257));
  });
});
