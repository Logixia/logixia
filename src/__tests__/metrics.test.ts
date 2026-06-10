/**
 * Tests for the Prometheus metrics plugin.
 *
 * Focus: the Prometheus exposition format is strict — an invalid metric or label
 * NAME makes the scraper reject the ENTIRE endpoint, not just that metric. So
 * names must be sanitized to [a-zA-Z_][a-zA-Z0-9_]*. Also covers basic
 * counter / histogram / gauge extraction and rendering.
 */

import { createMetricsPlugin } from '../metrics';
import type { LogEntry } from '../types/index';

function entry(level: string, payload?: Record<string, unknown>): LogEntry {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    level,
    appName: 'TestApp',
    message: 'm',
    ...(payload ? { payload } : {}),
  };
}

describe('MetricsPlugin — name sanitization', () => {
  it('sanitizes an invalid metric name in the output', () => {
    const m = createMetricsPlugin({ 'my-bad.metric': { type: 'counter' } });
    m.onLog(entry('info'));
    const out = m.render();
    // The TYPE/metric lines must use a valid sanitized identifier.
    expect(out).toContain('logixia_my_bad_metric');
    expect(out).toMatch(/^logixia_my_bad_metric 1$/m);
  });

  it('sanitizes invalid label names', () => {
    const m = createMetricsPlugin({
      reqs: { type: 'counter', labels: ['status code'] },
    });
    m.onLog(entry('info', { 'status code': '200' }));
    const out = m.render();
    expect(out).toContain('status_code="200"');
    expect(out).not.toContain('status code=');
  });

  it('prefixes a leading-digit name with an underscore', () => {
    const m = createMetricsPlugin({ '5xx': { type: 'counter' } });
    m.onLog(entry('error'));
    expect(m.render()).toContain('logixia__5xx');
  });
});

describe('MetricsPlugin — extraction', () => {
  it('counts entries matching a level filter', () => {
    const m = createMetricsPlugin({
      error_count: { type: 'counter', levelFilter: 'error' },
    });
    m.onLog(entry('error'));
    m.onLog(entry('info'));
    m.onLog(entry('error'));
    expect(m.render()).toMatch(/^logixia_error_count 2$/m);
  });

  it('observes a histogram field with cumulative buckets and +Inf', () => {
    const m = createMetricsPlugin({
      dur: { type: 'histogram', field: 'duration', buckets: [10, 100] },
    });
    m.onLog(entry('info', { duration: 5 }));
    m.onLog(entry('info', { duration: 50 }));
    const out = m.render();
    expect(out).toContain('logixia_dur_bucket{le="10"} 1'); // only the 5
    expect(out).toContain('logixia_dur_bucket{le="100"} 2'); // 5 and 50
    expect(out).toContain('logixia_dur_bucket{le="+Inf"} 2');
    expect(out).toContain('logixia_dur_count 2');
    expect(out).toContain('logixia_dur_sum 55');
  });

  it('tracks the latest value of a gauge', () => {
    const m = createMetricsPlugin({
      conns: { type: 'gauge', field: 'connections' },
    });
    m.onLog(entry('info', { connections: 3 }));
    m.onLog(entry('info', { connections: 7 }));
    expect(m.render()).toMatch(/^logixia_conns 7$/m);
  });

  it('reset() clears accumulated state', () => {
    const m = createMetricsPlugin({ c: { type: 'counter' } });
    m.onLog(entry('info'));
    m.reset();
    expect(m.render()).toMatch(/^logixia_c 0$/m);
  });

  it('onLog passes the entry through unchanged', () => {
    const m = createMetricsPlugin({ c: { type: 'counter' } });
    const e = entry('info', { x: 1 });
    expect(m.onLog(e)).toBe(e);
  });
});
