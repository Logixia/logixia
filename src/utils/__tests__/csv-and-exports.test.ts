import * as root from '../../index';
import { createExpressMiddleware } from '../../middleware/http-logger';
import * as nest from '../../nest';
import { SearchManager } from '../../search/search-manager';
import { csvField } from '../csv.utils';

describe('csvField', () => {
  it('guards formulas, quotes CR/LF/comma/quote, encodes objects', () => {
    expect(csvField('=1+1')).toBe("'=1+1");
    expect(csvField('a\rb')).toBe('"a\rb"');
    expect(csvField('a,b')).toBe('"a,b"');
    expect(csvField('say "hi"')).toBe('"say ""hi"""');
    expect(csvField({ a: 1 })).toBe('"{""a"":1}"');
    expect(csvField(-5)).toBe('-5');
  });

  it('renders null/undefined as empty (never as a quoted empty JSON string)', () => {
    expect(csvField(null)).toBe('');
    expect(csvField()).toBe('');
    expect(csvField(undefined, true)).toBe('""');
    expect(csvField(null, true)).not.toBe('""""""');
  });
});

describe('SearchManager CSV export', () => {
  it('neutralizes formula prefixes and quotes CR', async () => {
    const mgr = new SearchManager();
    const results = [
      { log: { timestamp: 't', level: 'info', appName: 'a', message: '=cmd|x' } },
      { log: { timestamp: 't', level: 'info', appName: 'a', message: 'x\ry' } },
    ] as never;
    const csv = await mgr.exportResults(results, { format: 'csv' } as never);
    expect(csv).toContain("'=cmd|x");
    expect(csv).toContain('"x\ry"');
  });
});

describe('public exports', () => {
  it('exposes the new exception filter and metrics API', () => {
    expect(root.LOGIXIA_EXCEPTION_FILTER_OPTIONS).toBe('LOGIXIA_EXCEPTION_FILTER_OPTIONS');
    expect(nest.LOGIXIA_EXCEPTION_FILTER_OPTIONS).toBe('LOGIXIA_EXCEPTION_FILTER_OPTIONS');
    expect(nest.LogixiaExceptionFilter).toBe(root.LogixiaExceptionFilter);
    expect(root.OVERFLOW_LABEL_VALUE).toBe('__overflow__');
  });
});

describe('http-logger traceIdHeader casing', () => {
  it('matches a mixed-case configured header against lower-cased request headers', () => {
    const logger = { logLevel: jest.fn() };
    const mw = createExpressMiddleware(logger as never, { traceIdHeader: 'X-Trace-ID' });
    const res = { statusCode: 200, on: jest.fn(), setHeader: jest.fn(), end: jest.fn() };
    mw(
      { method: 'GET', url: '/', headers: { 'x-trace-id': 'abc-123' } } as never,
      res as never,
      jest.fn()
    );
    const logged = JSON.stringify(logger.logLevel.mock.calls);
    expect(logged).toContain('abc-123');
  });
});
