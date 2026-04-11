/**
 * resolveResponseHeader() — configurable response header for the trace ID.
 *
 * Contract:
 *  - `undefined` config        → default `'X-Trace-Id'`
 *  - `{ responseHeader: 'X' }` → that string
 *  - `{ responseHeader: false }` → `null` (suppress header entirely)
 */

import { DEFAULT_TRACE_RESPONSE_HEADER, resolveResponseHeader } from '../trace.middleware';

describe('resolveResponseHeader', () => {
  it('returns the default header name when config is undefined', () => {
    expect(resolveResponseHeader()).toBe(DEFAULT_TRACE_RESPONSE_HEADER);
  });

  it('returns the default header name when config has no responseHeader', () => {
    expect(resolveResponseHeader({ enabled: true })).toBe(DEFAULT_TRACE_RESPONSE_HEADER);
  });

  it('returns a user-configured header name', () => {
    expect(resolveResponseHeader({ enabled: true, responseHeader: 'X-Correlation-ID' })).toBe(
      'X-Correlation-ID'
    );
  });

  it('returns null when responseHeader is explicitly false (suppress)', () => {
    expect(resolveResponseHeader({ enabled: true, responseHeader: false })).toBeNull();
  });
});
