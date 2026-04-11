/**
 * Defensive validation tests for extractTraceId.
 *
 * `extractTraceId` must return `undefined` (not a bad value) when the source
 * contains empty strings, whitespace-only strings, non-strings, or numeric
 * zero. This prevents garbage trace IDs from polluting AsyncLocalStorage.
 */

import { extractTraceId } from '../trace.utils';

describe('extractTraceId — rejects bad values', () => {
  it('rejects empty-string header values', () => {
    expect(
      extractTraceId({ headers: { 'x-trace-id': '' } }, { header: 'x-trace-id' })
    ).toBeUndefined();
  });

  it('rejects whitespace-only header values', () => {
    expect(
      extractTraceId({ headers: { 'x-trace-id': '   ' } }, { header: 'x-trace-id' })
    ).toBeUndefined();
  });

  it('rejects empty-string query values', () => {
    expect(extractTraceId({ query: { traceId: '' } }, { query: 'traceId' })).toBeUndefined();
  });

  it('rejects empty-string body values', () => {
    expect(extractTraceId({ body: { traceId: '' } }, { body: 'traceId' })).toBeUndefined();
  });

  it('rejects empty-string param values', () => {
    expect(extractTraceId({ params: { traceId: '' } }, { params: 'traceId' })).toBeUndefined();
  });

  it('trims surrounding whitespace on a valid value', () => {
    expect(
      extractTraceId({ headers: { 'x-trace-id': '  tid-123  ' } }, { header: 'x-trace-id' })
    ).toBe('tid-123');
  });

  it('prefers the first value of an array-valued header', () => {
    expect(
      extractTraceId(
        { headers: { 'x-trace-id': ['first-id', 'second-id'] } },
        { header: 'x-trace-id' }
      )
    ).toBe('first-id');
  });
});
