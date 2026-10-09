/**
 * Tests for `correlationFetch`.
 *
 * Regression (issue #118): the wrapper merged `init.headers` by spreading it
 * into a plain object, so a `Headers` instance (no own enumerable properties)
 * and an array of `[name, value]` tuples both collapsed to nothing and every
 * caller header was dropped. The duplicate check was also case-sensitive, so a
 * mixed-case `X-Correlation-ID` already on the request was sent twice.
 *
 * `fetch` is mocked so no real network call is made.
 */

import { correlationFetch, withCorrelationId } from '../correlation';

/** Capture the init that the wrapper hands to `globalThis.fetch`. */
function captureFetch(): { calls: RequestInit[]; restore: () => void } {
  const original = globalThis.fetch;
  const calls: RequestInit[] = [];
  (globalThis as unknown as { fetch: unknown }).fetch = (
    _input: unknown,
    init?: RequestInit
  ): Promise<Response> => {
    calls.push(init ?? {});
    return Promise.resolve({ ok: true } as Response);
  };
  return {
    calls,
    restore: () => {
      (globalThis as unknown as { fetch: unknown }).fetch = original;
    },
  };
}

/** Read the headers the wrapper sent, whatever shape it used. */
function sentHeaders(init: RequestInit): Array<[string, string]> {
  const h = init.headers;
  if (h instanceof Headers) return [...h.entries()];
  if (Array.isArray(h)) return h.map((pair) => [String(pair[0]), String(pair[1])]);
  return Object.entries(h ?? {}).map(([name, value]) => [name, String(value)]);
}

describe('correlationFetch', () => {
  let capture: ReturnType<typeof captureFetch>;

  beforeEach(() => {
    capture = captureFetch();
  });

  afterEach(() => {
    capture.restore();
  });

  it('keeps caller headers passed as a plain object', async () => {
    await withCorrelationId('cid-1', () =>
      correlationFetch('https://example.test/', { headers: { authorization: 'Bearer t' } })
    );

    const sent = sentHeaders(capture.calls[0]!);
    expect(sent).toContainEqual(['authorization', 'Bearer t']);
    expect(sent).toContainEqual(['x-correlation-id', 'cid-1']);
  });

  it('keeps caller headers passed as a Headers instance', async () => {
    await withCorrelationId('cid-1', () =>
      correlationFetch('https://example.test/', {
        headers: new Headers({ authorization: 'Bearer t' }),
      })
    );

    const sent = sentHeaders(capture.calls[0]!);
    expect(sent).toContainEqual(['authorization', 'Bearer t']);
    expect(sent).toContainEqual(['x-correlation-id', 'cid-1']);
  });

  it('keeps caller headers passed as an array of tuples', async () => {
    await withCorrelationId('cid-1', () =>
      correlationFetch('https://example.test/', {
        headers: [
          ['authorization', 'Bearer t'],
          ['accept', 'application/json'],
        ],
      })
    );

    const sent = sentHeaders(capture.calls[0]!);
    expect(sent).toContainEqual(['authorization', 'Bearer t']);
    expect(sent).toContainEqual(['accept', 'application/json']);
    expect(sent).toContainEqual(['x-correlation-id', 'cid-1']);
  });

  it('does not overwrite or duplicate an existing header with different casing', async () => {
    await withCorrelationId('cid-1', () =>
      correlationFetch('https://example.test/', { headers: { 'X-Correlation-ID': 'upstream' } })
    );

    const sent = sentHeaders(capture.calls[0]!);
    const correlationHeaders = sent.filter(([name]) => name.toLowerCase() === 'x-correlation-id');
    expect(correlationHeaders).toHaveLength(1);
    expect(correlationHeaders[0]![1]).toBe('upstream');
  });

  it('adds an explicit header name from options', async () => {
    await withCorrelationId('cid-1', () =>
      correlationFetch('https://example.test/', {}, { header: 'x-trace-id' })
    );

    expect(sentHeaders(capture.calls[0]!)).toContainEqual(['x-trace-id', 'cid-1']);
  });

  it('adds no header when no correlation context is active', async () => {
    await correlationFetch('https://example.test/', { headers: { authorization: 'Bearer t' } });

    const sent = sentHeaders(capture.calls[0]!);
    expect(sent).toEqual([['authorization', 'Bearer t']]);
  });

  it('passes the rest of the init through untouched', async () => {
    await withCorrelationId('cid-1', () =>
      correlationFetch('https://example.test/', { method: 'POST', body: '{"a":1}' })
    );

    expect(capture.calls[0]!.method).toBe('POST');
    expect(capture.calls[0]!.body).toBe('{"a":1}');
  });

  it('keeps the headers a Request input already carries', async () => {
    const request = new Request('https://example.test/', {
      headers: { authorization: 'Bearer t' },
    });

    await withCorrelationId('cid-1', () => correlationFetch(request));

    const sent = sentHeaders(capture.calls[0]!);
    expect(sent).toContainEqual(['authorization', 'Bearer t']);
    expect(sent).toContainEqual(['x-correlation-id', 'cid-1']);
  });

  it('layers init.headers over the Request headers', async () => {
    const request = new Request('https://example.test/', {
      headers: { authorization: 'Bearer t', accept: 'text/plain' },
    });

    await withCorrelationId('cid-1', () =>
      correlationFetch(request, { headers: { accept: 'application/json' } })
    );

    const sent = sentHeaders(capture.calls[0]!);
    expect(sent).toContainEqual(['authorization', 'Bearer t']);
    expect(sent).toContainEqual(['accept', 'application/json']);
    expect(sent).toContainEqual(['x-correlation-id', 'cid-1']);
  });
});
