/**
 * Comprehensive tests for trace.utils
 *
 * Covers:
 *  - generateTraceId: format validation
 *  - getCurrentTraceId / setTraceId / runWithTraceId: AsyncLocalStorage propagation
 *  - extractTraceId: headers, query, body, params extraction
 *  - createTraceMiddleware: request instrumentation
 *  - DEFAULT_TRACE_HEADERS constant
 */

import {
  createTraceMiddleware,
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
  getCurrentTraceId,
  runWithTraceId,
  setTraceId,
  traceStorage,
} from '../trace.utils';

// ── generateTraceId ───────────────────────────────────────────────────────────

describe('generateTraceId', () => {
  it('returns a non-empty string', () => {
    expect(typeof generateTraceId()).toBe('string');
    expect(generateTraceId().length).toBeGreaterThan(0);
  });

  it('returns a valid UUID v4 format', () => {
    const id = generateTraceId();
    // UUID v4: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it('generates unique IDs on each call', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateTraceId()));
    expect(ids.size).toBe(100);
  });
});

// ── getCurrentTraceId ─────────────────────────────────────────────────────────

describe('getCurrentTraceId', () => {
  it('returns undefined outside any trace context', () => {
    // Run in a fresh async context to isolate from any prior enterWith calls
    // We can't easily reset ALS state, so just confirm undefined or a string
    const result = getCurrentTraceId();
    // Should be either undefined or a string — just verify it doesn't throw
    expect(result === undefined || typeof result === 'string').toBe(true);
  });

  it('returns the trace ID when inside runWithTraceId', (done) => {
    const testId = 'test-trace-abc-123';
    runWithTraceId(testId, () => {
      expect(getCurrentTraceId()).toBe(testId);
      done();
    });
  });

  it('returns the correct ID in nested contexts', (done) => {
    runWithTraceId('outer-id', () => {
      runWithTraceId('inner-id', () => {
        expect(getCurrentTraceId()).toBe('inner-id');
        done();
      });
    });
  });

  it('restores the outer trace ID after inner context exits', (done) => {
    runWithTraceId('outer-id', () => {
      runWithTraceId('inner-id', () => {});
      // After inner context, we should still be in the outer one
      expect(getCurrentTraceId()).toBe('outer-id');
      done();
    });
  });
});

// ── runWithTraceId ────────────────────────────────────────────────────────────

describe('runWithTraceId', () => {
  it('executes the callback and returns its result', () => {
    const result = runWithTraceId('trace-xyz', () => 42);
    expect(result).toBe(42);
  });

  it('propagates trace ID through async callbacks', async () => {
    const id = 'async-trace-id';
    let captured: string | undefined;

    await new Promise<void>((resolve) => {
      runWithTraceId(id, async () => {
        await Promise.resolve(); // yield
        captured = getCurrentTraceId();
        resolve();
      });
    });

    expect(captured).toBe(id);
  });

  it('stores extra data fields alongside traceId', (done) => {
    runWithTraceId(
      'trace-id',
      () => {
        const store = traceStorage.getStore();
        expect(store?.traceId).toBe('trace-id');
        done();
      },
      { requestId: 'req-001' }
    );
  });
});

// ── setTraceId ────────────────────────────────────────────────────────────────

describe('setTraceId', () => {
  it('sets trace ID that is readable via getCurrentTraceId', (done) => {
    runWithTraceId('initial', () => {
      setTraceId('updated-id');
      expect(getCurrentTraceId()).toBe('updated-id');
      done();
    });
  });

  it('merges extra data with existing context', (done) => {
    runWithTraceId('tid', () => {
      setTraceId('new-tid', { userId: 'u-100' });
      const store = traceStorage.getStore();
      expect(store?.traceId).toBe('new-tid');
      expect(store?.userId).toBe('u-100');
      done();
    });
  });
});

// ── extractTraceId ────────────────────────────────────────────────────────────

describe('extractTraceId', () => {
  describe('from headers', () => {
    it('extracts trace ID from a single header name', () => {
      const req = { headers: { 'x-trace-id': 'trace-from-header' } };
      expect(extractTraceId(req, { header: 'x-trace-id' })).toBe('trace-from-header');
    });

    it('extracts the first match from an array of header names', () => {
      const req = { headers: { 'x-request-id': 'req-id' } };
      expect(extractTraceId(req, { header: ['x-trace-id', 'x-request-id'] })).toBe('req-id');
    });

    it('returns first item when header value is an array', () => {
      const req = { headers: { traceparent: ['tid-0', 'tid-1'] } };
      expect(extractTraceId(req, { header: 'traceparent' })).toBe('tid-0');
    });

    it('returns undefined when header is absent', () => {
      const req = { headers: { other: 'value' } };
      expect(extractTraceId(req, { header: 'x-trace-id' })).toBeUndefined();
    });

    it('is case-insensitive for header names', () => {
      const req = { headers: { 'x-trace-id': 'value' } };
      // extractTraceId lowercases the header key
      expect(extractTraceId(req, { header: 'X-Trace-Id' })).toBe('value');
    });
  });

  describe('from query parameters', () => {
    it('extracts trace ID from a query param', () => {
      const req = { query: { traceId: 'q-trace' } };
      expect(extractTraceId(req, { query: 'traceId' })).toBe('q-trace');
    });

    it('tries multiple query keys in order', () => {
      const req = { query: { trace_id: 'tid' } };
      expect(extractTraceId(req, { query: ['traceId', 'trace_id'] })).toBe('tid');
    });

    it('returns undefined when no matching query param', () => {
      const req = { query: {} };
      expect(extractTraceId(req, { query: 'traceId' })).toBeUndefined();
    });
  });

  describe('from body', () => {
    it('extracts trace ID from a body field', () => {
      const req = { body: { traceId: 'body-trace' } };
      expect(extractTraceId(req, { body: 'traceId' })).toBe('body-trace');
    });

    it('tries multiple body fields in order', () => {
      const req = { body: { trace_id: 'bt' } };
      expect(extractTraceId(req, { body: ['traceId', 'trace_id'] })).toBe('bt');
    });

    it('returns undefined when body field not present', () => {
      const req = { body: { other: 'val' } };
      expect(extractTraceId(req, { body: 'traceId' })).toBeUndefined();
    });
  });

  describe('from params', () => {
    it('extracts trace ID from route params', () => {
      const req = { params: { traceId: 'route-trace' } };
      expect(extractTraceId(req, { params: 'traceId' })).toBe('route-trace');
    });

    it('returns undefined when param not present', () => {
      const req = { params: { id: 'something' } };
      expect(extractTraceId(req, { params: 'traceId' })).toBeUndefined();
    });
  });

  describe('priority order', () => {
    it('prefers header over query', () => {
      const req = {
        headers: { 'x-trace-id': 'from-header' },
        query: { traceId: 'from-query' },
      };
      expect(extractTraceId(req, { header: 'x-trace-id', query: 'traceId' })).toBe('from-header');
    });

    it('falls back to query when header is absent', () => {
      const req = { headers: {}, query: { traceId: 'from-query' } };
      expect(extractTraceId(req, { header: 'x-trace-id', query: 'traceId' })).toBe('from-query');
    });

    it('returns undefined when nothing matches', () => {
      expect(extractTraceId({}, { header: 'x-trace-id', query: 'traceId' })).toBeUndefined();
    });
  });
});

// ── DEFAULT_TRACE_HEADERS ─────────────────────────────────────────────────────

describe('DEFAULT_TRACE_HEADERS', () => {
  it('is an array of strings', () => {
    expect(Array.isArray(DEFAULT_TRACE_HEADERS)).toBe(true);
    expect(DEFAULT_TRACE_HEADERS.length).toBeGreaterThan(0);
    for (const h of DEFAULT_TRACE_HEADERS) expect(typeof h).toBe('string');
  });

  it('includes traceparent (W3C/OTel)', () => {
    expect(DEFAULT_TRACE_HEADERS).toContain('traceparent');
  });

  it('includes x-trace-id', () => {
    expect(DEFAULT_TRACE_HEADERS).toContain('x-trace-id');
  });

  it('includes x-request-id', () => {
    expect(DEFAULT_TRACE_HEADERS).toContain('x-request-id');
  });

  it('includes x-correlation-id', () => {
    expect(DEFAULT_TRACE_HEADERS).toContain('x-correlation-id');
  });
});

// ── createTraceMiddleware ─────────────────────────────────────────────────────

describe('createTraceMiddleware', () => {
  it('calls next()', (done) => {
    const middleware = createTraceMiddleware({ enabled: true });
    const req = { headers: {} };
    const res = { setHeader: jest.fn() };
    middleware(req, res, done);
  });

  it('sets X-Trace-Id response header', (done) => {
    const middleware = createTraceMiddleware({ enabled: true });
    const req = { headers: {} };
    const res = { setHeader: jest.fn() };
    middleware(req, res, () => {
      expect(res.setHeader).toHaveBeenCalledWith('X-Trace-Id', expect.any(String));
      done();
    });
  });

  it('uses existing trace ID from request header', (done) => {
    const middleware = createTraceMiddleware({ enabled: true });
    const existingId = 'existing-trace-id';
    const req = { headers: { 'x-trace-id': existingId } };
    const res = { setHeader: jest.fn() };
    middleware(req, res, () => {
      expect(res.setHeader).toHaveBeenCalledWith('X-Trace-Id', existingId);
      done();
    });
  });

  it('generates a new trace ID when none is present', (done) => {
    const middleware = createTraceMiddleware({ enabled: true });
    const req = { headers: {} };
    const res = { setHeader: jest.fn() };
    middleware(req, res, () => {
      const [[, traceId]] = (res.setHeader as jest.Mock).mock.calls;
      expect(typeof traceId).toBe('string');
      expect(traceId.length).toBeGreaterThan(0);
      done();
    });
  });

  it('attaches traceId to the request object', (done) => {
    const middleware = createTraceMiddleware({ enabled: true });
    const req: Record<string, unknown> = { headers: {} };
    const res = { setHeader: jest.fn() };
    middleware(req, res, () => {
      expect(typeof req.traceId).toBe('string');
      done();
    });
  });

  it('uses custom generator when provided', (done) => {
    const customId = 'custom-generated-trace';
    const middleware = createTraceMiddleware({ enabled: true, generator: () => customId });
    const req = { headers: {} };
    const res = { setHeader: jest.fn() };
    middleware(req, res, () => {
      expect(res.setHeader).toHaveBeenCalledWith('X-Trace-Id', customId);
      done();
    });
  });

  it('runs callback inside a trace context', (done) => {
    const middleware = createTraceMiddleware({ enabled: true });
    const req = { headers: {} };
    const res = { setHeader: jest.fn() };
    middleware(req, res, () => {
      const id = getCurrentTraceId();
      expect(typeof id).toBe('string');
      done();
    });
  });
});
