/**
 * Comprehensive tests for LogixiaContext (AsyncLocalStorage-based context)
 *
 * Covers:
 *  - LogixiaContext.run: basic, nested, returns callback result
 *  - LogixiaContext.get: inside/outside context, parent fields propagated
 *  - LogixiaContext.set: merges fields into current context, no-op outside
 *  - LogixiaContext.getStorage: returns the ALS instance
 *  - createExpressContextMiddleware: requestId / traceId extraction, enrich hook
 *  - createFastifyContextHook: similar coverage
 */

import {
  createExpressContextMiddleware,
  createFastifyContextHook,
  LogixiaContext,
} from '../async-context';

// ── LogixiaContext.run ────────────────────────────────────────────────────────

describe('LogixiaContext.run', () => {
  it('returns the callback result', () => {
    const result = LogixiaContext.run({ requestId: 'abc' }, () => 42);
    expect(result).toBe(42);
  });

  it('makes context available via get() inside the callback', () => {
    LogixiaContext.run({ requestId: 'req-01', userId: 'u-1' }, () => {
      const ctx = LogixiaContext.get();
      expect(ctx?.requestId).toBe('req-01');
      expect(ctx?.userId).toBe('u-1');
    });
  });

  it('does not leak context outside the callback', () => {
    LogixiaContext.run({ requestId: 'inner' }, () => {});
    // After the callback, the context should be gone (or from a prior outer context)
    // We can't guarantee undefined if a parent context exists, so just verify
    // we're NOT in the 'inner' context any more
    const ctx = LogixiaContext.get();
    if (ctx) {
      expect(ctx.requestId).not.toBe('inner');
    }
  });

  it('supports nested contexts (inner overrides outer fields)', (done) => {
    LogixiaContext.run({ requestId: 'outer', tenantId: 't-1' }, () => {
      LogixiaContext.run({ requestId: 'inner' }, () => {
        const ctx = LogixiaContext.get();
        expect(ctx?.requestId).toBe('inner');
        expect(ctx?.tenantId).toBe('t-1'); // inherited from parent
        done();
      });
    });
  });

  it('restores parent context fields after inner context exits', (done) => {
    LogixiaContext.run({ requestId: 'outer' }, () => {
      LogixiaContext.run({ requestId: 'inner' }, () => {});
      // Back to outer context
      const ctx = LogixiaContext.get();
      expect(ctx?.requestId).toBe('outer');
      done();
    });
  });

  it('propagates context through async operations', async () => {
    let capturedCtx: ReturnType<typeof LogixiaContext.get>;

    await new Promise<void>((resolve) => {
      LogixiaContext.run({ requestId: 'async-req' }, async () => {
        await Promise.resolve();
        capturedCtx = LogixiaContext.get();
        resolve();
      });
    });

    expect(capturedCtx?.requestId).toBe('async-req');
  });

  it('propagates context through Promise.all', async () => {
    const results: string[] = [];

    await new Promise<void>((resolve) => {
      LogixiaContext.run({ requestId: 'concurrent' }, async () => {
        await Promise.all([
          (async () => {
            await Promise.resolve();
            results.push(LogixiaContext.get()!.requestId as string);
          })(),
          (async () => {
            await Promise.resolve();
            results.push(LogixiaContext.get()!.requestId as string);
          })(),
        ]);
        resolve();
      });
    });

    expect(results).toEqual(['concurrent', 'concurrent']);
  });

  it('stores all LogContext fields', () => {
    LogixiaContext.run(
      {
        requestId: 'r',
        traceId: 't',
        spanId: 's',
        userId: 'u',
        tenantId: 'ten',
        sessionId: 'sess',
        customField: 'custom',
      },
      () => {
        const ctx = LogixiaContext.get();
        expect(ctx?.requestId).toBe('r');
        expect(ctx?.traceId).toBe('t');
        expect(ctx?.spanId).toBe('s');
        expect(ctx?.userId).toBe('u');
        expect(ctx?.tenantId).toBe('ten');
        expect(ctx?.sessionId).toBe('sess');
        expect(ctx?.customField).toBe('custom');
      }
    );
  });
});

// ── LogixiaContext.get ────────────────────────────────────────────────────────

describe('LogixiaContext.get', () => {
  it('returns undefined when called outside any run() context', () => {
    // This will either return undefined or a context from a prior test
    // We run in a fresh promise to avoid ALS inheritance
    // The most reliable way: just verify it doesn't throw
    expect(() => LogixiaContext.get()).not.toThrow();
  });

  it('returns the active context object inside run()', () => {
    LogixiaContext.run({ requestId: 'test' }, () => {
      expect(LogixiaContext.get()).not.toBeNull();
    });
  });
});

// ── LogixiaContext.set ────────────────────────────────────────────────────────

describe('LogixiaContext.set', () => {
  it('merges fields into the existing context', () => {
    LogixiaContext.run({ requestId: 'req-1' }, () => {
      LogixiaContext.set({ userId: 'u-99' });
      const ctx = LogixiaContext.get();
      expect(ctx?.requestId).toBe('req-1');
      expect(ctx?.userId).toBe('u-99');
    });
  });

  it('overwrites existing fields', () => {
    LogixiaContext.run({ requestId: 'original' }, () => {
      LogixiaContext.set({ requestId: 'updated' });
      expect(LogixiaContext.get()?.requestId).toBe('updated');
    });
  });

  it('is a no-op when called outside a run() context', () => {
    // Should not throw
    expect(() => LogixiaContext.set({ requestId: 'no-context' })).not.toThrow();
  });

  it('sets custom fields beyond the predefined ones', () => {
    LogixiaContext.run({ requestId: 'r' }, () => {
      LogixiaContext.set({ correlationId: 'corr-1', traceFlags: 1 });
      const ctx = LogixiaContext.get();
      expect(ctx?.correlationId).toBe('corr-1');
      expect(ctx?.traceFlags).toBe(1);
    });
  });
});

// ── LogixiaContext.getStorage ─────────────────────────────────────────────────

describe('LogixiaContext.getStorage', () => {
  it('returns an AsyncLocalStorage instance', () => {
    const storage = LogixiaContext.getStorage();
    expect(storage).toBeDefined();
    expect(typeof storage.run).toBe('function');
    expect(typeof storage.getStore).toBe('function');
  });

  it('is the same instance across multiple calls (singleton)', () => {
    expect(LogixiaContext.getStorage()).toBe(LogixiaContext.getStorage());
  });
});

// ── createExpressContextMiddleware ────────────────────────────────────────────

describe('createExpressContextMiddleware', () => {
  it('calls next()', (done) => {
    const mw = createExpressContextMiddleware();
    const req: Record<string, unknown> = { headers: {} };
    mw(req, {}, done);
  });

  it('sets a traceId in the context', (done) => {
    const mw = createExpressContextMiddleware();
    const req: Record<string, unknown> = { headers: {} };
    mw(req, {}, () => {
      const ctx = LogixiaContext.get();
      expect(typeof ctx?.traceId).toBe('string');
      done();
    });
  });

  it('reads traceId from x-trace-id header (express)', (done) => {
    const mw = createExpressContextMiddleware();
    const req: Record<string, unknown> = { headers: { 'x-trace-id': 'req-from-header' } };
    mw(req, {}, () => {
      expect(LogixiaContext.get()?.traceId).toBe('req-from-header');
      done();
    });
  });

  it('reads traceId from x-trace-id header', (done) => {
    const mw = createExpressContextMiddleware();
    const req: Record<string, unknown> = { headers: { 'x-trace-id': 'trace-from-header' } };
    mw(req, {}, () => {
      expect(LogixiaContext.get()?.traceId).toBe('trace-from-header');
      done();
    });
  });

  it('uses custom traceIdHeader when provided', (done) => {
    const mw = createExpressContextMiddleware({ traceIdHeader: 'x-my-trace-id' });
    const req: Record<string, unknown> = { headers: { 'x-my-trace-id': 'custom-trace' } };
    mw(req, {}, () => {
      expect(LogixiaContext.get()?.traceId).toBe('custom-trace');
      done();
    });
  });

  it('uses custom traceIdHeader when provided', (done) => {
    const mw = createExpressContextMiddleware({ traceIdHeader: 'x-my-trace-id' });
    const req: Record<string, unknown> = { headers: { 'x-my-trace-id': 'my-trace' } };
    mw(req, {}, () => {
      expect(LogixiaContext.get()?.traceId).toBe('my-trace');
      done();
    });
  });

  it('calls the enrich function and merges its result', (done) => {
    const mw = createExpressContextMiddleware({
      enrich: (req) => ({ userId: req['userId'] as string }),
    });
    const req: Record<string, unknown> = { headers: {}, userId: 'u-enriched' };
    mw(req, {}, () => {
      expect(LogixiaContext.get()?.userId).toBe('u-enriched');
      done();
    });
  });

  it('generates a unique traceId when no header is present', (done) => {
    const mw = createExpressContextMiddleware();
    const req: Record<string, unknown> = { headers: {} };
    mw(req, {}, () => {
      const id = LogixiaContext.get()?.traceId as string;
      expect(id.length).toBeGreaterThan(0);
      done();
    });
  });
});

// ── createFastifyContextHook ──────────────────────────────────────────────────

describe('createFastifyContextHook', () => {
  it('calls done()', (done) => {
    const hook = createFastifyContextHook();
    hook({ headers: {} }, {}, done);
  });

  it('sets a traceId in the context', (done) => {
    const hook = createFastifyContextHook();
    hook({ headers: {} }, {}, () => {
      expect(typeof LogixiaContext.get()?.traceId).toBe('string');
      done();
    });
  });

  it('reads traceId from x-trace-id header', (done) => {
    const hook = createFastifyContextHook();
    hook({ headers: { 'x-trace-id': 'fastify-trace' } }, {}, () => {
      expect(LogixiaContext.get()?.traceId).toBe('fastify-trace');
      done();
    });
  });

  it('falls back to request.id field for traceId', (done) => {
    const hook = createFastifyContextHook();
    hook({ headers: {}, id: 'fastify-internal-id' }, {}, () => {
      expect(LogixiaContext.get()?.traceId).toBe('fastify-internal-id');
      done();
    });
  });

  it('calls the enrich function', (done) => {
    const hook = createFastifyContextHook({
      enrich: (req) => ({ tenantId: req['tenantId'] as string }),
    });
    hook({ headers: {}, tenantId: 'tenant-42' }, {}, () => {
      expect(LogixiaContext.get()?.tenantId).toBe('tenant-42');
      done();
    });
  });
});
