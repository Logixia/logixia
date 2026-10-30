/**
 * Tests for the browser logger and its remote transport.
 *
 * Regressions:
 *  - flush() spliced only ONE batchSize chunk, leaving a tail when the batch
 *    exceeded batchSize. It must drain the whole batch.
 *  - destroy() cleared the timer but did NOT flush, losing buffered logs on page
 *    unload / teardown. It must flush remaining entries.
 *  - BrowserLogger.child() dropped the parent's `json` option, so children of a
 *    JSON logger printed pretty lines, and it stripped a key named `_` instead
 *    of keeping every context field.
 *
 * fetch is mocked so no real network call is made.
 */

import type { BrowserLogEntry } from '../browser';
import { BrowserLogger, BrowserRemoteTransport } from '../browser';

function makeEntry(i: number): BrowserLogEntry {
  return { timestamp: '2026-01-01T00:00:00.000Z', level: 'info', appName: 'a', message: `b-${i}` };
}

function makeBigEntry(i: number): BrowserLogEntry {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    level: 'info',
    appName: 'a',
    message: `${'x'.repeat(2000)}-${i}`,
  };
}

describe('BrowserRemoteTransport', () => {
  let fetchMock: jest.Mock;
  let originalFetch: typeof globalThis.fetch | undefined;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn().mockResolvedValue({ ok: true });
    (globalThis as { fetch: unknown }).fetch = fetchMock;
  });

  afterEach(() => {
    (globalThis as { fetch: unknown }).fetch = originalFetch;
  });

  it('drains the whole batch across multiple POSTs when it exceeds batchSize', async () => {
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 10 });
    for (let i = 0; i < 35; i += 1) t.write(makeEntry(i));

    await t.flush();

    // 35 entries / batchSize 10 → 4 POSTs (10+10+10+5).
    const totalSent = fetchMock.mock.calls.reduce((sum, call) => {
      const body = JSON.parse((call[1] as { body: string }).body) as unknown[];
      return sum + body.length;
    }, 0);
    expect(totalSent).toBe(35);
    t.destroy();
  });

  it('flushes remaining buffered entries on destroy()', async () => {
    const t = new BrowserRemoteTransport({
      url: 'https://logs.example/ingest',
      batchSize: 1000, // never auto-flushes
      flushIntervalMs: 999_999,
    });
    for (let i = 0; i < 5; i += 1) t.write(makeEntry(i));
    expect(fetchMock).not.toHaveBeenCalled(); // still buffered

    t.destroy();
    // destroy() kicks off the flush; let the microtask settle.
    await Promise.resolve();
    await Promise.resolve();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0]![1].body) as unknown[];
    expect(body).toHaveLength(5);
  });

  it('re-buffers entries when the POST fails (no loss)', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network down'));
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    for (let i = 0; i < 3; i += 1) t.write(makeEntry(i));

    await t.flush(); // fails → re-buffered
    await t.flush(); // succeeds

    const lastBody = JSON.parse(
      fetchMock.mock.calls[fetchMock.mock.calls.length - 1]![1].body
    ) as unknown[];
    expect(lastBody).toHaveLength(3);
    t.destroy();
  });

  it('rejects a non-http(s) url scheme', () => {
    expect(() => new BrowserRemoteTransport({ url: 'javascript:alert(1)' })).toThrow();
  });

  it('re-buffers on 5xx and drops on permanent 4xx', async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 500 });
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    for (let i = 0; i < 3; i += 1) t.write(makeEntry(i));

    await t.flush(); // 500 → transient, re-buffered
    expect(t.dropped).toBe(0);

    fetchMock.mockResolvedValueOnce({ ok: false, status: 400 });
    await t.flush(); // 400 → permanent, dropped
    expect(t.dropped).toBe(3);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    t.destroy();
  });

  it('re-buffers on 429 (rate limit)', async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 429 });
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    t.write(makeEntry(1));

    await t.flush(); // 429 → transient, re-buffered
    expect(t.dropped).toBe(0);

    fetchMock.mockResolvedValueOnce({ ok: true });
    await t.flush(); // succeeds on retry
    expect(t.dropped).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    t.destroy();
  });

  it('drops oldest entries and counts them when over maxBufferSize', () => {
    const t = new BrowserRemoteTransport({
      url: 'https://logs.example/ingest',
      batchSize: 1000,
      maxBufferSize: 3,
    });
    for (let i = 0; i < 5; i += 1) t.write(makeEntry(i));

    expect(t.dropped).toBe(2); // the two oldest entries were evicted
    t.destroy();
  });

  it('sets keepalive for small bodies', async () => {
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    t.write(makeEntry(1));

    await t.flush();

    expect(fetchMock.mock.calls[0]![1].keepalive).toBe(true);
    t.destroy();
  });

  it('retries once without keepalive when fetch throws on the option, and remembers it', async () => {
    fetchMock.mockImplementation((_url: string, init: { keepalive?: boolean }) => {
      if ('keepalive' in init) {
        throw new TypeError(
          "The 'keepalive' field on 'RequestInitializerDict' is not implemented."
        );
      }
      return Promise.resolve({ ok: true });
    });
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    t.write(makeEntry(1));
    await t.flush();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect('keepalive' in fetchMock.mock.calls[1]![1]).toBe(false);
    expect(t.failedFlushes).toBe(0);

    t.write(makeEntry(2));
    await t.flush();
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect('keepalive' in fetchMock.mock.calls[2]![1]).toBe(false);
    t.destroy();
  });

  it('retries without keepalive when fetch rejects with a keepalive TypeError', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('keepalive is not supported'));
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    t.write(makeEntry(1));
    await t.flush();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(t.failedFlushes).toBe(0);
    t.destroy();
  });

  it('detects a keepalive rejection from another realm (not instanceof Error)', async () => {
    fetchMock.mockRejectedValueOnce({ name: 'TypeError', message: 'keepalive is not supported' });
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    t.write(makeEntry(1));
    await t.flush();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(t.failedFlushes).toBe(0);
    t.destroy();
  });

  it('re-buffers and reports a network failure through failedFlushes / lastError', async () => {
    const boom = new TypeError('network down');
    fetchMock.mockRejectedValueOnce(boom);
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    t.write(makeEntry(1));
    await t.flush();
    expect(t.failedFlushes).toBe(1);
    expect(t.lastError).toBe(boom);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await t.flush(); // the entry was re-buffered and now succeeds
    expect(fetchMock).toHaveBeenCalledTimes(2);
    t.destroy();
  });

  describe('failure reporting', () => {
    let errSpy: jest.SpyInstance;
    let savedSilent: string | undefined;

    beforeEach(() => {
      savedSilent = process.env.LOGIXIA_SILENT_INTERNAL;
      delete process.env.LOGIXIA_SILENT_INTERNAL;
      errSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    });
    afterEach(() => {
      if (savedSilent === undefined) delete process.env.LOGIXIA_SILENT_INTERNAL;
      else process.env.LOGIXIA_SILENT_INTERNAL = savedSilent;
      jest.restoreAllMocks();
    });

    const make = (extra: Record<string, unknown> = {}) =>
      new BrowserRemoteTransport({
        url: 'https://logs.example/ingest?api_key=SECRET',
        batchSize: 1000,
        flushIntervalMs: 0,
        ...extra,
      });
    const output = () => errSpy.mock.calls.map((c) => String(c[0])).join('');

    it.each([
      'error sending request for url (https://logs.example/ingest?api_key=SECRET)',
      'Failed to parse URL from /api/logs?token=SECRET',
      'Invalid value "Bearer SECRET" for header "Authorization"',
    ])('never includes error message text: %s', async (message) => {
      const raw = new TypeError(message);
      fetchMock.mockRejectedValueOnce(raw);
      const t = make();
      t.write(makeEntry(1));
      await t.flush();
      const out = output();
      expect(out).toContain('TypeError');
      expect(out).toContain('host logs.example');
      expect(out).not.toContain('SECRET');
      expect(out).not.toContain('api_key');
      expect(t.lastError).toBe(raw);
    });

    it('describes a relative endpoint without a host', async () => {
      fetchMock.mockRejectedValueOnce(new TypeError('Failed to parse URL from /api/logs'));
      const t = make({ url: '/api/logs' });
      t.write(makeEntry(1));
      await t.flush();
      expect(output()).toContain('relative endpoint');
    });

    it('throttles repeated failures and reports recovery', async () => {
      const now = jest.spyOn(Date, 'now');
      now.mockReturnValue(1_000_000);
      fetchMock.mockRejectedValue(new TypeError('down'));
      const t = make();
      t.write(makeEntry(1));
      await t.flush();
      await t.flush();
      await t.flush();
      expect(errSpy).toHaveBeenCalledTimes(1);
      expect(t.failedFlushes).toBe(3);

      now.mockReturnValue(1_000_000 + 61_000);
      await t.flush();
      expect(errSpy).toHaveBeenCalledTimes(2);

      fetchMock.mockReset().mockResolvedValue({ ok: true });
      await t.flush();
      expect(output()).toContain('recovered');
      expect(errSpy).toHaveBeenCalledTimes(3);
      t.destroy();
    });

    it('alternating failure and success does not bypass the throttle', async () => {
      jest.spyOn(Date, 'now').mockReturnValue(5_000_000);
      const t = make();
      for (let i = 0; i < 4; i += 1) {
        fetchMock.mockRejectedValueOnce(new TypeError('down'));
        t.write(makeEntry(i));
        await t.flush(); // failure
        await t.flush(); // success (re-buffered entry delivered)
      }
      // one failure report + one recovery notice, nothing more inside the window
      expect(errSpy).toHaveBeenCalledTimes(2);
      expect(t.failedFlushes).toBe(4);
      t.destroy();
    });

    it('counts entries written while reporting as dropped', async () => {
      const t = make();
      errSpy.mockImplementation(() => {
        t.write(makeEntry(99));
        return true;
      });
      fetchMock.mockRejectedValueOnce(new TypeError('down'));
      t.write(makeEntry(1));
      await t.flush();
      expect(t.dropped).toBe(1);
      t.destroy();
    });

    it('drops writes made from inside onError', async () => {
      const holder: { t?: BrowserRemoteTransport } = {};
      const t = make({ silent: true, onError: () => holder.t?.write(makeEntry(98)) });
      holder.t = t;
      fetchMock.mockRejectedValueOnce(new TypeError('down'));
      t.write(makeEntry(1));
      await t.flush();
      expect(t.dropped).toBe(1);
      fetchMock.mockClear();
      await t.flush();
      const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string) as BrowserLogEntry[];
      expect(body.map((e) => e.message)).toEqual(['b-1']);
      t.destroy();
    });

    it('defaults to silent in a real browser page and reports elsewhere', async () => {
      const g = globalThis as Record<string, unknown>;
      g['window'] = {};
      g['document'] = {};
      try {
        const onError = jest.fn();
        fetchMock.mockRejectedValueOnce(new TypeError('down'));
        const quiet = make({ onError });
        quiet.write(makeEntry(1));
        await quiet.flush();
        expect(errSpy).not.toHaveBeenCalled();
        expect(onError).toHaveBeenCalledTimes(1);

        fetchMock.mockRejectedValueOnce(new TypeError('down'));
        const loud = make({ silent: false });
        loud.write(makeEntry(1));
        await loud.flush();
        expect(errSpy).toHaveBeenCalledTimes(1);
      } finally {
        delete g['window'];
        delete g['document'];
      }
    });

    it('silent suppresses the console report but onError still fires', async () => {
      const onError = jest.fn();
      const boom = new TypeError('down');
      fetchMock.mockRejectedValueOnce(boom);
      const t = make({ silent: true, onError });
      t.write(makeEntry(1));
      await t.flush();
      expect(errSpy).not.toHaveBeenCalled();
      expect(onError).toHaveBeenCalledWith(boom);
      expect(t.failedFlushes).toBe(1);
    });

    it('a throwing onError does not break flushing', async () => {
      fetchMock.mockRejectedValueOnce(new TypeError('down'));
      const t = make({
        silent: true,
        onError: () => {
          throw new Error('cb');
        },
      });
      t.write(makeEntry(1));
      await expect(t.flush()).resolves.toBeUndefined();
    });

    it('does not queue entries written while reporting (no feedback loop)', async () => {
      const t = make();
      errSpy.mockImplementation(() => {
        t.write(makeEntry(99)); // app routes console.error back into the logger
        return true;
      });
      fetchMock.mockRejectedValueOnce(new TypeError('down'));
      t.write(makeEntry(1));
      await t.flush();
      fetchMock.mockClear();
      await t.flush();
      const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string) as BrowserLogEntry[];
      expect(body.map((e) => e.message)).toEqual(['b-1']);
      t.destroy();
    });

    it.each([500, 429, 401, 403])(
      'counts HTTP %i as a failure with a status-only message',
      async (status) => {
        fetchMock.mockResolvedValueOnce({ ok: false, status, text: async () => 'SECRET-BODY' });
        const t = make();
        t.write(makeEntry(1));
        await t.flush();
        expect(t.failedFlushes).toBe(1);
        expect((t.lastError as Error).message).toBe(`HTTP ${status}`);
        expect(output()).toContain(`HTTP ${status}`);
        expect(output()).not.toContain('SECRET');
        t.destroy();
      }
    );
  });

  it('disables keepalive for bodies at the 64KB limit', async () => {
    const t = new BrowserRemoteTransport({ url: 'https://logs.example/ingest', batchSize: 1000 });
    for (let i = 0; i < 40; i += 1) t.write(makeBigEntry(i)); // ~80KB serialised

    await t.flush();

    expect(fetchMock.mock.calls[0]![1].keepalive).toBe(false);
    t.destroy();
  });

  it('does not schedule a timer when flushIntervalMs is 0', () => {
    jest.useFakeTimers();
    const t = new BrowserRemoteTransport({
      url: 'https://logs.example/ingest',
      flushIntervalMs: 0,
    });
    expect(jest.getTimerCount()).toBe(0);
    t.destroy();
    jest.useRealTimers();
  });
});

describe('BrowserLogger.child()', () => {
  let errSpy: jest.SpyInstance;

  beforeEach(() => {
    errSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    errSpy.mockRestore();
  });

  function lastJsonEntry(): BrowserLogEntry {
    const calls = errSpy.mock.calls;
    return JSON.parse(calls[calls.length - 1]![0] as string) as BrowserLogEntry;
  }

  it('keeps json output for a child of a json: true logger', () => {
    const parent = new BrowserLogger({ appName: 'app', json: true });
    const child = parent.child({ requestId: 'r-1' });

    child.info('hello');

    expect(errSpy).toHaveBeenCalledTimes(1);
    const entry = lastJsonEntry();
    expect(entry.message).toBe('hello');
    expect(entry.payload).toEqual({ requestId: 'r-1' });
  });

  it('merges the parent context with the new fields, including context', () => {
    const parent = new BrowserLogger({
      appName: 'app',
      json: true,
      context: { service: 'checkout' },
    });
    const child = parent.child({ context: 'AuthService', userId: '42' });

    child.info('Login succeeded');

    expect(lastJsonEntry().payload).toEqual({
      service: 'checkout',
      context: 'AuthService',
      userId: '42',
    });
  });

  it('keeps both levels of context in a grandchild', () => {
    const parent = new BrowserLogger({ appName: 'app', json: true });
    const grandchild = parent.child({ requestId: 'r-1' }).child({ userId: '42' });

    grandchild.info('nested');

    expect(lastJsonEntry().payload).toEqual({ requestId: 'r-1', userId: '42' });
  });
});
