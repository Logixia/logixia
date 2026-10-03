/**
 * Tests for the browser logger's remote transport.
 *
 * Regressions:
 *  - flush() spliced only ONE batchSize chunk, leaving a tail when the batch
 *    exceeded batchSize. It must drain the whole batch.
 *  - destroy() cleared the timer but did NOT flush, losing buffered logs on page
 *    unload / teardown. It must flush remaining entries.
 *
 * fetch is mocked so no real network call is made.
 */

import type { BrowserLogEntry } from '../browser';
import { BrowserRemoteTransport } from '../browser';

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
