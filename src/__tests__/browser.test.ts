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
});
