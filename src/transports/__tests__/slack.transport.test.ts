/* eslint-disable sonarjs/no-clear-text-protocols -- negative tests for http URLs */
import type { TransportLogEntry } from '../../types/transport.types';
import { escapeSlack, SlackTransport } from '../slack.transport';

const URL_OK = 'https://hooks.slack.com/services/T000/B000/SECRETTOKEN123';

function entry(over: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'error',
    message: 'boom',
    ...over,
  };
}

describe('SlackTransport', () => {
  let fetchMock: jest.Mock;
  let original: typeof globalThis.fetch | undefined;
  let stderr: jest.SpyInstance;

  beforeEach(() => {
    jest.useFakeTimers();
    original = globalThis.fetch;
    fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    (globalThis as { fetch: unknown }).fetch = fetchMock;
    stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    jest.useRealTimers();
    (globalThis as { fetch: unknown }).fetch = original;
    stderr.mockRestore();
  });

  const body = (i = 0): Record<string, any> =>
    JSON.parse((fetchMock.mock.calls[i]![1] as { body: string }).body);
  const logged = (): string => stderr.mock.calls.map((c) => String(c[0])).join('');

  describe('config validation', () => {
    it.each([
      ['http://hooks.slack.com/services/a/b/c'],
      ['https://evil.example.com/services/a/b/c'],
      ['https://hooks.slack.com/other/path'],
      ['https://user:pw@hooks.slack.com/services/a/b/c'],
      ['not a url'],
      [''],
    ])('rejects %s without echoing it', (bad) => {
      let err: unknown;
      try {
        new SlackTransport({ webhookUrl: bad });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(TypeError);
      if (bad) expect((err as Error).message).not.toContain(bad);
    });

    it('allows a custom https host only when opted in, and still requires https', () => {
      expect(
        () =>
          new SlackTransport({ webhookUrl: 'https://proxy.example.com/x', allowCustomUrl: true })
      ).not.toThrow();
      expect(
        () => new SlackTransport({ webhookUrl: 'http://proxy.example.com/x', allowCustomUrl: true })
      ).toThrow(TypeError);
    });

    it('rejects an unknown level and defaults to error', () => {
      expect(() => new SlackTransport({ webhookUrl: URL_OK, level: 'loud' })).toThrow(TypeError);
      expect(new SlackTransport({ webhookUrl: URL_OK }).level).toBe('error');
    });

    it('does not expose the URL through JSON or inspect', () => {
      const t = new SlackTransport({ webhookUrl: URL_OK });
      expect(JSON.stringify(t)).not.toContain('SECRETTOKEN123');
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      expect(require('node:util').inspect(t, { depth: 6 })).not.toContain('SECRETTOKEN123');
    });
  });

  it('posts a Block Kit payload with text fallback, header, context and data', async () => {
    const t = new SlackTransport({
      webhookUrl: URL_OK,
      username: 'bot',
      iconEmoji: ':robot_face:',
    });
    t.write(entry({ appName: 'api', environment: 'prod', traceId: 'abc', data: { orderId: 7 } }));
    await t.flush();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const p = body();
    expect(p.text).toContain('[ERROR] boom');
    expect(p.username).toBe('bot');
    expect(p.icon_emoji).toBe(':robot_face:');
    expect(p.blocks[0]).toMatchObject({ type: 'header', text: { type: 'plain_text' } });
    expect(p.blocks[0].text.text).toBe('[ERROR] boom');
    const ctx = JSON.stringify(p.blocks[1]);
    expect(ctx).toContain('api');
    expect(ctx).toContain('prod');
    expect(ctx).toContain('abc');
    expect(p.blocks[2].text.text).toBe('```{"orderId":7}```');
    expect((fetchMock.mock.calls[0]![1] as { method: string }).method).toBe('POST');
  });

  it('filters by level (default error) and by custom filter', async () => {
    const t = new SlackTransport({ webhookUrl: URL_OK, filter: (e) => e.message !== 'skip' });
    t.write(entry({ level: 'info' }));
    t.write(entry({ level: 'warn' }));
    t.write(entry({ message: 'skip' }));
    t.write(entry({ level: 'fatal', message: 'dead' }));
    await t.flush();
    expect(body().text).toContain('dead');
    expect(body().blocks).toHaveLength(2);
    const w = new SlackTransport({ webhookUrl: URL_OK, level: 'warn' });
    w.write(entry({ level: 'warn' }));
    await w.flush();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('batches entries inside minIntervalMs into one message and sends the next window later', async () => {
    const t = new SlackTransport({ webhookUrl: URL_OK, minIntervalMs: 1000 });
    t.write(entry({ message: 'one' }));
    await jest.advanceTimersByTimeAsync(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    t.write(entry({ message: 'two' }));
    t.write(entry({ message: 'three' }));
    await jest.advanceTimersByTimeAsync(500);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(600);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const text = body(1).text as string;
    expect(text).toContain('two');
    expect(text).toContain('three');
    await t.close();
  });

  it('caps a message at 10 entries and reports the overflow', async () => {
    const t = new SlackTransport({ webhookUrl: URL_OK });
    for (let i = 0; i < 15; i += 1) t.write(entry({ message: `m${i}` }));
    await t.flush();
    const p = body();
    expect(p.blocks.length).toBeLessThanOrEqual(50);
    expect(JSON.stringify(p.blocks.at(-1))).toContain('5 more entries');
  });

  it('escapes &, <, > and disarms mentions in every field', async () => {
    const t = new SlackTransport({ webhookUrl: URL_OK });
    t.write(
      entry({
        message: '<!channel> <!here> <@U123> a&b',
        appName: '<!everyone>',
        data: { x: '<!channel> ```break``` @here' },
      })
    );
    await t.flush();
    const raw = JSON.stringify(body());
    expect(raw).not.toContain('<!channel>');
    expect(raw).not.toContain('<!here>');
    expect(raw).not.toContain('<!everyone>');
    expect(raw).not.toContain('<@U123>');
    const p = body();
    expect(p.text).toContain('&lt;!channel&gt;');
    expect(p.text).toContain('a&amp;b');
    expect(p.blocks[2].text.text.slice(3, -3)).not.toContain('```');
    expect(escapeSlack('@everyone')).not.toBe('@everyone');
  });

  it('truncates the header, data and fallback text', async () => {
    const t = new SlackTransport({ webhookUrl: URL_OK });
    t.write(
      entry({ message: 'm'.repeat(5000), appName: 'a'.repeat(5000), data: { d: '<'.repeat(9000) } })
    );
    await t.flush();
    const p = body();
    expect(p.blocks[0].text.text.length).toBeLessThanOrEqual(150);
    expect(p.blocks[2].text.text.length).toBeLessThanOrEqual(2500 + 6);
    expect(p.blocks[1].elements[0].text.length).toBeLessThan(400);
    expect(p.text.length).toBeLessThanOrEqual(1000);
    expect(p.blocks[2].text.text).not.toMatch(/&[a-z]{0,3}…/);
  });

  it('uses a custom formatter and falls back when it throws', async () => {
    const t = new SlackTransport({
      webhookUrl: URL_OK,
      formatter: (e) => {
        if (e.message === 'bad') throw new Error('x');
        return { text: `custom ${e.message}`, blocks: [{ type: 'divider' }] };
      },
    });
    t.write(entry({ message: 'ok' }));
    t.write(entry({ message: 'bad' }));
    await t.flush();
    const p = body();
    expect(p.text).toContain('custom ok');
    expect(p.blocks[0]).toEqual({ type: 'divider' });
    expect(p.blocks[1].type).toBe('header');
  });

  describe('failures', () => {
    it('throws on 500 without leaking the URL and keeps the entries for retry', async () => {
      fetchMock.mockResolvedValueOnce({ ok: false, status: 500 });
      const t = new SlackTransport({ webhookUrl: URL_OK });
      t.write(entry());
      const err = (await t.flush().catch((e: Error) => e)) as Error;
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toContain('500');
      expect(err.message).toContain('hooks.slack.com');
      expect(err.message).not.toContain('SECRETTOKEN123');
      await jest.advanceTimersByTimeAsync(5000);
      expect(fetchMock).toHaveBeenCalledTimes(2);
      await t.close();
    });

    it('drops the batch on a permanent 4xx', async () => {
      fetchMock.mockResolvedValue({ ok: false, status: 404 });
      const t = new SlackTransport({ webhookUrl: URL_OK });
      t.write(entry());
      await expect(t.flush()).rejects.toThrow('404');
      await jest.advanceTimersByTimeAsync(60_000);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('never puts the URL in network errors', async () => {
      fetchMock.mockRejectedValue(
        Object.assign(new TypeError(`fetch failed ${URL_OK}`), { cause: { code: 'ECONNREFUSED' } })
      );
      const t = new SlackTransport({ webhookUrl: URL_OK });
      t.write(entry());
      const err = (await t.flush().catch((e: Error) => e)) as Error;
      expect(err.message).toContain('ECONNREFUSED');
      expect(err.message).not.toContain('SECRETTOKEN123');
      await t.close();
      expect(logged()).not.toContain('SECRETTOKEN123');
    });

    it('waits for Retry-After on 429 and retries once', async () => {
      fetchMock
        .mockResolvedValueOnce({ ok: false, status: 429, headers: { get: () => '2' } })
        .mockResolvedValueOnce({ ok: true, status: 200 });
      const t = new SlackTransport({ webhookUrl: URL_OK });
      t.write(entry());
      const p = t.flush();
      await jest.advanceTimersByTimeAsync(1900);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      await jest.advanceTimersByTimeAsync(200);
      await p;
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('gives up after maxRetries on repeated 429', async () => {
      fetchMock.mockResolvedValue({ ok: false, status: 429, headers: { get: () => '1' } });
      const t = new SlackTransport({ webhookUrl: URL_OK, maxRetries: 1 });
      t.write(entry());
      const p = t.flush().catch((e: Error) => e);
      await jest.advanceTimersByTimeAsync(1500);
      expect(((await p) as Error).message).toContain('429');
      expect(fetchMock).toHaveBeenCalledTimes(2);
      fetchMock.mockResolvedValue({ ok: true, status: 200 });
      await t.close();
    });
  });

  it('bounds the queue and counts drops', async () => {
    const t = new SlackTransport({ webhookUrl: URL_OK, maxBufferSize: 10 });
    for (let i = 0; i < 15; i += 1) t.write(entry({ message: `m${i}` }));
    await t.flush();
    const text = body().text as string;
    expect(text).toContain('m14');
    expect(text).not.toContain('m0');
    expect(logged()).toContain('buffer full (10)');
  });

  it('close() flushes pending entries and stops accepting new ones', async () => {
    const t = new SlackTransport({ webhookUrl: URL_OK, minIntervalMs: 60_000 });
    t.write(entry({ message: 'first' }));
    await jest.advanceTimersByTimeAsync(0);
    t.write(entry({ message: 'pending' }));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await t.close();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(body(1).text).toContain('pending');
    t.write(entry({ message: 'late' }));
    await jest.advanceTimersByTimeAsync(120_000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
