/* eslint-disable sonarjs/no-clear-text-protocols -- negative tests for http URLs */
import type { TransportLogEntry } from '../../types/transport.types';
import { DISCORD_LEVEL_COLORS, DiscordTransport, escapeDiscord } from '../discord.transport';
import { TransportManager } from '../transport.manager';

const URL_OK = 'https://discord.com/api/webhooks/123456/SECRETTOKEN123';

function entry(over: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'error',
    message: 'boom',
    ...over,
  };
}

function embedSize(e: Record<string, any>): number {
  return (
    (e.title?.length ?? 0) +
    (e.description?.length ?? 0) +
    (e.fields ?? []).reduce((n: number, f: any) => n + f.name.length + f.value.length, 0)
  );
}

describe('DiscordTransport', () => {
  let fetchMock: jest.Mock;
  let original: typeof globalThis.fetch | undefined;
  let stderr: jest.SpyInstance;

  beforeEach(() => {
    jest.useFakeTimers();
    original = globalThis.fetch;
    fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 204 });
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
      ['http://discord.com/api/webhooks/1/x'],
      ['https://evil.example.com/api/webhooks/1/x'],
      ['https://discord.com/other'],
      ['https://u:p@discord.com/api/webhooks/1/x'],
      ['nope'],
      [''],
    ])('rejects %s without echoing it', (bad) => {
      let err: unknown;
      try {
        new DiscordTransport({ webhookUrl: bad });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(TypeError);
      if (bad) expect((err as Error).message).not.toContain(bad);
    });

    it('accepts discordapp.com, versioned paths and opted-in custom hosts', () => {
      for (const u of [
        'https://discordapp.com/api/webhooks/1/x',
        'https://discord.com/api/v10/webhooks/1/x',
      ]) {
        expect(() => new DiscordTransport({ webhookUrl: u })).not.toThrow();
      }
      expect(
        () =>
          new DiscordTransport({ webhookUrl: 'https://proxy.example.com/h', allowCustomUrl: true })
      ).not.toThrow();
    });

    it('requires an https avatarUrl and a known level; defaults to error', () => {
      expect(
        () => new DiscordTransport({ webhookUrl: URL_OK, avatarUrl: 'http://a/b.png' })
      ).toThrow(TypeError);
      expect(() => new DiscordTransport({ webhookUrl: URL_OK, level: 'x' })).toThrow(TypeError);
      expect(new DiscordTransport({ webhookUrl: URL_OK }).level).toBe('error');
    });

    it('does not expose the URL through JSON or inspect', () => {
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      expect(JSON.stringify(t)).not.toContain('SECRETTOKEN123');
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      expect(require('node:util').inspect(t, { depth: 6 })).not.toContain('SECRETTOKEN123');
    });
  });

  it('posts an embed with title, colour, fields, data block and no mentions', async () => {
    const t = new DiscordTransport({
      webhookUrl: URL_OK,
      username: 'bot',
      avatarUrl: 'https://example.com/a.png',
    });
    t.write(entry({ appName: 'api', environment: 'prod', traceId: 'tr1', data: { a: 1 } }));
    await t.flush();
    const p = body();
    expect(p.username).toBe('bot');
    expect(p.avatar_url).toBe('https://example.com/a.png');
    expect(p.allowed_mentions).toEqual({ parse: [] });
    expect(p.content).toBeUndefined();
    const e = p.embeds[0];
    expect(e.title).toBe('[ERROR] boom');
    expect(e.color).toBe(DISCORD_LEVEL_COLORS['error']);
    expect(e.fields.map((f: any) => f.name)).toEqual(['appName', 'environment', 'traceId']);
    expect(e.description).toBe('```json\n{"a":1}\n```');
  });

  it('maps level to colour', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK, level: 'info', minIntervalMs: 0 });
    t.write(entry({ level: 'error' }));
    t.write(entry({ level: 'warn' }));
    t.write(entry({ level: 'info' }));
    await t.flush();
    expect(body().embeds.map((e: any) => e.color)).toEqual([0xed4245, 0xfee75c, 0x3498db]);
  });

  it('filters by level and custom filter', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK });
    t.write(entry({ level: 'warn' }));
    t.write(entry({ message: 'keep' }));
    await t.flush();
    expect(body().embeds).toHaveLength(1);
    expect(body().embeds[0].title).toContain('keep');
  });

  it('caps at 10 embeds and reports the overflow in content', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK });
    for (let i = 0; i < 14; i += 1) t.write(entry({ message: `m${i}` }));
    await t.flush();
    const p = body();
    expect(p.embeds).toHaveLength(10);
    expect(p.content).toContain('4 more entries');
    expect(p.allowed_mentions).toEqual({ parse: [] });
  });

  it('batches entries inside the interval', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK, minIntervalMs: 1000 });
    t.write(entry({ message: 'one' }));
    await jest.advanceTimersByTimeAsync(0);
    t.write(entry({ message: 'two' }));
    t.write(entry({ message: 'three' }));
    await jest.advanceTimersByTimeAsync(1100);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(body(1).embeds).toHaveLength(2);
    await t.close();
  });

  it('enforces title, description and field limits', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK });
    t.write(
      entry({
        message: 'x'.repeat(2000),
        appName: 'a'.repeat(2000),
        data: { big: 'y'.repeat(20_000) },
      })
    );
    await t.flush();
    const e = body().embeds[0];
    expect(e.title.length).toBeLessThanOrEqual(256);
    expect(e.description.length).toBeLessThanOrEqual(4096);
    expect(e.description.length).toBeGreaterThan(3000);
    expect(e.description.endsWith('```')).toBe(true);
    expect(e.fields[0].value.length).toBeLessThanOrEqual(1024);
  });

  it('keeps the total of ten large embeds under 6000 characters', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK });
    for (let i = 0; i < 10; i += 1) {
      t.write(
        entry({
          message: 'm'.repeat(500),
          appName: 'a'.repeat(100),
          environment: 'e'.repeat(100),
          traceId: 't'.repeat(100),
          data: { big: 'z'.repeat(9000) },
        })
      );
    }
    await t.flush();
    const p = body();
    const total = p.embeds.reduce((n: number, e: any) => n + embedSize(e), 0);
    expect(total).toBeLessThanOrEqual(6000);
    expect(p.embeds.length).toBeGreaterThan(0);
    for (const e of p.embeds) {
      if (e.description) expect(e.description.endsWith('```')).toBe(true);
    }
  });

  it('escapes markdown, defuses mentions and code fences', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK });
    t.write(
      entry({
        message: '@everyone **bold** [x](http://evil) <@123>',
        appName: '@here',
        data: { x: '```break``` @everyone' },
      })
    );
    await t.flush();
    const p = body();
    const e = p.embeds[0];
    expect(e.title).not.toContain('@everyone');
    expect(e.title).toContain('\\*\\*bold\\*\\*');
    expect(e.title).toContain('\\[x\\]\\(');
    expect(e.fields[0].value).not.toContain('@here');
    expect(e.description.slice(8, -4)).not.toContain('```');
    expect(p.allowed_mentions.parse).toEqual([]);
    expect(escapeDiscord('a_b')).toBe('a\\_b');
  });

  it('uses a clamped custom formatter and falls back when it throws', async () => {
    const t = new DiscordTransport({
      webhookUrl: URL_OK,
      formatter: (e) => {
        if (e.message === 'bad') throw new Error('x');
        return {
          title: 't'.repeat(999),
          description: 'd'.repeat(9999),
          fields: Array.from({ length: 40 }, (_, i) => ({
            name: `n${i}`,
            value: 'v'.repeat(2000),
          })),
        };
      },
    });
    t.write(entry({ message: 'ok' }));
    await t.flush();
    t.write(entry({ message: 'bad' }));
    await t.flush();
    const custom = body().embeds[0];
    const fallback = body(1).embeds[0];
    expect(custom.title).toHaveLength(256);
    expect(embedSize(custom)).toBeLessThanOrEqual(6000);
    expect(custom.fields.length).toBeLessThanOrEqual(25);
    expect(custom.fields[0].value).toHaveLength(1024);
    expect(fallback.title).toBe('[ERROR] bad');
    expect(body().embeds).toHaveLength(1);
  });

  describe('failures', () => {
    it('throws on 500 without leaking the URL, then retries from the queue', async () => {
      fetchMock.mockResolvedValueOnce({ ok: false, status: 500 });
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry());
      const err = (await t.flush().catch((e: Error) => e)) as Error;
      expect(err.message).toContain('500');
      expect(err.message).toContain('discord.com');
      expect(err.message).not.toContain('SECRETTOKEN123');
      await jest.advanceTimersByTimeAsync(5000);
      expect(fetchMock).toHaveBeenCalledTimes(2);
      await t.close();
    });

    it('drops the batch on a permanent 4xx', async () => {
      fetchMock.mockResolvedValue({ ok: false, status: 404 });
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry());
      await expect(t.flush()).rejects.toThrow('404');
      await jest.advanceTimersByTimeAsync(60_000);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('never puts the URL in network errors or stderr', async () => {
      fetchMock.mockRejectedValue(new TypeError(`fetch failed ${URL_OK}`));
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry());
      const err = (await t.flush().catch((e: Error) => e)) as Error;
      expect(err.message).not.toContain('SECRETTOKEN123');
      await t.close();
      expect(logged()).not.toContain('SECRETTOKEN123');
    });

    it('waits retry_after from the 429 JSON body, then retries once', async () => {
      fetchMock
        .mockResolvedValueOnce({ ok: false, status: 429, json: async () => ({ retry_after: 1.5 }) })
        .mockResolvedValueOnce({ ok: true, status: 204 });
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry());
      const p = t.flush();
      await jest.advanceTimersByTimeAsync(1400);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      await jest.advanceTimersByTimeAsync(200);
      await p;
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('falls back to the Retry-After header and gives up after maxRetries', async () => {
      fetchMock.mockResolvedValue({
        ok: false,
        status: 429,
        json: async () => {
          throw new Error('no body');
        },
        headers: { get: () => '1' },
      });
      const t = new DiscordTransport({ webhookUrl: URL_OK, maxRetries: 1 });
      t.write(entry());
      const p = t.flush().catch((e: Error) => e);
      await jest.advanceTimersByTimeAsync(1500);
      expect(((await p) as Error).message).toContain('429');
      expect(fetchMock).toHaveBeenCalledTimes(2);
      fetchMock.mockResolvedValue({ ok: true, status: 204 });
      await t.close();
    });
  });

  it('bounds the queue and counts drops', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK, maxBufferSize: 10 });
    for (let i = 0; i < 25; i += 1) t.write(entry({ message: `m${i}` }));
    await t.flush();
    const titles = body().embeds.map((e: any) => e.title);
    expect(titles).toContain('[ERROR] m24');
    expect(titles).not.toContain('[ERROR] m0');
    expect(logged()).toContain('buffer full (10)');
  });

  it('close() flushes pending entries and stops accepting new ones', async () => {
    const t = new DiscordTransport({ webhookUrl: URL_OK, minIntervalMs: 60_000 });
    t.write(entry({ message: 'first' }));
    await jest.advanceTimersByTimeAsync(0);
    t.write(entry({ message: 'pending' }));
    await t.close();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(body(1).embeds[0].title).toContain('pending');
    t.write(entry({ message: 'late' }));
    await jest.advanceTimersByTimeAsync(120_000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  describe('review hardening', () => {
    it('delivers good entries when one entry cannot be rendered', async () => {
      const t = new DiscordTransport({
        webhookUrl: URL_OK,
        formatter: (e) => {
          if (e.message === 'poison') return { title: 'poison', timestamp: BigInt(1) as never };
          return { title: e.message };
        },
      });
      t.write(entry({ message: 'good1' }));
      t.write(entry({ message: 'poison' }));
      t.write(entry({ message: 'good2' }));
      await expect(t.flush()).resolves.toBeUndefined();
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const raw = JSON.stringify(body());
      expect(raw).toContain('good1');
      expect(raw).toContain('good2');
      expect(logged()).toContain('cannot be rendered');
      fetchMock.mockClear();
      t.write(entry({ message: 'good3' }));
      await t.flush();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('survives an invalid timestamp', async () => {
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry({ timestamp: new Date('nope'), message: 'late' }));
      await t.flush();
      expect(JSON.stringify(body())).toContain('late');
      expect(JSON.stringify(body())).not.toContain('Invalid');
    });

    it('drops entries once, without retrying, when global fetch is missing', async () => {
      (globalThis as { fetch: unknown }).fetch = undefined;
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry());
      await expect(t.flush()).resolves.toBeUndefined();
      t.write(entry());
      await expect(t.flush()).resolves.toBeUndefined();
      await jest.advanceTimersByTimeAsync(60_000);
      expect(fetchMock).not.toHaveBeenCalled();
      expect(logged().match(/global fetch is unavailable/g)).toHaveLength(1);
    });

    it('level fatal sends fatal only', async () => {
      const t = new DiscordTransport({ webhookUrl: URL_OK, level: 'fatal' });
      t.write(entry({ level: 'error', message: 'plain-error' }));
      t.write(entry({ level: 'fatal', message: 'dead' }));
      await t.flush();
      const raw = JSON.stringify(body());
      expect(raw).toContain('dead');
      expect(raw).not.toContain('plain-error');
    });

    it('does not run the user filter itself (the TransportManager runs it once)', async () => {
      const filter = jest.fn(() => true);
      const t = new DiscordTransport({ webhookUrl: URL_OK, filter });
      const manager = new TransportManager({ custom: [t] });
      await manager.write({
        timestamp: new Date(),
        level: 'error',
        message: 'x',
        appName: 'a',
      } as never);
      expect(filter).toHaveBeenCalledTimes(1);
      await t.flush();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('reports overflow as over the per-message limit, not as a full buffer', async () => {
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      for (let i = 0; i < 25; i += 1) t.write(entry({ message: `m${i}` }));
      await t.flush();
      expect(logged()).toContain('15 entries over the per-message limit (10)');
      expect(logged()).not.toContain('buffer full');
      expect(JSON.stringify(body())).toContain('15 more entries');
    });

    it('close() cancels a pending Retry-After wait and still makes a final send', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: { get: () => '25' },
        json: async () => ({ retry_after: 25 }),
      });
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry());
      const first = t.flush().catch((e: Error) => e);
      await jest.advanceTimersByTimeAsync(100);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const closing = t.close();
      await jest.advanceTimersByTimeAsync(10);
      await closing;
      expect(((await first) as Error).message).toContain('cancelled');
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('cancels response bodies for success, errors and 429', async () => {
      const cancel = jest.fn(async () => {});
      fetchMock
        .mockResolvedValueOnce({ ok: true, status: 204, body: { cancel } })
        .mockResolvedValueOnce({ ok: false, status: 500, body: { cancel } })
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: () => '0' },
          body: { cancel },
        });
      const t = new DiscordTransport({ webhookUrl: URL_OK, maxRetries: 0 });
      t.write(entry());
      await t.flush();
      t.write(entry());
      await t.flush().catch(() => {});
      await jest.advanceTimersByTimeAsync(5000);
      expect(cancel.mock.calls.length).toBeGreaterThanOrEqual(3);
      await t.close();
    });

    it('omits whitespace-only fields instead of sending empty values', async () => {
      const t = new DiscordTransport({ webhookUrl: URL_OK });
      t.write(entry({ context: '   ', traceId: '\n', environment: ' prod ' }));
      await t.flush();
      const fields = body().embeds[0].fields;
      expect(fields.map((f: any) => f.name)).toEqual(['environment']);
      expect(fields.every((f: any) => f.value !== '')).toBe(true);
    });

    it('keeps a single oversized custom embed (footer, author, fields) within 6000 chars', async () => {
      const t = new DiscordTransport({
        webhookUrl: URL_OK,
        formatter: () => ({
          title: 't'.repeat(256),
          description: 'd'.repeat(4096),
          footer: { text: 'f'.repeat(2048) },
          author: { name: 'a'.repeat(256) },
          fields: Array.from({ length: 10 }, (_, i) => ({
            name: `n${i}`,
            value: 'v'.repeat(1024),
          })),
        }),
      });
      t.write(entry());
      await t.flush();
      const e = body().embeds[0];
      const total = embedSize(e) + (e.footer?.text.length ?? 0) + (e.author?.name.length ?? 0);
      expect(total).toBeLessThanOrEqual(6000);
    });

    it('drops trailing custom embeds when several exceed the total', async () => {
      const t = new DiscordTransport({
        webhookUrl: URL_OK,
        formatter: () => ({ title: 't', footer: { text: 'f'.repeat(2048) } }),
      });
      for (let i = 0; i < 5; i += 1) t.write(entry());
      await t.flush();
      const p = body();
      expect(p.embeds.length).toBeLessThanOrEqual(2);
      expect(p.content).toContain('more entries');
    });
  });
});
