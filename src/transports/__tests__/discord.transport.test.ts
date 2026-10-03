/**
 * Tests for the Discord webhook transport.
 *
 * Verifies the webhook payload shape (username/avatar_url/content/embeds),
 * the default embed builder (title truncation, level → colour mapping, data as
 * a JSON code block), the 10-embed cap with drop counter, the 429 retry path,
 * and the error thrown on other non-2xx responses. fetch is mocked — no network.
 */

import type { TransportLogEntry } from '../../types/transport.types';
import { DiscordTransport } from '../discord.transport';

function entry(i: number, over: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `discord-${i}`,
    ...over,
  };
}

interface FetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

describe('DiscordTransport', () => {
  let fetchMock: jest.Mock;
  let original: typeof globalThis.fetch | undefined;

  beforeEach(() => {
    original = globalThis.fetch;
    fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    (globalThis as { fetch: unknown }).fetch = fetchMock;
  });

  afterEach(() => {
    (globalThis as { fetch: unknown }).fetch = original;
    jest.useRealTimers();
  });

  function lastBody(): Record<string, unknown> {
    const call = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
    return JSON.parse((call[1] as FetchInit).body!);
  }

  function embedsOf(body: Record<string, unknown>): Array<Record<string, unknown>> {
    return body.embeds as Array<Record<string, unknown>>;
  }

  it('throws a TypeError when webhookUrl is not an https: URL', () => {
    expect(() => new DiscordTransport({ webhookUrl: 'http://insecure.example/x' })).toThrow(
      TypeError
    );
    expect(() => new DiscordTransport({ webhookUrl: 'not-a-url' })).toThrow(TypeError);
    expect(
      () => new DiscordTransport({ webhookUrl: 'https://discord.com/api/webhooks/1/2' })
    ).not.toThrow();
  });

  it('POSTs an embed with title, colour and metadata fields', async () => {
    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
    });
    t.write(
      entry(1, {
        level: 'error',
        message: 'boom',
        appName: 'api',
        environment: 'prod',
        traceId: 'trace-1',
      })
    );
    await t.flush();

    const body = lastBody();
    const embed = embedsOf(body)[0]!;
    expect(embed.title).toBe('[ERROR] boom');
    expect(embed.color).toBe(0xed4245);
    expect(embed.fields).toEqual([
      { name: 'appName', value: 'api', inline: true },
      { name: 'environment', value: 'prod', inline: true },
      { name: 'traceId', value: 'trace-1', inline: true },
    ]);
    await t.close();
  });

  it('maps warn → yellow and info → blue', async () => {
    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
    });
    t.write(entry(1, { level: 'warn', message: 'careful' }));
    t.write(entry(2, { level: 'info', message: 'fyi' }));
    await t.flush();

    const embeds = embedsOf(lastBody());
    expect(embeds[0]!.color).toBe(0xfee75c);
    expect(embeds[1]!.color).toBe(0x3498db);
    await t.close();
  });

  it('truncates the title to 256 chars and description to 4096', async () => {
    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
    });
    const longMessage = 'x'.repeat(1000);
    const longData = { blob: 'y'.repeat(10_000) };
    t.write(entry(1, { message: longMessage, data: longData }));
    await t.flush();

    const embed = embedsOf(lastBody())[0]!;
    expect((embed.title as string).length).toBeLessThanOrEqual(256);
    expect((embed.title as string).endsWith('...')).toBe(true);
    expect((embed.description as string).length).toBeLessThanOrEqual(4096);
    await t.close();
  });

  it('caps at 10 embeds and reports the dropped overflow in content', async () => {
    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
    });
    for (let i = 0; i < 15; i += 1) t.write(entry(i));
    await t.flush();

    const body = lastBody();
    expect(embedsOf(body)).toHaveLength(10);
    expect(body.content).toContain('5');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await t.close();
  });

  it('retries once after a 429, honouring retry_after', async () => {
    jest.useFakeTimers();
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 429, json: async () => ({ retry_after: 250 }) })
      .mockResolvedValueOnce({ ok: true, status: 200 });

    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
    });
    t.write(entry(1));
    const flushPromise = t.flush();
    await jest.advanceTimersByTimeAsync(250);
    await flushPromise;

    expect(fetchMock).toHaveBeenCalledTimes(2);
    await t.close();
  });

  it('throws on a non-2xx response that is not a 429', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500 });
    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
    });
    t.write(entry(1));

    await expect(t.flush()).rejects.toThrow('HTTP 500');

    // The failed entry was re-buffered; drain it cleanly so close() doesn't re-throw.
    fetchMock.mockResolvedValue({ ok: true, status: 200 });
    await t.close();
  });

  it('re-buffers entries when the POST fails so nothing is lost', async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 503 });
    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
    });
    t.write(entry(1, { message: 'keep-me' }));

    await expect(t.flush()).rejects.toThrow();
    // The failed send re-queued the entry; a second flush (now mocked ok) delivers it.
    await t.flush();

    const embed = embedsOf(lastBody())[0]!;
    expect(embed.title).toBe('[INFO] keep-me');
    await t.close();
  });

  it('honours username/avatarUrl and a custom formatter', async () => {
    const t = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/1/2',
      minIntervalMs: 999_999,
      username: 'logixia',
      avatarUrl: 'https://example.com/avatar.png',
      formatter: (e) => ({ title: `custom:${e.message}` }),
    });
    t.write(entry(1, { message: 'hello' }));
    await t.flush();

    const body = lastBody();
    expect(body.username).toBe('logixia');
    expect(body.avatar_url).toBe('https://example.com/avatar.png');
    expect(embedsOf(body)[0]!.title).toBe('custom:hello');
    await t.close();
  });
});
