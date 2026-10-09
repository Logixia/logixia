/**
 * Tests for the Slack incoming-webhook transport.
 *
 * Verifies the webhook payload shape (text fallback + Block Kit blocks), the
 * default block builder (header/context/code), the level default, batching
 * inside `minIntervalMs`, code-block truncation, the error thrown on non-2xx,
 * and `close()` flushing. fetch is mocked — no network.
 */

import type { TransportLogEntry } from '../../types/transport.types';
import { SlackTransport } from '../slack.transport';

function entry(i: number, over: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `slack-${i}`,
    ...over,
  };
}

interface FetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

describe('SlackTransport', () => {
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

  function blocksOf(body: Record<string, unknown>): Array<Record<string, unknown>> {
    return body.blocks as Array<Record<string, unknown>>;
  }

  it('throws a TypeError when webhookUrl is not an https: URL', () => {
    expect(() => new SlackTransport({ webhookUrl: 'http://insecure.example/x' })).toThrow(
      TypeError
    );
    expect(() => new SlackTransport({ webhookUrl: 'not-a-url' })).toThrow(TypeError);
    expect(
      () => new SlackTransport({ webhookUrl: 'https://hooks.slack.com/services/T/B/Q' })
    ).not.toThrow();
  });

  it('defaults level to "error" and allows overriding it', () => {
    expect(new SlackTransport({ webhookUrl: 'https://hooks.slack.com/services/T/B/Q' }).level).toBe(
      'error'
    );
    expect(
      new SlackTransport({ webhookUrl: 'https://hooks.slack.com/services/T/B/Q', level: 'info' })
        .level
    ).toBe('info');
  });

  it('POSTs a text fallback plus header/context/code blocks', async () => {
    const t = new SlackTransport({
      webhookUrl: 'https://hooks.slack.com/services/T/B/Q',
      minIntervalMs: 999_999,
    });
    t.write(
      entry(1, {
        level: 'error',
        message: 'boom',
        appName: 'api',
        environment: 'prod',
        traceId: 'trace-1',
        data: { code: 42 },
      })
    );
    await t.flush();

    const body = lastBody();
    expect(body.text).toBe('[ERROR] boom');
    const blocks = blocksOf(body);
    expect(blocks[0]).toMatchObject({
      type: 'header',
      text: { type: 'plain_text', text: '[ERROR] boom' },
    });
    expect(blocks[1]).toMatchObject({ type: 'context' });
    expect(JSON.stringify(blocks[1])).toContain('appName');
    expect(JSON.stringify(blocks[1])).toContain('environment');
    expect(JSON.stringify(blocks[1])).toContain('traceId');
    expect(blocks[2]).toMatchObject({ type: 'section' });
    expect((blocks[2] as { text: { text: string } }).text.text).toContain('"code": 42');
    await t.close();
  });

  it('truncates the data code block to ~2500 chars', async () => {
    const t = new SlackTransport({
      webhookUrl: 'https://hooks.slack.com/services/T/B/Q',
      minIntervalMs: 999_999,
    });
    t.write(entry(1, { data: { blob: 'y'.repeat(10_000) } }));
    await t.flush();

    const blocks = blocksOf(lastBody());
    const section = blocks.find((b) => b.type === 'section') as { text: { text: string } };
    expect(section.text.text.length).toBeLessThanOrEqual(2500);
    expect(section.text.text.endsWith('...')).toBe(true);
    await t.close();
  });

  it('batches entries inside minIntervalMs into one request', async () => {
    jest.useFakeTimers();
    const t = new SlackTransport({
      webhookUrl: 'https://hooks.slack.com/services/T/B/Q',
      minIntervalMs: 1000,
    });

    t.write(entry(1));
    t.write(entry(2));
    t.write(entry(3));
    expect(fetchMock).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(1000);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const body = lastBody();
    expect(blocksOf(body)).toHaveLength(3); // one header per entry
    expect(body.text).toContain('slack-1');
    expect(body.text).toContain('slack-3');
    await t.close();
  });

  it('throws on a non-2xx response so the manager retry/fallback can kick in', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500 });
    const t = new SlackTransport({
      webhookUrl: 'https://hooks.slack.com/services/T/B/Q',
      minIntervalMs: 999_999,
    });
    t.write(entry(1));

    await expect(t.flush()).rejects.toThrow('HTTP 500');

    fetchMock.mockResolvedValue({ ok: true, status: 200 });
    await t.close();
  });

  it('close() flushes pending entries', async () => {
    jest.useFakeTimers();
    const t = new SlackTransport({
      webhookUrl: 'https://hooks.slack.com/services/T/B/Q',
      minIntervalMs: 1000,
    });
    t.write(entry(1, { message: 'pending' }));

    // close() clears the pending timer and flushes immediately.
    await t.close();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(lastBody().text).toContain('pending');
  });

  it('honours username/iconEmoji and a custom formatter', async () => {
    const t = new SlackTransport({
      webhookUrl: 'https://hooks.slack.com/services/T/B/Q',
      minIntervalMs: 999_999,
      username: 'logixia',
      iconEmoji: ':warning:',
      formatter: () => ({ type: 'section', text: { type: 'mrkdwn', text: 'custom' } }),
    });
    t.write(entry(1));
    await t.flush();

    const body = lastBody();
    expect(body.username).toBe('logixia');
    expect(body.icon_emoji).toBe(':warning:');
    expect(blocksOf(body)).toEqual([{ type: 'section', text: { type: 'mrkdwn', text: 'custom' } }]);
    await t.close();
  });
});
