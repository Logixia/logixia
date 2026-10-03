/**
 * Discord webhook transport — send logixia log entries to a Discord channel.
 *
 * Discord webhooks accept a JSON body with an optional `content` string and up
 * to 10 `embeds`. This transport is deliberately dependency-free: it builds the
 * webhook payload directly and POSTs it with the global `fetch`, mirroring the
 * OTLP transport's self-contained style.
 *
 * Rate limiting: entries are buffered and flushed at most once per
 * `minIntervalMs` (default 1000ms). A single flush sends at most 10 embeds; any
 * entries beyond that are dropped and reported in the `content` counter line so
 * no log is silently swallowed.
 *
 * @example
 * ```ts
 * transports: {
 *   custom: [ new DiscordTransport({
 *     webhookUrl: 'https://discord.com/api/webhooks/123/abc',
 *     level: 'error',
 *     username: 'logixia',
 *   }) ],
 * }
 * ```
 */

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { safeToString } from '../utils/coerce.utils';
import { internalWarn } from '../utils/internal-log';

/** Discord caps webhook payloads at 10 embeds per request. */
const MAX_EMBEDS = 10;
/** Discord embed title limit (characters). */
const TITLE_LIMIT = 256;
/** Discord embed description limit (characters). */
const DESCRIPTION_LIMIT = 4096;
/** Discord embed field value limit (characters). */
const FIELD_VALUE_LIMIT = 1024;

/**
 * Level → Discord embed colour. Error is Discord's red, warn yellow, info blue.
 * Unlisted/custom levels fall back to a neutral grey.
 */
const LEVEL_COLOURS: Readonly<Record<string, number>> = {
  error: 0xed4245,
  warn: 0xfee75c,
  warning: 0xfee75c,
  info: 0x3498db,
};
const DEFAULT_COLOUR = 0x95a5a6;

/** Default backoff when a 429 response has no `retry_after` field. */
const DEFAULT_RETRY_AFTER_MS = 1000;

export interface DiscordTransportConfig {
  /** Discord webhook URL. Must be an `https:` URL. */
  webhookUrl: string;
  /** Minimum level to forward. Default: 'error' (avoids flooding a channel). */
  level?: string;
  /** Override the bot username shown in the channel. */
  username?: string;
  /** Override the bot avatar URL shown in the channel. */
  avatarUrl?: string;
  /**
   * Minimum interval (ms) between webhook requests. Entries arriving inside the
   * window are batched into a single request. Default: 1000.
   */
  minIntervalMs?: number;
  /** Predicate evaluated before writing; return false to skip this entry. */
  filter?: (entry: TransportLogEntry) => boolean;
  /** Override the default embed for an entry. */
  formatter?: (entry: TransportLogEntry) => Record<string, unknown>;
}

/** Truncate `text` to `limit` characters, appending an ellipsis when cut. */
function truncate(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit - 3)}...` : text;
}

/** Resolve a promise after `ms` milliseconds (mockable via fake timers). */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export class DiscordTransport implements IAsyncTransport {
  public readonly name = 'discord';
  public readonly level: string;
  public readonly filter?: (entry: TransportLogEntry) => boolean;

  private readonly webhookUrl: string;
  private readonly username: string | undefined;
  private readonly avatarUrl: string | undefined;
  private readonly minIntervalMs: number;
  private readonly formatter?: (entry: TransportLogEntry) => Record<string, unknown>;

  private batch: TransportLogEntry[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private lastFlushAt = Date.now();
  private flushing = false;

  constructor(config: DiscordTransportConfig) {
    if (typeof config.webhookUrl !== 'string' || !config.webhookUrl.startsWith('https:')) {
      throw new TypeError('DiscordTransport: webhookUrl must be an https: URL');
    }
    this.webhookUrl = config.webhookUrl;
    this.level = config.level ?? 'error';
    this.username = config.username;
    this.avatarUrl = config.avatarUrl;
    this.minIntervalMs = config.minIntervalMs ?? 1000;
    if (config.filter) this.filter = config.filter;
    if (config.formatter) this.formatter = config.formatter;
  }

  write(entry: TransportLogEntry): void {
    this.batch.push(entry);
    this.scheduleFlush();
  }

  /** Flush at most once per `minIntervalMs`; otherwise defer until the window ends. */
  private scheduleFlush(): void {
    const now = Date.now();
    const elapsed = now - this.lastFlushAt;
    if (elapsed >= this.minIntervalMs) {
      this.flush().catch(() => {});
      return;
    }
    if (this.flushTimer === null) {
      this.flushTimer = setTimeout(() => {
        this.flushTimer = null;
        this.flush().catch(() => {});
      }, this.minIntervalMs - elapsed);
      if (this.flushTimer.unref) this.flushTimer.unref();
    }
  }

  /**
   * Send one webhook request with up to {@link MAX_EMBEDS} embeds. Entries
   * beyond the cap are dropped and reported in the `content` counter line.
   */
  async flush(): Promise<void> {
    if (this.flushing || this.batch.length === 0) return;
    this.flushing = true;
    try {
      const entries = this.batch.splice(0, MAX_EMBEDS);
      const dropped = this.batch.length;
      this.batch.length = 0;
      try {
        await this.send(entries, dropped);
        this.lastFlushAt = Date.now();
      } catch (err) {
        // Re-buffer so a transient failure is not silently lost.
        this.batch.unshift(...entries);
        throw err;
      }
    } finally {
      this.flushing = false;
    }
  }

  async close(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  private async send(entries: TransportLogEntry[], dropped: number): Promise<void> {
    if (typeof fetch !== 'function') {
      internalWarn('DiscordTransport: global fetch unavailable — cannot send logs');
      return;
    }
    const payload: Record<string, unknown> = {
      ...(this.username ? { username: this.username } : {}),
      ...(this.avatarUrl ? { avatar_url: this.avatarUrl } : {}),
      ...(dropped > 0 ? { content: `…${dropped} additional log(s) dropped this interval` } : {}),
      embeds: entries.map((entry) => this.toEmbed(entry)),
    };
    await this.post(payload);
  }

  /** POST the payload, honouring Discord's 429 `retry_after` with one retry. */
  private async post(payload: Record<string, unknown>): Promise<void> {
    let res = await this.fetchJson(payload);
    if (res.ok) return;

    if (res.status === 429) {
      const retryAfterMs = await this.readRetryAfter(res);
      await sleep(retryAfterMs);
      res = await this.fetchJson(payload);
      if (res.ok) return;
    }

    throw new Error(`Discord webhook failed: HTTP ${res.status}`);
  }

  private fetchJson(payload: Record<string, unknown>): Promise<Response> {
    return fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }

  /** Read Discord's `retry_after` (milliseconds) from a 429 body, else default. */
  private async readRetryAfter(res: Response): Promise<number> {
    try {
      const body = (await res.json()) as { retry_after?: unknown };
      if (typeof body?.retry_after === 'number' && body.retry_after >= 0) {
        return body.retry_after;
      }
    } catch {
      // Non-JSON body — fall through to the default backoff.
    }
    return DEFAULT_RETRY_AFTER_MS;
  }

  /** Build the default embed, or defer to a custom `formatter` when provided. */
  private toEmbed(entry: TransportLogEntry): Record<string, unknown> {
    if (this.formatter) return this.formatter(entry);

    const title = truncate(`[${entry.level.toUpperCase()}] ${entry.message}`, TITLE_LIMIT);
    const colour = LEVEL_COLOURS[entry.level.toLowerCase()] ?? DEFAULT_COLOUR;

    const fields: Array<{ name: string; value: string; inline: boolean }> = [];
    if (entry.appName !== undefined) {
      fields.push({
        name: 'appName',
        value: truncate(String(entry.appName), FIELD_VALUE_LIMIT),
        inline: true,
      });
    }
    if (entry.environment !== undefined) {
      fields.push({
        name: 'environment',
        value: truncate(String(entry.environment), FIELD_VALUE_LIMIT),
        inline: true,
      });
    }
    if (entry.traceId !== undefined) {
      fields.push({
        name: 'traceId',
        value: truncate(String(entry.traceId), FIELD_VALUE_LIMIT),
        inline: true,
      });
    }

    const embed: Record<string, unknown> = { title, color: colour };
    const description = this.buildDescription(entry);
    if (description !== '') embed['description'] = description;
    if (fields.length > 0) embed['fields'] = fields;
    return embed;
  }

  /** Render `data` as a JSON code block, truncated to Discord's description limit. */
  private buildDescription(entry: TransportLogEntry): string {
    if (!entry.data || Object.keys(entry.data).length === 0) return '';
    let json: string;
    try {
      json = JSON.stringify(entry.data, null, 2);
    } catch {
      json = safeToString(entry.data);
    }
    return truncate(`\`\`\`json\n${json}\n\`\`\``, DESCRIPTION_LIMIT);
  }
}
