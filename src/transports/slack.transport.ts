/**
 * Slack incoming-webhook transport — send logixia log entries to a Slack channel.
 *
 * Slack incoming webhooks accept a JSON body with a plain-text `text` fallback
 * plus a `blocks` array of Block Kit elements. This transport is deliberately
 * dependency-free: it builds the webhook payload directly and POSTs it with the
 * global `fetch`, mirroring the OTLP transport's self-contained style.
 *
 * Rate limiting: entries are buffered and flushed at most once per
 * `minIntervalMs` (default 1000ms). Entries that arrive inside the window are
 * batched into a single message (one `text` line + one block set per entry).
 *
 * @example
 * ```ts
 * transports: {
 *   custom: [ new SlackTransport({
 *     webhookUrl: 'https://hooks.slack.com/services/T/B/Q',
 *     level: 'error',
 *     username: 'logixia',
 *   }) ],
 * }
 * ```
 */

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { safeToString } from '../utils/coerce.utils';
import { internalWarn } from '../utils/internal-log';

/** Slack header block `plain_text` limit (characters). */
const HEADER_LIMIT = 150;
/** Slack `mrkdwn` text limit for the data code block (kept conservative). */
const CODE_LIMIT = 2500;

export interface SlackTransportConfig {
  /** Slack incoming-webhook URL. Must be an `https:` URL. */
  webhookUrl: string;
  /** Minimum level to forward. Default: 'error' (avoids flooding a channel). */
  level?: string;
  /** Override the bot username shown in the channel. */
  username?: string;
  /** Override the bot icon emoji (e.g. ':warning:'). */
  iconEmoji?: string;
  /**
   * Minimum interval (ms) between webhook requests. Entries arriving inside the
   * window are batched into a single message. Default: 1000.
   */
  minIntervalMs?: number;
  /** Predicate evaluated before writing; return false to skip this entry. */
  filter?: (entry: TransportLogEntry) => boolean;
  /**
   * Override the default blocks for an entry — return a custom block object.
   */
  formatter?: (entry: TransportLogEntry) => Record<string, unknown>;
}

/** Truncate `text` to `limit` characters, appending an ellipsis when cut. */
function truncate(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit - 3)}...` : text;
}

export class SlackTransport implements IAsyncTransport {
  public readonly name = 'slack';
  public readonly level: string;
  public readonly filter?: (entry: TransportLogEntry) => boolean;

  private readonly webhookUrl: string;
  private readonly username: string | undefined;
  private readonly iconEmoji: string | undefined;
  private readonly minIntervalMs: number;
  private readonly formatter?: (entry: TransportLogEntry) => Record<string, unknown>;

  private batch: TransportLogEntry[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private lastFlushAt = Date.now();
  private flushing = false;

  constructor(config: SlackTransportConfig) {
    if (typeof config.webhookUrl !== 'string' || !config.webhookUrl.startsWith('https:')) {
      throw new TypeError('SlackTransport: webhookUrl must be an https: URL');
    }
    this.webhookUrl = config.webhookUrl;
    this.level = config.level ?? 'error';
    this.username = config.username;
    this.iconEmoji = config.iconEmoji;
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

  /** Drain every buffered entry into a single Slack message. */
  async flush(): Promise<void> {
    if (this.flushing || this.batch.length === 0) return;
    this.flushing = true;
    try {
      const entries = this.batch.splice(0);
      try {
        await this.send(entries);
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

  private async send(entries: TransportLogEntry[]): Promise<void> {
    if (typeof fetch !== 'function') {
      internalWarn('SlackTransport: global fetch unavailable — cannot send logs');
      return;
    }

    const textParts: string[] = [];
    const blocks: Array<Record<string, unknown>> = [];
    for (const entry of entries) {
      textParts.push(`[${entry.level.toUpperCase()}] ${entry.message}`);
      blocks.push(...this.toBlocks(entry));
    }

    const payload: Record<string, unknown> = {
      ...(this.username ? { username: this.username } : {}),
      ...(this.iconEmoji ? { icon_emoji: this.iconEmoji } : {}),
      text: textParts.join('\n'),
      blocks,
    };

    const res = await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Slack webhook failed: HTTP ${res.status}`);
    }
  }

  /** Build the default Block Kit blocks, or defer to a custom `formatter`. */
  private toBlocks(entry: TransportLogEntry): Array<Record<string, unknown>> {
    if (this.formatter) return [this.formatter(entry)];

    const blocks: Array<Record<string, unknown>> = [];

    blocks.push({
      type: 'header',
      text: {
        type: 'plain_text',
        text: truncate(`[${entry.level.toUpperCase()}] ${entry.message}`, HEADER_LIMIT),
      },
    });

    const contextParts: string[] = [];
    if (entry.appName !== undefined) contextParts.push(`*appName:* ${entry.appName}`);
    if (entry.environment !== undefined) contextParts.push(`*environment:* ${entry.environment}`);
    if (entry.traceId !== undefined) contextParts.push(`*traceId:* ${entry.traceId}`);
    if (contextParts.length > 0) {
      blocks.push({
        type: 'context',
        elements: [{ type: 'mrkdwn', text: contextParts.join('  |  ') }],
      });
    }

    if (entry.data && Object.keys(entry.data).length > 0) {
      let json: string;
      try {
        json = JSON.stringify(entry.data, null, 2);
      } catch {
        json = safeToString(entry.data);
      }
      blocks.push({
        type: 'section',
        text: { type: 'mrkdwn', text: truncate(`\`\`\`\n${json}\n\`\`\``, CODE_LIMIT) },
      });
    }

    return blocks;
  }
}
