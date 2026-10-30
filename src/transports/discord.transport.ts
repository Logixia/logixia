/**
 * Discord webhook transport.
 *
 * Sends error-level (by default) entries to a Discord channel as embeds.
 * Entries inside `minIntervalMs` are batched into one request (max 10 embeds;
 * the overflow is dropped and counted in the message `content`). Every request
 * carries `allowed_mentions: { parse: [] }` so logged data can never ping
 * @everyone, roles or users, and logged text has its markdown escaped.
 *
 * Limits follow https://discord.com/developers/docs/resources/message#embed-object-embed-limits
 *
 * The webhook URL is a secret: it is never logged and never appears in errors.
 *
 * @example
 * transports: { custom: [ new DiscordTransport({ webhookUrl: process.env.DISCORD_WEBHOOK_URL! }) ] }
 */

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalWarn } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';
import {
  DEFAULT_WEBHOOK_TIMEOUT_MS,
  defuseText,
  meetsLevel,
  parseWebhookUrl,
  resolveMinLevel,
  retryAfterHeaderMs,
  singleLine,
  truncateText,
  WebhookQueue,
  type WebhookResponseLike,
} from './webhook-queue';

export const DISCORD_TITLE_MAX = 256;
export const DISCORD_DESCRIPTION_MAX = 4096;
export const DISCORD_FIELD_VALUE_MAX = 1024;
export const DISCORD_EMBEDS_MAX = 10;
export const DISCORD_FIELDS_MAX = 25;
export const DISCORD_EMBED_TOTAL_MAX = 6000;
export const DISCORD_CONTENT_MAX = 2000;
const FIELD_VALUE_CAP = 64;
const FENCE_OVERHEAD = '```json\n\n```'.length;
const MIN_USEFUL_BODY = 20;

export interface DiscordEmbedField {
  name: string;
  value: string;
  inline?: boolean;
}

export interface DiscordEmbed {
  title?: string;
  description?: string;
  color?: number;
  timestamp?: string;
  fields?: DiscordEmbedField[];
  [key: string]: unknown;
}

export interface DiscordTransportConfig {
  /** Webhook URL (secret). Must be https on discord.com / discordapp.com unless `allowCustomUrl`. */
  webhookUrl: string;
  /** Minimum level to send. Default: 'error'. */
  level?: string;
  username?: string;
  /** https URL of the avatar shown for the webhook. */
  avatarUrl?: string;
  /** Entries within this window are batched into one request. Default: 1000. */
  minIntervalMs?: number;
  /**
   * Overrides the embed built for each entry. Limits are still enforced, but
   * escaping the content is the formatter's responsibility.
   */
  formatter?: (entry: TransportLogEntry) => DiscordEmbed;
  filter?: (entry: TransportLogEntry) => boolean;
  /** Accept an https webhook URL on any host (e.g. a proxy or Discord-compatible service). */
  allowCustomUrl?: boolean;
  /** Retries after an HTTP 429 (waits retry_after, max 30s). Default: 1. */
  maxRetries?: number;
  /** Max queued entries; the oldest are dropped past this. Default: 1000. */
  maxBufferSize?: number;
  requestTimeoutMs?: number;
}

export const DISCORD_LEVEL_COLORS: Record<string, number> = {
  fatal: 0x992d22,
  error: 0xed4245,
  warn: 0xfee75c,
  warning: 0xfee75c,
  info: 0x3498db,
  debug: 0x95a5a6,
  verbose: 0x95a5a6,
  trace: 0x95a5a6,
};
const DEFAULT_COLOR = 0x95a5a6;

/** Escapes Discord markdown and defuses @everyone / @here and code fences. */
export function escapeDiscord(text: string): string {
  return defuseText(text.replace(/[\\*_~`|>#[\]()]/g, '\\$&'));
}

function embedChars(embed: DiscordEmbed): number {
  return (
    (embed.title?.length ?? 0) +
    (embed.description?.length ?? 0) +
    (embed.fields ?? []).reduce((n, f) => n + f.name.length + f.value.length, 0)
  );
}

function codeBlock(json: string, max: number): string {
  return `\`\`\`json\n${truncateText(
    json.replace(/`{3,}/g, (m) => m.split('').join('​')),
    max
  )}\n\`\`\``;
}

function clampCustomEmbed(embed: DiscordEmbed): DiscordEmbed {
  const out: DiscordEmbed = { ...embed };
  if (typeof out.title === 'string') out.title = truncateText(out.title, DISCORD_TITLE_MAX);
  if (typeof out.description === 'string') {
    out.description = truncateText(out.description, DISCORD_DESCRIPTION_MAX);
  }
  if (Array.isArray(out.fields)) {
    out.fields = out.fields.slice(0, DISCORD_FIELDS_MAX).map((f) => ({
      ...f,
      name: truncateText(String(f.name), DISCORD_TITLE_MAX),
      value: truncateText(String(f.value), DISCORD_FIELD_VALUE_MAX),
    }));
  }
  return out;
}

interface EmbedDraft {
  embed: DiscordEmbed;
  json: string | undefined;
}

export class DiscordTransport implements IAsyncTransport {
  public readonly name = 'discord';
  public readonly level: string;
  public filter?: (entry: TransportLogEntry) => boolean;

  private readonly queue!: WebhookQueue;
  private readonly username: string | undefined;
  private readonly avatarUrl: string | undefined;
  private readonly formatter: ((entry: TransportLogEntry) => DiscordEmbed) | undefined;

  constructor(config: DiscordTransportConfig) {
    const url = parseWebhookUrl(config.webhookUrl, {
      label: 'DiscordTransport',
      hostMatches: (h) =>
        ['discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com'].includes(h),
      pathMatches: (p) => /^\/api(\/v\d+)?\/webhooks\//.test(p),
      expected: 'discord.com',
      allowCustomUrl: config.allowCustomUrl,
    });
    if (config.avatarUrl !== undefined && !/^https:\/\//i.test(config.avatarUrl)) {
      throw new TypeError('DiscordTransport: avatarUrl must use https:');
    }
    this.level = resolveMinLevel(config.level, 'DiscordTransport');
    if (config.filter) this.filter = config.filter;
    this.username = config.username;
    this.avatarUrl = config.avatarUrl;
    this.formatter = config.formatter;
    const queue = new WebhookQueue({
      label: 'DiscordTransport',
      url,
      minIntervalMs: config.minIntervalMs,
      maxPerMessage: DISCORD_EMBEDS_MAX,
      maxQueueSize: config.maxBufferSize,
      maxRetries: config.maxRetries,
      requestTimeoutMs: config.requestTimeoutMs ?? DEFAULT_WEBHOOK_TIMEOUT_MS,
      build: (entries, overflow) => this.buildPayload(entries, overflow),
      retryAfterMs: readRetryAfter,
    });
    // non-enumerable so util.inspect / spreads of the transport never reach the secret URL
    Object.defineProperty(this, 'queue', { value: queue, enumerable: false });
  }

  write(entry: TransportLogEntry): void {
    if (!meetsLevel(entry.level, this.level)) return;
    if (this.filter && !this.filter(entry)) return;
    this.queue.push(entry);
  }

  flush(): Promise<void> {
    return this.queue.flush();
  }

  close(): Promise<void> {
    return this.queue.close();
  }

  /** Never serialise the webhook URL (JSON.stringify, util.inspect). */
  toJSON(): Record<string, unknown> {
    return { name: this.name, level: this.level };
  }

  private buildPayload(entries: TransportLogEntry[], overflow: number): Record<string, unknown> {
    const drafts = entries.map((e) => this.draftFor(e));
    const kept = this.fitToBudget(drafts);
    const dropped = overflow + (drafts.length - kept.length);

    const payload: Record<string, unknown> = {
      embeds: kept.map((d) => d.embed),
      allowed_mentions: { parse: [] },
    };
    if (dropped > 0) {
      payload['content'] = truncateText(
        `… and ${dropped} more entr${dropped === 1 ? 'y' : 'ies'} not shown`,
        DISCORD_CONTENT_MAX
      );
    }
    if (this.username) payload['username'] = truncateText(this.username, 80);
    if (this.avatarUrl) payload['avatar_url'] = this.avatarUrl;
    return payload;
  }

  /** Enforces the 6000-char total: drops trailing embeds if needed, then shares the rest among descriptions. */
  private fitToBudget(drafts: EmbedDraft[]): EmbedDraft[] {
    const kept = [...drafts];
    const base = () => kept.reduce((n, d) => n + embedChars(d.embed), 0);
    while (kept.length > 1 && base() > DISCORD_EMBED_TOTAL_MAX) kept.pop();
    const withData = kept.filter((d) => d.json !== undefined);
    if (withData.length === 0) return kept;
    const share = Math.floor((DISCORD_EMBED_TOTAL_MAX - base()) / withData.length);
    const body = Math.min(DISCORD_DESCRIPTION_MAX, share) - FENCE_OVERHEAD;
    for (const d of withData) {
      if (body >= MIN_USEFUL_BODY) d.embed.description = codeBlock(d.json!, body);
    }
    return kept;
  }

  private draftFor(entry: TransportLogEntry): EmbedDraft {
    if (this.formatter) {
      try {
        return { embed: clampCustomEmbed(this.formatter(entry)), json: undefined };
      } catch {
        internalWarn('DiscordTransport: formatter threw; using the default embed');
      }
    }
    return defaultDraft(entry);
  }
}

function defaultDraft(entry: TransportLogEntry): EmbedDraft {
  const title = `[${singleLine(entry.level).toUpperCase()}] ${escapeDiscord(singleLine(entry.message))}`;
  const fields: DiscordEmbedField[] = [
    ['appName', entry.appName],
    ['environment', entry.environment],
    ['context', entry.context],
    ['traceId', entry.traceId],
  ]
    .filter((pair): pair is [string, string] => typeof pair[1] === 'string' && pair[1] !== '')
    .map(([name, value]) => ({
      name,
      value: truncateText(escapeDiscord(singleLine(value)), FIELD_VALUE_CAP),
      inline: true,
    }));
  const embed: DiscordEmbed = {
    title: truncateText(title, DISCORD_TITLE_MAX),
    color: DISCORD_LEVEL_COLORS[entry.level.toLowerCase()] ?? DEFAULT_COLOR,
    timestamp: entry.timestamp.toISOString(),
    fields,
  };
  const json =
    entry.data && Object.keys(entry.data).length > 0 ? stringifyForLog(entry.data) : undefined;
  return { embed, json };
}

async function readRetryAfter(res: WebhookResponseLike): Promise<number | undefined> {
  try {
    const body = (await res.json?.()) as { retry_after?: unknown } | undefined;
    const seconds = Number(body?.retry_after);
    if (body?.retry_after !== undefined && Number.isFinite(seconds) && seconds >= 0) {
      return seconds * 1000;
    }
  } catch {
    // fall through to the header
  }
  return retryAfterHeaderMs(res);
}
