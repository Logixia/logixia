/**
 * Slack incoming-webhook transport.
 *
 * Sends error-level (by default) entries to a Slack channel as Block Kit
 * messages. Entries inside `minIntervalMs` are batched into one message so a
 * log storm cannot flood the channel. All logged text is escaped for Slack
 * mrkdwn (`&`, `<`, `>`), which also disarms `<!channel>`, `<!here>` and
 * `<@U123>` mentions coming from logged data.
 *
 * The webhook URL is a secret: it is never logged and never appears in errors.
 *
 * @example
 * transports: { custom: [ new SlackTransport({ webhookUrl: process.env.SLACK_WEBHOOK_URL! }) ] }
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
  safeIso,
  singleLine,
  truncateText,
  WebhookQueue,
} from './webhook-queue';

export const SLACK_HEADER_MAX = 150;
export const SLACK_DATA_MAX = 2500;
const SLACK_FIELD_MAX = 300;
const SLACK_TEXT_MAX = 1000;
const SLACK_MAX_BLOCKS = 50;
const SLACK_MAX_PER_MESSAGE = 10;

/** A Slack message body as returned by a custom `formatter`. */
export interface SlackMessage {
  text?: string;
  blocks?: unknown[];
  [key: string]: unknown;
}

export interface SlackTransportConfig {
  /** Incoming-webhook URL (secret). Must be https on hooks.slack.com unless `allowCustomUrl`. */
  webhookUrl: string;
  /** Minimum level to send. Default: 'error'. */
  level?: string;
  username?: string;
  iconEmoji?: string;
  /** Entries within this window are batched into one message. Default: 1000. */
  minIntervalMs?: number;
  /**
   * Overrides the message built for each entry. The results of one window are
   * merged: texts are joined and blocks concatenated (capped at 50 blocks).
   * Escaping the content is the formatter's responsibility.
   */
  formatter?: (entry: TransportLogEntry) => SlackMessage;
  filter?: (entry: TransportLogEntry) => boolean;
  /** Accept an https webhook URL on any host (e.g. a proxy or Slack-compatible service). */
  allowCustomUrl?: boolean;
  /** Retries after an HTTP 429 (waits Retry-After, max 30s). Default: 1. */
  maxRetries?: number;
  /** Max queued entries; the oldest are dropped past this. Default: 1000. */
  maxBufferSize?: number;
  requestTimeoutMs?: number;
}

/** Escapes the three characters Slack treats specially and defuses broadcast mentions. */
export function escapeSlack(text: string): string {
  return defuseText(text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'));
}

const LEVEL_EMOJI: Record<string, string> = {
  fatal: ':rotating_light:',
  error: ':red_circle:',
  warn: ':warning:',
  warning: ':warning:',
  info: ':information_source:',
};

export class SlackTransport implements IAsyncTransport {
  public readonly name = 'slack';
  public readonly level: string;
  public filter?: (entry: TransportLogEntry) => boolean;

  private readonly queue!: WebhookQueue<SlackMessage>;
  private readonly username: string | undefined;
  private readonly iconEmoji: string | undefined;
  private readonly formatter: ((entry: TransportLogEntry) => SlackMessage) | undefined;

  constructor(config: SlackTransportConfig) {
    const url = parseWebhookUrl(config.webhookUrl, {
      label: 'SlackTransport',
      hostMatches: (h) => h === 'hooks.slack.com' || h === 'hooks.slack-gov.com',
      pathMatches: (p) => p.startsWith('/services/') || p.startsWith('/triggers/'),
      expected: 'hooks.slack.com',
      allowCustomUrl: config.allowCustomUrl,
    });
    this.level = resolveMinLevel(config.level, 'SlackTransport');
    if (config.filter) this.filter = config.filter;
    this.username = config.username;
    this.iconEmoji = config.iconEmoji;
    this.formatter = config.formatter;
    const queue = new WebhookQueue<SlackMessage>({
      label: 'SlackTransport',
      url,
      minIntervalMs: config.minIntervalMs,
      maxPerMessage: SLACK_MAX_PER_MESSAGE,
      maxQueueSize: config.maxBufferSize,
      maxRetries: config.maxRetries,
      requestTimeoutMs: config.requestTimeoutMs ?? DEFAULT_WEBHOOK_TIMEOUT_MS,
      render: (entry) => this.messageFor(entry),
      assemble: (messages, overflow) => this.buildPayload(messages, overflow),
    });
    // non-enumerable so util.inspect / spreads of the transport never reach the secret URL
    Object.defineProperty(this, 'queue', { value: queue, enumerable: false });
  }

  write(entry: TransportLogEntry): void {
    if (!meetsLevel(entry.level, this.level)) return;
    // `filter` is applied by the TransportManager; it is not run again here
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

  private buildPayload(messages: SlackMessage[], overflow: number): Record<string, unknown> {
    const blocks = messages.flatMap((m) => m.blocks ?? []);
    const plural = overflow === 1 ? 'y' : 'ies';
    const counter = overflow > 0 ? `… and ${overflow} more entr${plural} not shown` : '';
    if (counter) {
      blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: counter }] });
    }
    const text = [...messages.map((m) => m.text ?? ''), counter].filter(Boolean).join('\n');
    const payload: Record<string, unknown> = {
      text: truncateText(text, SLACK_TEXT_MAX),
      blocks: blocks.slice(0, SLACK_MAX_BLOCKS),
    };
    if (this.username) payload['username'] = truncateText(this.username, 80);
    if (this.iconEmoji) payload['icon_emoji'] = this.iconEmoji;
    return payload;
  }

  private messageFor(entry: TransportLogEntry): SlackMessage {
    if (this.formatter) {
      try {
        return this.formatter(entry);
      } catch {
        internalWarn('SlackTransport: formatter threw; using the default message');
      }
    }
    return defaultMessage(entry);
  }
}

function defaultMessage(entry: TransportLogEntry): SlackMessage {
  const level = singleLine(entry.level).toUpperCase();
  const emoji = LEVEL_EMOJI[entry.level.toLowerCase()] ?? ':white_circle:';
  const headline = `[${level}] ${singleLine(entry.message)}`;
  const blocks: unknown[] = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: truncateText(escapeSlack(headline), SLACK_HEADER_MAX),
        emoji: false,
      },
    },
  ];

  const context = [
    ['app', entry.appName],
    ['env', entry.environment],
    ['context', entry.context],
    ['trace', entry.traceId],
    ['time', safeIso(entry.timestamp)],
  ]
    .map(([label, value]) => [label, typeof value === 'string' ? singleLine(value) : ''] as const)
    .filter(([, value]) => value !== '')
    .map(([label, value]) => ({
      type: 'mrkdwn',
      text: `*${label}:* ${truncateText(escapeSlack(value), SLACK_FIELD_MAX)}`,
    }));
  if (context.length > 0) blocks.push({ type: 'context', elements: context });

  if (entry.data && Object.keys(entry.data).length > 0) {
    const json = truncateText(escapeSlack(stringifyForLog(entry.data)), SLACK_DATA_MAX);
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `\`\`\`${json}\`\`\`` } });
  }

  return {
    text: `${emoji} ${escapeSlack(truncateText(headline, SLACK_HEADER_MAX))}`,
    blocks,
  };
}
