/**
 * Shared core for the chat-webhook transports (Slack, Discord).
 *
 * - entries inside `minIntervalMs` are batched into one message; entries past
 *   `maxPerMessage` are dropped and reported to the payload builder as overflow
 * - the queue is bounded (BufferCap); the oldest entries go first
 * - HTTP 429 waits for Retry-After (bounded) and retries a bounded number of times
 * - errors only ever name the webhook host, never the URL (the URL is a secret)
 */

import type { TransportLogEntry } from '../types/transport.types';
import { internalError } from '../utils/internal-log';
import { BufferCap } from './buffer-cap';

const MAX_BACKOFF_MS = 30_000;
const DEFAULT_QUEUE_CAP = 1000;
export const DEFAULT_WEBHOOK_TIMEOUT_MS = 10_000;
const ZWSP = '​';

const LEVEL_RANK: Record<string, number> = {
  fatal: 0,
  error: 0,
  warn: 1,
  warning: 1,
  info: 2,
  debug: 3,
  verbose: 4,
  trace: 5,
};

export function resolveMinLevel(level: string | undefined, label: string): string {
  const resolved = (level ?? 'error').toLowerCase();
  if (!(resolved in LEVEL_RANK)) {
    throw new TypeError(`${label}: unknown level "${String(level).slice(0, 40)}"`);
  }
  return resolved;
}

/** Unknown (custom) entry levels pass, like the TransportManager does. */
export function meetsLevel(entryLevel: string, minLevel: string): boolean {
  const entryRank = LEVEL_RANK[entryLevel.toLowerCase()];
  return entryRank === undefined || entryRank <= (LEVEL_RANK[minLevel] ?? 0);
}

export interface WebhookUrlRules {
  label: string;
  hostMatches: (host: string) => boolean;
  pathMatches: (path: string) => boolean;
  expected: string;
  allowCustomUrl: boolean | undefined;
}

/** Validates the secret URL. Error messages never contain it. */
export function parseWebhookUrl(raw: unknown, rules: WebhookUrlRules): URL {
  const { label, allowCustomUrl, hostMatches, pathMatches, expected } = rules;
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new TypeError(`${label}: webhookUrl is required`);
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError(`${label}: webhookUrl is not a valid URL`);
  }
  if (url.protocol !== 'https:') {
    throw new TypeError(`${label}: webhookUrl must use https:`);
  }
  if (url.username || url.password) {
    throw new TypeError(`${label}: webhookUrl must not contain credentials`);
  }
  if (!allowCustomUrl) {
    const host = url.hostname.toLowerCase();
    if (!hostMatches(host) || !pathMatches(url.pathname) || url.port) {
      throw new TypeError(
        `${label}: webhookUrl must be a ${expected} webhook (set allowCustomUrl: true to use another https endpoint)`
      );
    }
  }
  return url;
}

export interface WebhookResponseLike {
  ok: boolean;
  status: number;
  headers?: { get(name: string): string | null } | undefined;
  json?: () => Promise<unknown>;
}

export class WebhookHttpError extends Error {
  constructor(
    public readonly status: number,
    label: string,
    host: string
  ) {
    super(`${label}: webhook ${host} returned HTTP ${status}`);
    this.name = 'WebhookHttpError';
  }

  get permanent(): boolean {
    return this.status >= 400 && this.status < 500 && this.status !== 429;
  }
}

export interface WebhookQueueOptions {
  label: string;
  url: URL;
  minIntervalMs: number | undefined;
  maxPerMessage: number;
  maxQueueSize: number | undefined;
  maxRetries: number | undefined;
  requestTimeoutMs: number | undefined;
  /** Builds the JSON request body; `overflow` counts entries that did not fit. */
  build: (entries: TransportLogEntry[], overflow: number) => unknown;
  /** Reads the wait (ms) from a 429 response. Defaults to the Retry-After header. */
  retryAfterMs?: (res: WebhookResponseLike) => Promise<number | undefined>;
}

export function retryAfterHeaderMs(res: WebhookResponseLike): number | undefined {
  const raw = res.headers?.get('retry-after');
  if (raw === null || raw === undefined || raw === '') return undefined;
  const seconds = Number(raw);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : undefined;
}

function nonNegative(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
}

function failureCode(err: unknown): string {
  const cause = (err as { cause?: { code?: unknown } } | null)?.cause;
  const code = cause?.code ?? (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string') return code.slice(0, 40);
  return err instanceof Error ? err.name : 'error';
}

export class WebhookQueue {
  private items: TransportLogEntry[] = [];
  private readonly cap: BufferCap;
  private readonly host: string;
  private readonly minIntervalMs: number;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;
  private timer: NodeJS.Timeout | null = null;
  private inFlight: Promise<void> | undefined;
  private nextAllowed = 0;
  private failures = 0;
  private closed = false;

  constructor(private readonly opts: WebhookQueueOptions) {
    this.host = opts.url.hostname;
    this.minIntervalMs = nonNegative(opts.minIntervalMs, 1000);
    this.maxRetries = Math.floor(nonNegative(opts.maxRetries, 1));
    this.timeoutMs = nonNegative(opts.requestTimeoutMs, DEFAULT_WEBHOOK_TIMEOUT_MS);
    this.cap = new BufferCap(opts.label, opts.maxQueueSize, opts.maxPerMessage, DEFAULT_QUEUE_CAP);
  }

  get length(): number {
    return this.items.length;
  }

  push(entry: TransportLogEntry): void {
    if (this.closed) return;
    this.items.push(entry);
    this.cap.enforce(this.items);
    this.schedule();
  }

  flush(): Promise<void> {
    this.inFlight ??= this.drain().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  async close(): Promise<void> {
    this.closed = true;
    this.clearTimer();
    try {
      await this.inFlight;
    } catch {
      // already reported by the timer path
    }
    try {
      await this.flush();
    } catch (err) {
      internalError(`${this.opts.label} flush on close failed`, err);
    }
    if (this.items.length > 0) {
      internalError(`${this.opts.label} closing with ${this.items.length} undelivered entries`);
      this.items = [];
    }
  }

  private clearTimer(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private schedule(): void {
    if (this.timer || this.closed || this.items.length === 0) return;
    const delay = Math.max(0, this.nextAllowed - Date.now());
    this.timer = setTimeout(() => {
      this.timer = null;
      this.flush().catch((err) => internalError(`${this.opts.label} send failed`, err));
    }, delay);
    this.timer.unref?.();
  }

  private async drain(): Promise<void> {
    if (this.items.length === 0) return;
    const all = this.items;
    this.items = [];
    const batch = all.slice(0, this.opts.maxPerMessage);
    const overflow = all.length - batch.length;
    if (overflow > 0) this.cap.note(overflow);
    this.nextAllowed = Date.now() + this.minIntervalMs;
    try {
      await this.sendWithRetry(this.opts.build(batch, overflow));
      this.failures = 0;
    } catch (err) {
      if (!(err instanceof WebhookHttpError && err.permanent)) {
        this.items.unshift(...batch);
        this.cap.enforce(this.items);
        this.failures += 1;
        const backoff = Math.min(
          MAX_BACKOFF_MS,
          Math.max(1000, this.minIntervalMs) * 2 ** this.failures
        );
        this.nextAllowed = Math.max(this.nextAllowed, Date.now() + backoff);
      }
      throw err;
    } finally {
      this.schedule();
    }
  }

  private async sendWithRetry(payload: unknown): Promise<void> {
    const body = JSON.stringify(payload);
    for (let attempt = 0; ; attempt += 1) {
      const res = await this.post(body);
      if (res.ok) return;
      if (res.status !== 429) throw new WebhookHttpError(res.status, this.opts.label, this.host);
      const waitMs = await this.readRetryAfter(res);
      this.nextAllowed = Math.max(this.nextAllowed, Date.now() + waitMs);
      if (attempt >= this.maxRetries) {
        throw new WebhookHttpError(429, this.opts.label, this.host);
      }
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
    }
  }

  private async readRetryAfter(res: WebhookResponseLike): Promise<number> {
    let waitMs: number | undefined;
    try {
      waitMs = this.opts.retryAfterMs ? await this.opts.retryAfterMs(res) : retryAfterHeaderMs(res);
    } catch {
      waitMs = undefined;
    }
    return Math.min(MAX_BACKOFF_MS, Math.max(0, waitMs ?? Math.max(1000, this.minIntervalMs)));
  }

  private async post(body: string): Promise<WebhookResponseLike> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return (await fetch(this.opts.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        redirect: 'error',
        signal: controller.signal,
      })) as WebhookResponseLike;
    } catch (err) {
      // fetch errors may echo the request URL; keep only the host and a short code (no cause)
      // eslint-disable-next-line preserve-caught-error -- the cause can contain the secret URL
      throw new Error(
        `${this.opts.label}: request to ${this.host} failed (${controller.signal.aborted ? 'timeout' : failureCode(err)})`
      );
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Cuts `text` to `max` chars without splitting a surrogate pair or a `&amp;`-style entity. */
export function truncateText(text: string, max: number, ellipsis = '…'): string {
  if (text.length <= max) return text;
  let cut = text.slice(0, Math.max(0, max - ellipsis.length));
  cut = cut.replace(/&[a-z]{0,3}$/, '');
  if (/[\uD800-\uDBFF]$/.test(cut)) cut = cut.slice(0, -1);
  return cut + ellipsis;
}

/** Breaks code-fence and broadcast-mention sequences with a zero-width space. */
export function defuseText(text: string): string {
  return text
    .replace(/`{3,}/g, (m) => m.split('').join(ZWSP))
    .replace(/@(everyone|here|channel)/gi, `@${ZWSP}$1`);
}

/** Collapses control characters and newlines for single-line fields. */
export function singleLine(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
}
