/**
 * Shared core for the chat-webhook transports (Slack, Discord).
 *
 * - entries inside `minIntervalMs` are batched into one message; entries past
 *   `maxPerMessage` are dropped and reported to the payload builder as overflow
 * - the queue is bounded (BufferCap); the oldest entries go first
 * - HTTP 429 waits for Retry-After (bounded, cancelled by close()) and retries a
 *   bounded number of times
 * - an entry that cannot be rendered is dropped alone; an unserializable batch or a
 *   missing global fetch is dropped, never retried
 * - errors only ever name the webhook host, never the URL (the URL is a secret)
 */

import type { TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';
import { HttpError, isPermanentHttpError } from './batch-buffer';
import { BufferCap } from './buffer-cap';

const MAX_BACKOFF_MS = 30_000;
const DEFAULT_QUEUE_CAP = 1000;
const CLOSE_TIMEOUT_MS = 3000;
const OVERFLOW_WARN_MS = 5000;
export const DEFAULT_WEBHOOK_TIMEOUT_MS = 10_000;
const ZWSP = '​';

const LEVEL_RANK: Record<string, number> = {
  fatal: 0,
  error: 1,
  warn: 2,
  warning: 2,
  info: 3,
  debug: 4,
  verbose: 5,
  trace: 6,
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
  return entryRank === undefined || entryRank <= (LEVEL_RANK[minLevel] ?? 1);
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
  body?: { cancel(): Promise<void> } | null | undefined;
  json?: () => Promise<unknown>;
}

interface PostResult {
  ok: boolean;
  status: number;
  retryAfterMs: number | undefined;
}

export interface WebhookQueueOptions<T> {
  label: string;
  url: URL;
  minIntervalMs: number | undefined;
  maxPerMessage: number;
  maxQueueSize: number | undefined;
  maxRetries: number | undefined;
  requestTimeoutMs: number | undefined;
  /** Renders one entry. A throw (or unserializable result) drops only that entry. */
  render: (entry: TransportLogEntry) => T;
  /**
   * Builds the JSON request body from the rendered entries. `overflow` counts
   * entries beyond `maxPerMessage` that were dropped; the body must say so.
   */
  assemble: (rendered: T[], overflow: number) => unknown;
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

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal.aborted) return resolve();
    const done = (): void => {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    timer.unref?.();
    signal.addEventListener('abort', done, { once: true });
  });
}

async function cancelBody(res: WebhookResponseLike): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // body already consumed or locked
  }
}

/**
 * Throttled queue for chat webhooks. It is not built on BatchBuffer because the
 * semantics differ: sends are spaced by `minIntervalMs` (leading edge, then one
 * message per window), a window sends one summarized message and drops the
 * overflow, 429 waits are cancellable by close(), and flush() surfaces send
 * errors. HttpError / isPermanentHttpError are shared with BatchBuffer.
 *
 * Entries past `maxPerMessage` in one window are not sent: the message carries a
 * "… and N more" line and an internal warning reports the count.
 */
export class WebhookQueue<T> {
  private items: TransportLogEntry[] = [];
  private readonly cap: BufferCap;
  private readonly host: string;
  private readonly httpLabel: string;
  private readonly minIntervalMs: number;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;
  private timer: NodeJS.Timeout | null = null;
  private inFlight: Promise<void> | undefined;
  private nextAllowed = 0;
  private failures = 0;
  private closed = false;
  private readonly shutdown = new AbortController();
  private overflowPending = 0;
  private lastOverflowWarn = 0;
  private fetchWarned = false;

  constructor(private readonly opts: WebhookQueueOptions<T>) {
    this.host = opts.url.hostname;
    this.httpLabel = `${opts.label} (${this.host})`;
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

  /** Cancels rate-limit waits, then makes one best-effort send with a short timeout. */
  async close(): Promise<void> {
    this.closed = true;
    this.clearTimer();
    this.shutdown.abort();
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
    this.reportOverflow(true);
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

  private reportOverflow(force = false): void {
    const now = Date.now();
    if (this.overflowPending === 0 || (!force && now - this.lastOverflowWarn < OVERFLOW_WARN_MS)) {
      return;
    }
    const n = this.overflowPending;
    internalWarn(
      `${this.opts.label}: ${n} entr${n === 1 ? 'y' : 'ies'} over the per-message limit (${this.opts.maxPerMessage}) summarized in a "... and N more" line and not sent`
    );
    this.overflowPending = 0;
    this.lastOverflowWarn = now;
  }

  private render(batch: TransportLogEntry[]): T[] {
    const rendered: T[] = [];
    let bad = 0;
    for (const entry of batch) {
      try {
        const value = this.opts.render(entry);
        JSON.stringify(value);
        rendered.push(value);
      } catch (err) {
        bad += 1;
        if (bad === 1) {
          internalError(`${this.opts.label}: dropping an entry that cannot be rendered`, err);
        }
      }
    }
    if (bad > 1) {
      internalError(`${this.opts.label}: dropped ${bad} entries that cannot be rendered`);
    }
    return rendered;
  }

  private async drain(): Promise<void> {
    if (this.items.length === 0) return;
    if (typeof fetch !== 'function') {
      if (!this.fetchWarned) {
        this.fetchWarned = true;
        internalWarn(
          `${this.opts.label}: global fetch is unavailable (Node 18+ required); dropping entries`
        );
      }
      this.items = [];
      return;
    }
    const all = this.items;
    this.items = [];
    const batch = all.slice(0, this.opts.maxPerMessage);
    const overflow = all.length - batch.length;
    if (overflow > 0) {
      this.overflowPending += overflow;
      this.reportOverflow();
    }
    this.nextAllowed = Date.now() + this.minIntervalMs;
    try {
      const rendered = this.render(batch);
      if (rendered.length === 0 && overflow === 0) return;
      let body: string;
      try {
        body = JSON.stringify(this.opts.assemble(rendered, overflow));
      } catch (err) {
        internalError(`${this.opts.label}: dropping a batch that cannot be serialized`, err);
        return;
      }
      try {
        await this.sendWithRetry(body);
        this.failures = 0;
      } catch (err) {
        if (!isPermanentHttpError(err)) {
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
      }
    } finally {
      this.schedule();
    }
  }

  private async sendWithRetry(body: string): Promise<void> {
    for (let attempt = 0; ; attempt += 1) {
      const res = await this.post(body);
      if (res.ok) return;
      if (res.status !== 429) throw new HttpError(res.status, '', this.httpLabel);
      const waitMs = Math.min(
        MAX_BACKOFF_MS,
        Math.max(0, res.retryAfterMs ?? Math.max(1000, this.minIntervalMs))
      );
      this.nextAllowed = Math.max(this.nextAllowed, Date.now() + waitMs);
      if (attempt >= this.maxRetries || this.closed) {
        throw new HttpError(429, '', this.httpLabel);
      }
      await sleep(waitMs, this.shutdown.signal);
      if (this.shutdown.signal.aborted) {
        throw new Error(`${this.opts.label}: rate-limit wait cancelled by close()`);
      }
    }
  }

  private async readRetryAfter(res: WebhookResponseLike): Promise<number | undefined> {
    try {
      return this.opts.retryAfterMs ? await this.opts.retryAfterMs(res) : retryAfterHeaderMs(res);
    } catch {
      return undefined;
    }
  }

  private async post(body: string): Promise<PostResult> {
    const controller = new AbortController();
    const timeoutMs = this.closed ? Math.min(this.timeoutMs, CLOSE_TIMEOUT_MS) : this.timeoutMs;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = (await fetch(this.opts.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        redirect: 'error',
        signal: controller.signal,
      })) as WebhookResponseLike;
      let retryAfterMs: number | undefined;
      try {
        if (res.status === 429) retryAfterMs = await this.readRetryAfter(res);
      } finally {
        await cancelBody(res);
      }
      return { ok: res.ok, status: res.status, retryAfterMs };
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

/** ISO string, or undefined for a missing or invalid timestamp. */
export function safeIso(date: unknown): string | undefined {
  return date instanceof Date && !Number.isNaN(date.getTime()) ? date.toISOString() : undefined;
}
