/**
 * Shared batching core for the network transports (OTLP, CloudWatch, GCP, Azure).
 *
 * - one send in flight at a time; flush() and close() join it instead of
 *   racing it, so close() cannot return while a request is still on the wire
 * - a failed batch goes back to the front in its original order
 * - 4xx responses other than 429 drop the batch with a warning instead of
 *   retrying a request the server will never accept
 * - the buffer is capped; when full the oldest entries are dropped
 */

import * as http from 'node:http';
import * as https from 'node:https';

import { internalError, internalWarn } from '../utils/internal-log';

export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_BUFFER_SIZE = 10_000;
const WARN_INTERVAL_MS = 10_000;
const MAX_ERROR_BODY = 500;
const MAX_BACKOFF_MS = 30_000;

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    label: string
  ) {
    const detail = body ? `: ${body.slice(0, MAX_ERROR_BODY)}` : '';
    super(`${label} returned HTTP ${status}${detail}`);
    this.name = 'HttpError';
  }
}

export function isPermanentHttpError(err: unknown): boolean {
  return err instanceof HttpError && err.status >= 400 && err.status < 500 && err.status !== 429;
}

export interface HttpRequestOptions {
  url: URL;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs: number;
  label: string;
}

export interface HttpResult {
  status: number;
  body: string;
}

/** One request with a hard timeout. Rejects with HttpError on any non-2xx status. */
export function httpRequest(opts: HttpRequestOptions): Promise<HttpResult> {
  const { url, method = 'POST', headers = {}, body, timeoutMs, label } = opts;
  const transport = url.protocol === 'http:' ? http : https;
  return new Promise<HttpResult>((resolve, reject) => {
    const req = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        method,
        headers:
          body === undefined ? headers : { ...headers, 'Content-Length': Buffer.byteLength(body) },
      },
      (res) => {
        let raw = '';
        res.on('data', (c: Buffer) => (raw += c.toString()));
        res.on('end', () => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) resolve({ status, body: raw });
          else reject(new HttpError(status, raw, label));
        });
        res.on('error', reject);
      }
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`${label} timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export interface BatchBufferOptions<T> {
  name: string;
  batchSize: number;
  maxBufferSize?: number;
  send: (items: T[]) => Promise<void>;
  /** Overrides the default drop-on-4xx rule. Return true to keep and retry the batch. */
  shouldRetry?: (err: unknown) => boolean;
}

export class BatchBuffer<T> {
  private items: T[] = [];
  private inFlight: Promise<void> | undefined;
  private dropped = 0;
  private lastDropWarn = 0;
  private failures = 0;
  private retryAfter = 0;

  constructor(private readonly opts: BatchBufferOptions<T>) {}

  get length(): number {
    return this.items.length;
  }

  get batchSize(): number {
    return this.opts.batchSize;
  }

  push(item: T): void {
    this.items.push(item);
    this.enforceCap();
  }

  /** Threshold flush for write(): skipped while a send is running or the endpoint is backing off. */
  flushIfFull(): void {
    if (this.items.length < this.opts.batchSize || this.inFlight || Date.now() < this.retryAfter) {
      return;
    }
    this.flush().catch(() => {});
  }

  flush(): Promise<void> {
    if (!this.inFlight) {
      this.inFlight = this.drain().finally(() => {
        this.inFlight = undefined;
      });
    }
    return this.inFlight;
  }

  /** Flush up to `attempts` times, then report whatever is still undelivered. */
  async close(attempts = 3): Promise<void> {
    await this.inFlight;
    for (let i = 0; i < attempts && this.items.length > 0; i += 1) {
      await this.flush();
    }
    if (this.items.length > 0) {
      internalError(
        `${this.opts.name} closing with ${this.items.length} undelivered entr${this.items.length === 1 ? 'y' : 'ies'}`
      );
    }
  }

  private async drain(): Promise<void> {
    while (this.items.length > 0) {
      const batch = this.items.splice(0, this.opts.batchSize);
      try {
        await this.opts.send(batch);
        this.failures = 0;
      } catch (err) {
        const retry = this.opts.shouldRetry
          ? this.opts.shouldRetry(err)
          : !isPermanentHttpError(err);
        if (!retry) {
          internalWarn(
            `${this.opts.name}: dropping ${batch.length} entr${batch.length === 1 ? 'y' : 'ies'} the server rejected (${err instanceof Error ? err.message : String(err)})`
          );
          continue;
        }
        internalError(`${this.opts.name} flush error`, err);
        this.items.unshift(...batch);
        this.enforceCap();
        this.failures += 1;
        this.retryAfter = Date.now() + Math.min(MAX_BACKOFF_MS, 1000 * 2 ** (this.failures - 1));
        return;
      }
    }
  }

  private enforceCap(): void {
    const max = this.opts.maxBufferSize ?? DEFAULT_MAX_BUFFER_SIZE;
    const excess = this.items.length - max;
    if (excess <= 0) return;
    this.items.splice(0, excess);
    this.dropped += excess;
    const now = Date.now();
    if (now - this.lastDropWarn >= WARN_INTERVAL_MS) {
      internalWarn(
        `${this.opts.name}: buffer full (${max}), dropped ${this.dropped} oldest entr${this.dropped === 1 ? 'y' : 'ies'}`
      );
      this.dropped = 0;
      this.lastDropWarn = now;
    }
  }
}
