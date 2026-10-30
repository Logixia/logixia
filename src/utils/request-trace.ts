/**
 * Per-request trace ID resolution shared by the HTTP logger middleware and the
 * context helpers. Internal: not re-exported from the package entry points.
 */

import {
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
  sanitizeIncomingId,
} from './trace.utils';

export type TraceHeaderOption = string | readonly string[];

/** Minimal structural request shape; Express and Fastify requests satisfy it. */
export interface ContextRequestLike {
  headers?: Record<string, string | string[] | undefined> | undefined;
  id?: unknown;
}

/** Fastify's default `genReqId` output (`req-` + base36 counter), unique only per process. */
const FASTIFY_COUNTER_ID = /^req-[\da-z]+$/;

const FALLBACK_KEY = '_logixiaFallbackId';

/** Header names to read a trace ID from, defaulting to the library-wide list. */
export function resolveTraceHeaders(option: TraceHeaderOption | undefined): readonly string[] {
  if (option === undefined) return DEFAULT_TRACE_HEADERS;
  return typeof option === 'string' ? [option] : option;
}

/**
 * Resolve the trace ID for a request: a sanitised incoming header (honouring
 * `traceparent`), then a non-counter `request.id`, then a generated ID. Header
 * and `request.id` are recomputed per call so each caller's own header list is
 * honoured; only the generated fallback is stored on the request so every helper
 * agrees when no ID was sent.
 */
export function resolveRequestTraceId(req: ContextRequestLike, headers: readonly string[]): string {
  const fromHeader = extractTraceId(req, { header: [...headers] });
  if (fromHeader !== undefined) return fromHeader;

  const fromId = sanitizeIncomingId(req.id);
  if (fromId !== undefined && !FASTIFY_COUNTER_ID.test(fromId)) return fromId;

  const holder = req as Record<string, unknown>;
  const cached = holder[FALLBACK_KEY];
  if (typeof cached === 'string') return cached;
  const generated = generateTraceId();
  try {
    holder[FALLBACK_KEY] = generated;
  } catch {
    // frozen request object: each caller generates its own
  }
  return generated;
}
