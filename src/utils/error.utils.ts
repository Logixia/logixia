/**
 * Error serialization utilities for Logixia
 *
 * v1.1 improvements:
 *  - Full ES2022 `cause` chain serialization (recursive)
 *  - AggregateError.errors array serialization
 *  - Standard extra fields: code, statusCode, status, errno, syscall, path
 *  - Circular-reference safe via a WeakSet seen guard
 */

import type { ErrorSerializationOptions } from '../types';

// Well-known extra fields to always capture when present on an error
const EXTRA_FIELDS = [
  'code',
  'statusCode',
  'status',
  'errno',
  'syscall',
  'path',
  'address',
  'port',
  'type',
] as const;

/**
 * Serialize an Error into a plain JSON-safe object, including:
 *  - `name`, `message`, `stack`
 *  - `cause` (recursively serialized, full ES2022 chain)
 *  - `errors` (for AggregateError)
 *  - standard Node.js error fields (`code`, `statusCode`, `errno`, …)
 *  - any other enumerable own properties
 */
export function serializeError(
  error: Error,
  options: ErrorSerializationOptions = {}
): Record<string, unknown> {
  const { includeStack = true, maxDepth = 5, excludeFields = [] } = options;
  const seen = new WeakSet<object>();
  return _serializeError(error, includeStack, maxDepth, excludeFields, 0, seen);
}

function _serializeError(
  error: Error,
  includeStack: boolean,
  maxDepth: number,
  excludeFields: string[],
  depth: number,
  seen: WeakSet<object>
): Record<string, unknown> {
  if (depth >= maxDepth) {
    return { name: error.name, message: error.message, _truncated: true };
  }

  if (seen.has(error)) {
    return { name: error.name, message: error.message, _circular: true };
  }
  seen.add(error);

  const serialized: Record<string, unknown> = {
    name: error.name,
    message: error.message,
  };

  if (includeStack && error.stack) {
    serialized.stack = error.stack;
  }

  // ── ES2022 cause chain ──────────────────────────────────────────────────────
  const errorWithCause = error as Error & { cause?: unknown };
  if (errorWithCause.cause !== undefined) {
    if (errorWithCause.cause instanceof Error) {
      serialized.cause = _serializeError(
        errorWithCause.cause,
        includeStack,
        maxDepth,
        excludeFields,
        depth + 1,
        seen
      );
    } else {
      serialized.cause = serializeValue(errorWithCause.cause, maxDepth - depth - 1);
    }
  }

  // ── AggregateError.errors ───────────────────────────────────────────────────
  const aggregateError = error as Error & { errors?: unknown[] };
  if (Array.isArray(aggregateError.errors)) {
    serialized.errors = aggregateError.errors.map((e) =>
      e instanceof Error
        ? _serializeError(e, includeStack, maxDepth, excludeFields, depth + 1, seen)
        : serializeValue(e, maxDepth - depth - 1)
    );
  }

  // ── Standard Node.js / HTTP error fields ───────────────────────────────────
  const errorRecord = error as unknown as Record<string, unknown>;
  for (const field of EXTRA_FIELDS) {
    if (!excludeFields.includes(field) && field in error && errorRecord[field] !== undefined) {
      serialized[field] = errorRecord[field];
    }
  }

  // ── All other own enumerable properties ────────────────────────────────────
  const skip = new Set<string>([
    'name',
    'message',
    'stack',
    'cause',
    'errors',
    ...EXTRA_FIELDS,
    ...excludeFields,
  ]);

  for (const key of Object.getOwnPropertyNames(error)) {
    if (skip.has(key)) continue;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    try {
      serialized[key] = serializeValue(errorRecord[key], maxDepth - depth - 1);
    } catch {
      serialized[key] = '[Unserializable]';
    }
  }

  return serialized;
}

/**
 * Recursively serialize an arbitrary value to a JSON-safe representation.
 */
function serializeValue(value: unknown, remainingDepth: number): unknown {
  if (remainingDepth <= 0) return '[Max Depth]';
  if (value === null || value === undefined) return value;

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (value instanceof Date) return value.toISOString();

  if (value instanceof Error) {
    return _serializeError(value, true, remainingDepth, [], 0, new WeakSet());
  }

  if (Array.isArray(value)) {
    return value.map((item) => serializeValue(item, remainingDepth - 1));
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      try {
        out[k] = serializeValue(v, remainingDepth - 1);
      } catch {
        out[k] = '[Unserializable]';
      }
    }
    return out;
  }

  return String(value);
}

/**
 * Type guard: returns true if the value looks like an Error object.
 */
export function isError(value: unknown): value is Error {
  return (
    value instanceof Error ||
    (Boolean(value) &&
      typeof value === 'object' &&
      'name' in (value as object) &&
      'message' in (value as object))
  );
}

/**
 * Coerce any thrown value into a proper Error instance.
 */
export function normalizeError(error: unknown): Error {
  if (isError(error)) return error;

  if (typeof error === 'string') return new Error(error);

  if (typeof error === 'object' && error !== null) {
    const e = error as Record<string, unknown>;
    const err = new Error(typeof e['message'] === 'string' ? e['message'] : 'Unknown error');
    Object.assign(err, error);
    return err;
  }

  return new Error(String(error));
}
