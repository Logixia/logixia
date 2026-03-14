/**
 * Log redaction utilities for Logixia
 *
 * Solves the #1 logging security problem: sensitive data (PII, secrets, tokens)
 * being logged to transports that shouldn't have them.
 *
 * Addresses Winston issue #1079 "redacting secrets" which has been open for years
 * with no built-in solution.
 *
 * @example
 * ```ts
 * const logger = createLogger({
 *   redact: {
 *     paths: ['req.headers.authorization', '*.password', 'user.creditCard', 'token'],
 *     patterns: [/Bearer\s+\S+/gi, /sk-[a-z0-9]{32,}/gi],
 *     censor: '[REDACTED]',
 *   }
 * });
 * ```
 */

import type { RedactConfig } from '../types';

export type { RedactConfig };

const DEFAULT_CENSOR = '[REDACTED]';

/**
 * Convert a dot-notation path pattern to a RegExp.
 * Supports `*` (one segment) and `**` (zero or more segments).
 *
 * Examples:
 *   "password"          → /^password$/
 *   "user.password"     → /^user\.password$/
 *   "*.token"           → /^[^.]+\.token$/
 *   "req.headers.*"     → /^req\.headers\.[^.]+$/
 *   "**"                → /^.*$/
 */
function pathToRegExp(pattern: string): RegExp {
  const regexStr = pattern
    .split('.')
    .map((segment) => {
      if (segment === '**') return '.*';
      if (segment === '*') return '[^.]+';
      // Escape regex special chars in the segment
      return segment.replace(/[$()*+.?[\\\]^{|}]/g, '\\$&');
    })
    .join('\\.');

  return new RegExp(`^${regexStr}$`);
}

/** Pre-compiled path matchers keyed by pattern string for perf */
const patternCache = new Map<string, RegExp>();

function matchesPath(fullPath: string, pattern: string): boolean {
  let re = patternCache.get(pattern);
  if (!re) {
    re = pathToRegExp(pattern);
    patternCache.set(pattern, re);
  }
  return re.test(fullPath);
}

/**
 * Deep-clone and redact an object according to the given RedactConfig.
 * Non-objects are returned as-is (with pattern replacement on strings).
 *
 * The function is intentionally non-mutating — it returns a new object.
 */
export function redactObject(
  obj: Record<string, unknown>,
  config: RedactConfig,
  _currentPath = ''
): Record<string, unknown> {
  const { paths = [], patterns = [], censor = DEFAULT_CENSOR } = config;
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    const fullPath = _currentPath ? `${_currentPath}.${key}` : key;

    // ── 1. Path-based redaction ──────────────────────────────────────────────
    if (paths.length > 0 && paths.some((p) => matchesPath(fullPath, p))) {
      result[key] = censor;
      continue;
    }

    // ── 2. Recurse into plain objects ────────────────────────────────────────
    if (isPlainObject(value)) {
      result[key] = redactObject(value as Record<string, unknown>, config, fullPath);
      continue;
    }

    // ── 3. Pattern-based redaction on string values ──────────────────────────
    if (typeof value === 'string' && patterns.length > 0) {
      let redacted = value;
      for (const pattern of patterns) {
        redacted = redacted.replace(pattern, censor);
      }
      result[key] = redacted;
      continue;
    }

    // ── 4. Recurse into arrays ───────────────────────────────────────────────
    if (Array.isArray(value)) {
      result[key] = value.map((item) => {
        if (isPlainObject(item)) {
          return redactObject(item as Record<string, unknown>, config, fullPath);
        }
        if (typeof item === 'string' && patterns.length > 0) {
          return patterns.reduce((s, p) => s.replace(p, censor), item);
        }
        return item;
      });
      continue;
    }

    // ── 5. Pass-through ──────────────────────────────────────────────────────
    result[key] = value;
  }

  return result;
}

/**
 * Apply redaction to a log payload (top-level call convenience wrapper).
 * Returns a new object — never mutates the input.
 */
export function applyRedaction(
  payload: Record<string, unknown> | undefined,
  config: RedactConfig | undefined
): Record<string, unknown> | undefined {
  if (!payload || !config) return payload;
  if (
    (!config.paths || config.paths.length === 0) &&
    (!config.patterns || config.patterns.length === 0)
  ) {
    return payload;
  }
  return redactObject(payload, config);
}

function isPlainObject(value: unknown): boolean {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    !(value instanceof Date) &&
    !(value instanceof Error) &&
    !(value instanceof RegExp)
  );
}
