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

// ── Built-in PII / secret patterns ──────────────────────────────────────────

/**
 * Conservative patterns: tokens and secrets that should NEVER appear in logs.
 * Applied when `autoDetect: true` or `autoDetect: 'conservative'`.
 */
const PII_CONSERVATIVE_PATTERNS: readonly RegExp[] = [
  // JWT tokens (three base64url segments separated by dots)
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
  // Bearer / Token auth header values
  // eslint-disable-next-line sonarjs/duplicates-in-character-class
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  // Generic API key patterns (sk-, pk-, api-, etc.)
  // eslint-disable-next-line sonarjs/duplicates-in-character-class
  /\b(?:sk|pk|api|key|secret|token)-[A-Za-z0-9_-]{16,}/gi,
  // AWS-style access key IDs and secret access keys
  /\bAKIA[0-9A-Z]{16}\b/g,
  // eslint-disable-next-line sonarjs/duplicates-in-character-class
  /\b[A-Za-z0-9/+]{40}\b(?=.*aws)/gi,
];

/**
 * Conservative field-name paths auto-redacted by name regardless of value.
 */
const PII_CONSERVATIVE_PATHS: readonly string[] = [
  '**.password',
  '**.passwd',
  '**.secret',
  '**.token',
  '**.apiKey',
  '**.api_key',
  '**.accessToken',
  '**.access_token',
  '**.refreshToken',
  '**.refresh_token',
  '**.authorization',
  '**.credentials',
  '**.privateKey',
  '**.private_key',
  '**.clientSecret',
  '**.client_secret',
];

/**
 * Aggressive patterns: also catch personal data that could identify a person.
 * Applied when `autoDetect: 'aggressive'`.
 */
const PII_AGGRESSIVE_PATTERNS: readonly RegExp[] = [
  // Email addresses
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  // US Social Security Numbers (XXX-XX-XXXX or XXXXXXXXX)
  /\b\d{3}-?\d{2}-?\d{4}\b/g,
  // Credit / debit card numbers (13-19 digits, optional spaces/dashes)
  /\b(?:\d[ -]?){13,19}\b/g,
  // US phone numbers
  /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  // IPv4 addresses
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
];

const PII_AGGRESSIVE_PATHS: readonly string[] = [
  ...PII_CONSERVATIVE_PATHS,
  '**.email',
  '**.emailAddress',
  '**.email_address',
  '**.phone',
  '**.phoneNumber',
  '**.phone_number',
  '**.mobile',
  '**.ssn',
  '**.sin',
  '**.dob',
  '**.dateOfBirth',
  '**.date_of_birth',
  '**.creditCard',
  '**.credit_card',
  '**.cardNumber',
  '**.card_number',
  '**.cvv',
  '**.cvc',
  '**.ipAddress',
  '**.ip_address',
];

/**
 * Build an effective config that merges `autoDetect` PII rules into the
 * explicit `paths` and `patterns` the caller provided.
 */
function resolveConfig(config: RedactConfig): RedactConfig {
  const { autoDetect } = config;
  const { paths = [], patterns = [] } = config;

  let mergedPaths: readonly string[] = paths;
  let mergedPatterns: readonly RegExp[] = patterns;

  if (autoDetect) {
    const aggressive = autoDetect === 'aggressive';
    const extraPaths = aggressive ? PII_AGGRESSIVE_PATHS : PII_CONSERVATIVE_PATHS;
    const extraPatterns = aggressive
      ? [...PII_CONSERVATIVE_PATTERNS, ...PII_AGGRESSIVE_PATTERNS]
      : PII_CONSERVATIVE_PATTERNS;
    mergedPaths = [...paths, ...extraPaths];
    mergedPatterns = [...patterns, ...extraPatterns];
  }

  // Filter out non-strings / non-RegExps: callers occasionally pass through
  // env-derived arrays that contain `undefined` entries (e.g.
  // `LOGIXIA_REDACT=,foo,`), and a non-string would crash `pathToRegExp`'s
  // split/replace pipeline.
  return {
    ...config,
    paths: mergedPaths.filter((p): p is string => typeof p === 'string'),
    patterns: mergedPatterns.filter((p): p is RegExp => p instanceof RegExp),
  };
}

/**
 * Convert a dot-notation path pattern to a RegExp.
 * Supports `*` (exactly one segment) and `**` (zero or more segments).
 *
 * Because `**` may match *zero* segments, it also absorbs the dot separator
 * that joins it to its neighbour — so `**.password` matches both a bare
 * top-level `password` (zero leading segments) and any nested `*.password`.
 *
 * Examples:
 *   "password"          → /^password$/
 *   "user.password"     → /^user\.password$/
 *   "*.token"           → /^[^.]+\.token$/
 *   "req.headers.*"     → /^req\.headers\.[^.]+$/
 *   "**"                → /^.*$/
 *   "**.password"       → /^(?:.*\.)?password$/   (matches `password` and `a.b.password`)
 *   "req.**"            → /^req(?:\..*)?$/         (matches `req` and `req.a.b`)
 *
 * Consecutive `**` segments are collapsed (`a.**.**.b` ≡ `a.**.b`).
 */
function pathToRegExp(pattern: string): RegExp {
  // Collapse runs of consecutive `**` — they are semantically redundant
  // (`a.**.**.b` ≡ `a.**.b`) and would otherwise emit two optional groups that
  // fight over the shared separator and fail to match zero-segment paths.
  const segments = pattern
    .split('.')
    .filter((seg, i, arr) => !(seg === '**' && arr[i - 1] === '**'));
  const lastIndex = segments.length - 1;

  let regexStr = '';
  for (const [i, segment] of segments.entries()) {
    // A `**` token emits an optional group that already contains the dot on
    // one side, so the matching boundary separator must NOT be emitted here:
    //   - a non-final `**` (leading/middle) → group `(?:.*\.)?` owns its RIGHT dot
    //   - a trailing `**`                   → group `(?:\..*)?` owns its LEFT dot
    // Every other boundary (including a middle `**`'s structural LEFT dot) is a
    // literal `\.`.
    const prevOwnsRightDot = i > 0 && segments[i - 1] === '**' && i - 1 < lastIndex;
    const ownsLeftDot = segment === '**' && i === lastIndex && i > 0;
    if (i > 0 && !prevOwnsRightDot && !ownsLeftDot) {
      regexStr += String.raw`\.`;
    }

    if (segment === '**') {
      // `**` = zero or more path segments.
      if (lastIndex === 0) {
        regexStr += '.*'; // standalone `**`
      } else if (i === lastIndex) {
        regexStr += String.raw`(?:\..*)?`; // trailing `X.**` — optional ".segs"
      } else {
        regexStr += String.raw`(?:.*\.)?`; // leading/middle — optional "segs."
      }
      continue;
    }

    regexStr += segment === '*' ? '[^.]+' : segment.replace(/[$()*+.?[\\\]^{|}]/g, '\\$&');
  }

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
    // Prototype pollution guard: skip forbidden keys that could mutate
    // Object.prototype when assigned via bracket notation on a literal object.
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
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
 * Apply pattern-based redaction to a single string (e.g. the log message).
 *
 * Path-based rules don't apply to a bare string — only the `patterns` are run.
 * Returns the input unchanged when no patterns are configured, so the hot path
 * stays allocation-free for the common no-redact case.
 */
export function applyRedactionToString(value: string, config: RedactConfig | undefined): string {
  if (!config) return value;
  const resolved = resolveConfig(config);
  if (!resolved.patterns || resolved.patterns.length === 0) return value;
  let redacted = value;
  for (const pattern of resolved.patterns) {
    redacted = redacted.replace(pattern, resolved.censor ?? DEFAULT_CENSOR);
  }
  return redacted;
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
  const resolved = resolveConfig(config);
  if (
    (!resolved.paths || resolved.paths.length === 0) &&
    (!resolved.patterns || resolved.patterns.length === 0)
  ) {
    return payload;
  }
  return redactObject(payload, resolved);
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
