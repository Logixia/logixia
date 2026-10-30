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
import { safeToString } from './coerce.utils';
import { serializeError } from './error.utils';
import { SENSITIVE_KEY_NAMES } from './sensitive-names';

export type { RedactConfig };

const DEFAULT_CENSOR = '[REDACTED]';

/** Maximum nesting depth walked; deeper values are replaced with a marker. */
const MAX_DEPTH = 32;
/** Maximum number of objects/arrays visited per redaction pass. */
const MAX_NODES = 10_000;
/**
 * Strings longer than this are truncated before pattern scanning. The tail is
 * dropped rather than emitted unscanned, so oversized input can never carry an
 * unredacted secret past the patterns.
 */
const MAX_SCAN_LENGTH = 16_384;
const MAX_DEPTH_MARKER = '[MaxDepth]';
const MAX_NODES_MARKER = '[MaxNodes]';
export const REDACTION_FAILED = '[RedactionFailed]';

// ── Built-in PII / secret patterns ──────────────────────────────────────────

/**
 * Conservative patterns: tokens and secrets that should NEVER appear in logs.
 * Applied when `autoDetect: true` or `autoDetect: 'conservative'`.
 */
const PII_CONSERVATIVE_PATTERNS: readonly RegExp[] = [
  // JWT tokens (three base64url segments separated by dots); segment lengths are
  // bounded so scanning stays linear on adversarial input
  /eyJ[A-Za-z0-9_-]{1,1024}\.[A-Za-z0-9_-]{1,16384}\.[A-Za-z0-9_-]{0,1024}/g,
  // Bearer / Token auth header values
  // eslint-disable-next-line sonarjs/duplicates-in-character-class
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  // Generic API key patterns (sk-, pk-, api-, etc.)
  // eslint-disable-next-line sonarjs/duplicates-in-character-class
  /\b(?:sk|pk|api|key|secret|token)-[A-Za-z0-9_-]{16,}/gi,
  // AWS-style access key IDs
  /\bAKIA[0-9A-Z]{16}\b/g,
  // AWS secret access keys, recognised by the adjacent key name
  // eslint-disable-next-line sonarjs/duplicates-in-character-class
  /secret[_-]?(?:access[_-]?)?key["'\s:=]{1,6}[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/gi,
];

/**
 * Conservative field-name paths auto-redacted by name regardless of value.
 */
const PII_CONSERVATIVE_PATHS: readonly string[] = SENSITIVE_KEY_NAMES.map((name) => `**.${name}`);

/**
 * Aggressive patterns: also catch personal data that could identify a person.
 * Applied when `autoDetect: 'aggressive'`.
 */
const PII_AGGRESSIVE_PATTERNS: readonly RegExp[] = [
  // Email addresses
  /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b/g,
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

  return new RegExp(`^${regexStr}$`, 'i');
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

function isTokenChar(code: number): boolean {
  return (
    (code >= 48 && code <= 57) || // 0-9
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    code === 46 || // .
    code === 95 || // _
    code === 126 || // ~
    code === 43 || // +
    code === 47 || // /
    code === 61 || // =
    code === 45 // -
  );
}

function applyPatterns(value: string, patterns: readonly RegExp[], censor: string): string {
  let redacted = value;
  let suffix = '';
  if (redacted.length > MAX_SCAN_LENGTH) {
    // Drop the trailing run of token characters so a secret straddling the cut
    // is removed whole rather than emitted as an unredactable prefix.
    let end = MAX_SCAN_LENGTH;
    while (end > 0 && isTokenChar(redacted.charCodeAt(end - 1))) end--;
    suffix = `…[truncated ${value.length - end} unscanned chars]`;
    redacted = redacted.slice(0, end);
  }
  for (const pattern of patterns) {
    redacted = redacted.replace(pattern, censor);
  }
  return redacted + suffix;
}

const CIRCULAR = '[Circular]';

interface WalkState {
  config: RedactConfig;
  ancestors: Set<object>;
  nodes: number;
}

function joinPath(parent: string, key: string): string {
  return parent ? `${parent}.${key}` : key;
}

function walkValue(
  value: unknown,
  state: WalkState,
  fullPath: string,
  bare: string,
  depth: number
): unknown {
  const { paths = [], excludePaths = [], patterns = [], censor = DEFAULT_CENSOR } = state.config;

  if (paths.some((p) => matchesPath(fullPath, p) || matchesPath(bare, p))) {
    return censor;
  }

  if (typeof value === 'object' && value !== null) {
    if (depth >= MAX_DEPTH) return MAX_DEPTH_MARKER;
    if (++state.nodes > MAX_NODES) return MAX_NODES_MARKER;
  }

  if (typeof value === 'string') {
    if (patterns.length === 0) return value;
    if (excludePaths.some((p) => matchesPath(fullPath, p) || matchesPath(bare, p))) return value;
    return applyPatterns(value, patterns, censor);
  }

  if (Array.isArray(value)) {
    return walkContainer(value, state, fullPath, bare, depth, walkArray);
  }

  if (value instanceof Error) {
    return walkContainer(value, state, fullPath, bare, depth, walkError);
  }

  if (value instanceof URL) {
    const url = new URL(value.href);
    url.username = '';
    url.password = '';
    const redacted = walkValue(url.href, state, fullPath, bare, depth);
    return redacted === value.href ? value : redacted;
  }

  if (isPlainObject(value)) {
    const walk =
      typeof (value as { toJSON?: unknown }).toJSON === 'function' ? walkToJSON : walkRecord;
    return walkContainer(value as object, state, fullPath, bare, depth, walk);
  }

  return value;
}

function walkContainer(
  value: object,
  state: WalkState,
  fullPath: string,
  bare: string,
  depth: number,
  walk: (value: never, state: WalkState, fullPath: string, bare: string, depth: number) => unknown
): unknown {
  if (state.ancestors.has(value)) return CIRCULAR;
  state.ancestors.add(value);
  try {
    return walk(value as never, state, fullPath, bare, depth + 1);
  } finally {
    state.ancestors.delete(value);
  }
}

/**
 * Array elements are matched by their indexed path (`users.0.password`) and by
 * the index-free path (`users.password`) that earlier versions used.
 */
function walkArray(
  arr: unknown[],
  state: WalkState,
  fullPath: string,
  bare: string,
  depth: number
): unknown[] {
  let result: unknown[] | undefined;
  for (const [i, item] of arr.entries()) {
    const next = walkValue(item, state, joinPath(fullPath, String(i)), bare, depth);
    if (next !== item && !result) result = arr.slice(0, i);
    if (result) result.push(next);
  }
  return result ?? arr;
}

function walkRecord(
  obj: Record<string, unknown>,
  state: WalkState,
  fullPath: string,
  bare: string,
  depth: number
): Record<string, unknown> {
  let result: Record<string, unknown> | undefined;
  const entries = Object.entries(obj);
  for (const [index, [key, value]] of entries.entries()) {
    // Prototype pollution guard: skip forbidden keys that could mutate
    // Object.prototype when assigned via bracket notation on a literal object.
    const forbidden = key === '__proto__' || key === 'constructor' || key === 'prototype';
    const next = forbidden
      ? undefined
      : walkValue(value, state, joinPath(fullPath, key), joinPath(bare, key), depth);
    if ((forbidden || next !== value) && !result) {
      result = Object.fromEntries(entries.slice(0, index));
    }
    if (result && !forbidden) result[key] = next;
  }
  return result ?? obj;
}

/** Errors are serialized (own props + cause chain) and the result is walked. */
function walkError(
  err: Error,
  state: WalkState,
  fullPath: string,
  bare: string,
  depth: number
): Record<string, unknown> {
  let serialized: Record<string, unknown>;
  try {
    serialized = serializeError(err);
  } catch {
    return { name: err.name, message: REDACTION_FAILED };
  }
  const result = walkRecord(serialized, state, fullPath, bare, depth);
  return result === serialized ? { ...serialized } : result;
}

/** Objects with `toJSON()` are redacted via the value they would serialize to. */
function walkToJSON(
  obj: { toJSON: () => unknown },
  state: WalkState,
  fullPath: string,
  bare: string,
  depth: number
): unknown {
  let json: unknown;
  try {
    json = obj.toJSON();
  } catch {
    return REDACTION_FAILED;
  }
  if (json === obj) return walkRecord(obj as Record<string, unknown>, state, fullPath, bare, depth);
  return walkValue(json, state, fullPath, bare, depth);
}

/**
 * Redact an object according to the given RedactConfig and return a new
 * top-level object. Subtrees with nothing to redact are shared with the input,
 * never mutated. Circular references become `[Circular]`.
 */
export function redactObject(
  obj: Record<string, unknown>,
  config: RedactConfig,
  _currentPath = ''
): Record<string, unknown> {
  const state: WalkState = { config, ancestors: new Set([obj]), nodes: 0 };
  const result = walkRecord(obj, state, _currentPath, _currentPath, 0);
  return result === obj ? { ...obj } : result;
}

/**
 * Apply pattern-based redaction to a single string (e.g. the log message).
 *
 * Path-based rules don't apply to a bare string — only the `patterns` are run.
 * Returns the input unchanged when no patterns are configured, so the hot path
 * stays allocation-free for the common no-redact case.
 */
export function applyRedactionToString(value: unknown, config: RedactConfig | undefined): string {
  const text = typeof value === 'string' ? value : safeToString(value);
  if (!config) return text;
  const resolved = resolveConfig(config);
  if (!resolved.patterns || resolved.patterns.length === 0) return text;
  return applyPatterns(text, resolved.patterns, resolved.censor ?? DEFAULT_CENSOR);
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

const OPAQUE_BUILTINS: readonly (abstract new (...args: never[]) => object)[] = [
  Date,
  Error,
  RegExp,
  URL,
  URLSearchParams,
  ArrayBuffer,
  DataView,
  Map,
  Set,
  WeakMap,
  WeakSet,
  Promise,
];

/** Plain objects and class instances are walked; built-ins are left alone. */
function isPlainObject(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (ArrayBuffer.isView(value)) return false;
  return !OPAQUE_BUILTINS.some((ctor) => value instanceof ctor);
}
