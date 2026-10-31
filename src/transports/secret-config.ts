/**
 * Keeps credentials out of serialized transport output and error text.
 *
 * `protectSecrets()` replaces each listed field with a non-enumerable accessor backed
 * by a WeakMap, whether or not the field is assigned yet, so later assignments (a
 * connection opened on first write, a refreshed token) stay hidden too. It also
 * installs `toJSON()` and a Node inspect hook returning a redacted view: scalar
 * fields stay for debugging, secret-looking keys become '[REDACTED]', URLs lose
 * userinfo, query and fragment. No Node imports, so browser bundles can use it.
 */

import { assignOwn } from '../utils/own-property';
import {
  DEFAULT_REDACT_QUERY_PARAMS,
  SENSITIVE_KEY_NAMES,
  TRANSPORT_CONFIG_SECRET_NAMES,
} from '../utils/sensitive-names';

export const REDACTED = '[REDACTED]';

const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');
const MAX_DEPTH = 4;
const MIN_SECRET_LENGTH = 4;
const SCHEME_PREFIX = /^[a-z][a-z0-9+.-]*:\/\//i;
/** `scheme://userinfo@`: userinfo runs to the LAST `@` before the path, so `p@ss` is covered. */
const USERINFO = /(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/?#]*@/gi;

function normalizeName(name: string): string {
  return name.toLowerCase().replaceAll('-', '').replaceAll('_', '');
}

const SECRET_NAMES = [...SENSITIVE_KEY_NAMES, ...TRANSPORT_CONFIG_SECRET_NAMES].map(normalizeName);
const QUERY_NAMES = new Set(DEFAULT_REDACT_QUERY_PARAMS.map(normalizeName));

/** Exact match for short names (`key`, `pfx`), suffix match for longer ones (`azureClientSecret`). */
function isSecretKey(key: string): boolean {
  const name = normalizeName(key);
  return SECRET_NAMES.some((n) => name === n || (n.length >= 5 && name.endsWith(n)));
}

function isUrlKey(key: string): boolean {
  return /url|uri|endpoint|href/i.test(key);
}

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replaceAll('+', ' '));
  } catch {
    return value;
  }
}

/** Absolute URL: `scheme://host` only. Relative or unparseable: path kept, query and fragment cut. */
export function redactUrl(raw: string | URL): string {
  if (typeof raw !== 'string') return `${raw.protocol}//${raw.host}`;
  if (SCHEME_PREFIX.test(raw)) {
    try {
      const url = new URL(raw);
      return `${url.protocol}//${url.host}`;
    } catch {
      return REDACTED;
    }
  }
  return raw.split(/[?#]/, 1)[0] ?? '';
}

function redactHeaders(headers: unknown): unknown {
  if (!headers || typeof headers !== 'object') return headers;
  return Object.fromEntries(Object.keys(headers).map((name) => [name, REDACTED]));
}

/** Redacted deep copy of a config-like value. Never throws, never returns a secret. */
export function redactConfig(value: unknown, depth = 0, key = ''): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return SCHEME_PREFIX.test(value) || isUrlKey(key) ? redactUrl(value) : value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'function') return '[Function]';
  if (typeof value !== 'object') return '[Unserializable]';
  if (typeof URL !== 'undefined' && value instanceof URL) return redactUrl(value);
  if (Array.isArray(value)) {
    return depth >= MAX_DEPTH ? '[Array]' : value.map((v) => redactConfig(v, depth + 1, key));
  }
  if (!isPlainObject(value) || depth >= MAX_DEPTH)
    return `[${value.constructor?.name ?? 'Object'}]`;
  const out: Record<string, unknown> = {};
  for (const [name, inner] of Object.entries(value)) {
    if (isSecretKey(name)) assignOwn(out, name, inner === undefined ? undefined : REDACTED);
    else if (name.toLowerCase() === 'headers') assignOwn(out, name, redactHeaders(inner));
    else assignOwn(out, name, redactConfig(inner, depth + 1, name));
  }
  return out;
}

// ── Secret protection ───────────────────────────────────────────────────────

const hiddenKeys = new WeakMap<object, Set<string>>();
const hiddenValues = new WeakMap<object, Map<string, unknown>>();

function viewOf(target: object): Record<string, unknown> {
  const hidden = hiddenKeys.get(target) ?? new Set<string>();
  const values = hiddenValues.get(target);
  const view: Record<string, unknown> = { class: target.constructor?.name };
  for (const key of new Set([...Object.keys(target), ...hidden])) {
    const inner = hidden.has(key) ? values?.get(key) : (target as Record<string, unknown>)[key];
    if (isSecretKey(key)) view[key] = inner === undefined ? undefined : REDACTED;
    else if (key.toLowerCase() === 'headers') view[key] = redactHeaders(inner);
    else if (
      inner !== null &&
      typeof inner === 'object' &&
      !hidden.has(key) &&
      !(inner instanceof URL)
    ) {
      view[key] = '[Object]';
    } else if (hidden.has(key) && typeof inner === 'string' && !isUrlKey(key)) {
      view[key] = REDACTED;
    } else view[key] = redactConfig(inner, 0, key);
  }
  return view;
}

/**
 * Hides `keys` on `target` (assigned or not yet) and gives it a redacted `toJSON()` /
 * inspect view. Fields stay readable and writable. Safe to call more than once.
 * Throws when the target cannot carry the protection (frozen or sealed), instead of
 * silently leaving the secret enumerable.
 */
export function protectSecrets(target: object, keys: readonly string[]): void {
  if (!Object.isExtensible(target)) {
    throw new TypeError(
      `protectSecrets: ${target.constructor?.name ?? 'object'} is not extensible`
    );
  }
  let hidden = hiddenKeys.get(target);
  let values = hiddenValues.get(target);
  if (!hidden || !values) {
    hidden = new Set();
    values = new Map();
    hiddenKeys.set(target, hidden);
    hiddenValues.set(target, values);
    const view = (): Record<string, unknown> => viewOf(target);
    Object.defineProperty(target, 'toJSON', { value: view, enumerable: false, configurable: true });
    Object.defineProperty(target, INSPECT_CUSTOM, {
      value: view,
      enumerable: false,
      configurable: true,
    });
  }
  const store = values;
  for (const key of keys) {
    if (hidden.has(key)) continue;
    const desc = Object.getOwnPropertyDescriptor(target, key);
    if (desc && !desc.configurable) {
      throw new TypeError(`protectSecrets: "${key}" is not configurable`);
    }
    if (desc && 'value' in desc) store.set(key, desc.value);
    hidden.add(key);
    Object.defineProperty(target, key, {
      enumerable: false,
      configurable: true,
      get: () => store.get(key),
      set: (next: unknown) => void store.set(key, next),
    });
  }
}

// ── Scrubbing error text ────────────────────────────────────────────────────

/** The raw, decoded and percent-encoded spellings of a secret. */
function variantsOf(secret: string): string[] {
  return [secret, safeDecode(secret), encodeURIComponent(secret), encodeURI(secret)];
}

/** Secret parts of a URL string: the password and the values of sensitive query parameters. */
export function urlSecrets(raw: string | URL): string[] {
  const text = typeof raw === 'string' ? raw : raw.href;
  const out: string[] = [];
  const userinfo = new RegExp(USERINFO.source, 'i').exec(text);
  if (userinfo) {
    const info = text.slice(userinfo[1]!.length, userinfo.index + userinfo[0].length - 1);
    const colon = info.indexOf(':');
    if (colon !== -1) out.push(info.slice(colon + 1));
  }
  const queryStart = text.indexOf('?');
  if (queryStart !== -1) {
    const query = text.slice(queryStart + 1).split('#', 1)[0] ?? '';
    for (const pair of query.split('&')) {
      const eq = pair.indexOf('=');
      if (eq > 0 && QUERY_NAMES.has(normalizeName(safeDecode(pair.slice(0, eq))))) {
        out.push(pair.slice(eq + 1));
      }
    }
  }
  return out.flatMap(variantsOf);
}

/** Every secret string held in a config-like value: secret-keyed values, header values, URL secrets. */
export function collectSecrets(value: unknown, depth = 0, key = ''): string[] {
  if (typeof value === 'string') {
    if (isSecretKey(key)) return [value];
    return SCHEME_PREFIX.test(value) || isUrlKey(key) ? urlSecrets(value) : [];
  }
  if (!value || typeof value !== 'object' || depth > MAX_DEPTH) return [];
  if (typeof URL !== 'undefined' && value instanceof URL) return urlSecrets(value);
  if (Array.isArray(value)) return value.flatMap((v) => collectSecrets(v, depth + 1, key));
  if (!isPlainObject(value)) return [];
  const isHeaders = key.toLowerCase() === 'headers';
  return Object.entries(value).flatMap(([name, inner]) => {
    if (isHeaders && typeof inner === 'string') return [inner];
    if (isSecretKey(name) && inner !== null && typeof inner === 'object') {
      return collectSecrets(inner, depth + 1, 'secret');
    }
    return collectSecrets(inner, depth + 1, name);
  });
}

/** Replaces URL userinfo and every spelling of the given secret values in `text`. */
export function scrubSecrets(text: string, secrets: readonly (string | undefined)[]): string {
  let out = text.replace(USERINFO, `$1${REDACTED}@`);
  const all = new Set(
    secrets.flatMap((s) => (s && s.length >= MIN_SECRET_LENGTH ? variantsOf(s) : []))
  );
  for (const secret of [...all].sort((a, b) => b.length - a.length)) {
    if (secret.length >= MIN_SECRET_LENGTH) out = out.split(secret).join(REDACTED);
  }
  return out;
}

/** Scrubs message, stack and the cause chain of `err` in place; returns it. */
export function scrubError<T>(err: T, secrets: readonly (string | undefined)[], depth = 0): T {
  if (!(err instanceof Error) || depth > 3) return err;
  try {
    err.message = scrubSecrets(err.message, secrets);
    if (err.stack) err.stack = scrubSecrets(err.stack, secrets);
    scrubError((err as { cause?: unknown }).cause, secrets, depth + 1);
  } catch {
    /* frozen error: leave as is */
  }
  return err;
}

/** A `.catch()` handler that scrubs the secrets from the error, then rethrows it. */
export function scrubbing(secrets: () => (string | undefined)[]): (err: unknown) => never {
  return (err) => {
    throw scrubError(err, secrets());
  };
}
