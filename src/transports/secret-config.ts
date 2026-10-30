/**
 * Keeps credentials out of serialized transport output.
 *
 * `protectSecrets()` makes the named own fields non-enumerable (so spreads,
 * JSON.stringify and util.inspect skip them) and installs `toJSON()` and a
 * Node inspect hook that return a redacted view: non-secret fields stay for
 * debugging, secret-looking keys become '[REDACTED]', URLs shrink to their origin.
 * No Node imports, so browser bundles can use it.
 */

export const REDACTED = '[REDACTED]';

const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');
const SECRET_WORDS = [
  'secret',
  'token',
  'passw',
  'pwd',
  'apikey',
  'authorization',
  'credential',
  'privatekey',
  'writekey',
  'connectionstring',
  'signature',
  'cookie',
  'passphrase',
];
const SECRET_KEY_EXACT = /^(key|cert|ca|pfx|auth)$/i;
function isSecretKey(key: string): boolean {
  const flat = key.toLowerCase().replace(/[-_]/g, '');
  return SECRET_KEY_EXACT.test(key) || SECRET_WORDS.some((word) => flat.includes(word));
}
const URL_LIKE = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;
const MAX_DEPTH = 4;

const hiddenKeys = new WeakMap<object, Set<string>>();

/** `scheme://host[:port]` only; userinfo, path and query (which may hold secrets) are dropped. */
export function redactUrl(raw: string | URL): string {
  try {
    const url = typeof raw === 'string' ? new URL(raw) : raw;
    return `${url.protocol}//${url.host}`;
  } catch {
    return REDACTED;
  }
}

function redactHeaders(headers: unknown): unknown {
  if (!headers || typeof headers !== 'object') return headers;
  return Object.fromEntries(Object.keys(headers).map((name) => [name, REDACTED]));
}

/** Redacted deep copy of a config-like value. Never throws, never returns a secret. */
export function redactConfig(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return URL_LIKE.test(value) ? redactUrl(value) : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'function') return '[Function]';
  if (typeof value !== 'object') return '[Unserializable]';
  if (typeof URL !== 'undefined' && value instanceof URL) return redactUrl(value);
  if (depth >= MAX_DEPTH) return '[Object]';
  if (Array.isArray(value)) return value.map((v) => redactConfig(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value)) {
    if (isSecretKey(key)) {
      out[key] = inner === undefined ? undefined : REDACTED;
    } else if (key.toLowerCase() === 'headers') {
      out[key] = redactHeaders(inner);
    } else {
      out[key] = redactConfig(inner, depth + 1);
    }
  }
  return out;
}

function viewOf(target: object): Record<string, unknown> {
  const hidden = hiddenKeys.get(target) ?? new Set<string>();
  const view: Record<string, unknown> = { class: target.constructor?.name };
  for (const key of new Set([...Object.keys(target), ...hidden])) {
    const inner = (target as Record<string, unknown>)[key];
    if (isSecretKey(key)) view[key] = inner === undefined ? undefined : REDACTED;
    else if (
      inner !== null &&
      typeof inner === 'object' &&
      !hidden.has(key) &&
      !(inner instanceof URL)
    ) {
      view[key] = '[Object]';
    } else view[key] = key.toLowerCase() === 'headers' ? redactHeaders(inner) : redactConfig(inner);
  }
  return view;
}

/**
 * Hides `keys` on `target` and gives it a redacted `toJSON()` / inspect view.
 * Safe to call more than once; later calls add keys. Fields stay readable and writable.
 */
export function protectSecrets(target: object, keys: readonly string[]): void {
  let hidden = hiddenKeys.get(target);
  if (!hidden) {
    hidden = new Set();
    hiddenKeys.set(target, hidden);
    const view = (): Record<string, unknown> => viewOf(target);
    Object.defineProperty(target, 'toJSON', { value: view, enumerable: false, configurable: true });
    Object.defineProperty(target, INSPECT_CUSTOM, {
      value: view,
      enumerable: false,
      configurable: true,
    });
  }
  for (const key of keys) {
    const desc = Object.getOwnPropertyDescriptor(target, key);
    if (!desc) continue;
    hidden.add(key);
    Object.defineProperty(target, key, { ...desc, enumerable: false });
  }
}

/** Replaces every occurrence of the given secret values, and URL credentials, in `text`. */
export function scrubSecrets(text: string, secrets: readonly (string | undefined)[]): string {
  let out = text.replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@]*@/gi, `$1${REDACTED}@`);
  for (const secret of secrets) {
    if (secret && secret.length >= 4) out = out.split(secret).join(REDACTED);
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

/** Secret parts of a URL: userinfo and query values. */
export function urlSecrets(raw: string | URL): string[] {
  try {
    const url = typeof raw === 'string' ? new URL(raw) : raw;
    return [url.username, url.password, ...url.searchParams.values()];
  } catch {
    return [];
  }
}

/** A `.catch()` handler that scrubs the secrets from the error, then rethrows it. */
export function scrubbing(secrets: () => (string | undefined)[]): (err: unknown) => never {
  return (err) => {
    throw scrubError(err, secrets());
  };
}
