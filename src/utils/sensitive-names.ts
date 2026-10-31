/**
 * The one list of sensitive names. Log redaction (redact.utils), the HTTP logger
 * middleware and transport secret handling (transports/secret-config) all read it,
 * so the lists cannot drift. No imports: safe from any module, including browser code.
 */

/** Field names redacted by name, wherever they appear in logged data. */
export const SENSITIVE_KEY_NAMES: readonly string[] = [
  'password',
  'passwd',
  'secret',
  'token',
  'apiKey',
  'api_key',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'authorization',
  'credentials',
  'privateKey',
  'private_key',
  'clientSecret',
  'client_secret',
  'cookie',
  'set-cookie',
  'x-api-key',
  'session',
  'proxy-authorization',
  'x-auth-token',
  'x-access-token',
  'aws_secret_access_key',
  'awsSecretAccessKey',
  'secretAccessKey',
];

/**
 * Extra names that only mean "secret" inside transport configuration, where
 * short words like `key` or `signature` are credentials, not log fields.
 */
export const TRANSPORT_CONFIG_SECRET_NAMES: readonly string[] = [
  'writeKey',
  'apiSecret',
  'connectionString',
  'sessionToken',
  'passphrase',
  'signature',
  'pwd',
  'pfx',
  'cert',
  'key',
  'auth',
];

/** Request headers whose values are never logged. */
export const DEFAULT_REDACT_HEADERS: readonly string[] = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'proxy-authorization',
  'x-auth-token',
  'x-access-token',
  'x-csrf-token',
  'x-amz-security-token',
];

/** Query-string parameters whose values are never logged. */
export const DEFAULT_REDACT_QUERY_PARAMS: readonly string[] = [
  'token',
  'access_token',
  'refresh_token',
  'code',
  'password',
  'secret',
  'api_key',
  'apikey',
  'key',
  'signature',
  'sig',
  'auth',
  'accesstoken',
  'refreshtoken',
  'id_token',
  'idtoken',
  'client_secret',
  'clientsecret',
  'session',
  'sessionid',
  'session_id',
  'jwt',
  'auth_token',
  'authtoken',
  'api-key',
  'x-api-key',
  'x-amz-signature',
  'x-amz-credential',
  'x-amz-security-token',
  'x-goog-signature',
  'x-goog-credential',
  'access-token',
  'x-access-token',
  'x-auth-token',
  'apitoken',
  'api_token',
];

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

/** Replace the values of sensitive query parameters, leaving the rest verbatim. */
export function redactUrlQuery(url: string, redactParams: ReadonlySet<string>): string {
  const q = url.indexOf('?');
  if (q === -1) return url;
  const hashAt = url.indexOf('#', q);
  const query = url.slice(q + 1, hashAt === -1 ? undefined : hashAt);
  const hash = hashAt === -1 ? '' : url.slice(hashAt);
  const cleaned = query
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      const rawKey = eq === -1 ? pair : pair.slice(0, eq);
      const decoded = safeDecode(rawKey);
      const bracket = decoded.indexOf('[');
      const name = (bracket === -1 ? decoded : decoded.slice(0, bracket)).toLowerCase();
      return redactParams.has(name) && eq !== -1 ? `${rawKey}=[REDACTED]` : pair;
    })
    .join('&');
  return `${url.slice(0, q)}?${cleaned}${hash}`;
}

/** Lower-cased lookup set of the default names plus any extras. */
export function buildNameSet(
  defaults: readonly string[],
  extra: readonly string[] | undefined
): Set<string> {
  return new Set([...defaults, ...(extra ?? [])].map((n) => n.toLowerCase()));
}

const REDACTED = '[REDACTED]';
const MIN_SCRUB_LENGTH = 3;

function queryNameOf(rawKey: string): string {
  const decoded = safeDecode(rawKey);
  const bracket = decoded.indexOf('[');
  return (bracket === -1 ? decoded : decoded.slice(0, bracket)).toLowerCase();
}

/**
 * Raw and decoded values of sensitive query parameters present in this URL.
 * Values shorter than 3 characters or already `[REDACTED]` are ignored.
 */
export function sensitiveQueryValues(url: string, names: ReadonlySet<string>): string[] {
  const q = url.indexOf('?');
  if (q === -1) return [];
  const hashAt = url.indexOf('#', q);
  const query = url.slice(q + 1, hashAt === -1 ? undefined : hashAt);
  const found = new Set<string>();
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    if (eq === -1 || !names.has(queryNameOf(pair.slice(0, eq)))) continue;
    const raw = pair.slice(eq + 1);
    for (const value of [raw, safeDecode(raw)]) {
      if (value.length >= MIN_SCRUB_LENGTH && value !== REDACTED) found.add(value);
    }
  }
  return [...found];
}

/** Replace every literal occurrence of `values` in `text` with `[REDACTED]`. */
export function scrubValues(text: string, values: readonly string[]): string {
  if (values.length === 0 || text.length === 0) return text;
  let out = text;
  for (const value of [...values].sort((a, b) => b.length - a.length)) {
    if (value.length > 0 && out.includes(value)) out = out.split(value).join(REDACTED);
  }
  return out;
}

function isUrlTerminator(ch: string): boolean {
  return (
    ch === ' ' ||
    ch === '\n' ||
    ch === '\r' ||
    ch === '\t' ||
    ch === '"' ||
    ch === "'" ||
    ch === '`'
  );
}

/**
 * Redact sensitive query values in every `?query` found inside free text (an
 * error message, a stack line). Scans for `?` and cuts at whitespace or a quote.
 */
export function redactUrlsInText(text: string, names: ReadonlySet<string>): string {
  let q = text.indexOf('?');
  if (q === -1) return text;
  let out = '';
  let cursor = 0;
  while (q !== -1) {
    let end = q + 1;
    while (end < text.length && !isUrlTerminator(text.charAt(end))) end++;
    out += text.slice(cursor, q) + redactUrlQuery(text.slice(q, end), names);
    cursor = end;
    q = text.indexOf('?', end);
  }
  return out + text.slice(cursor);
}

/** Shape-preserving URL redaction plus literal scrubbing of this request's secret values. */
export function sanitizeText(
  text: string,
  names: ReadonlySet<string>,
  values: readonly string[]
): string {
  return scrubValues(redactUrlsInText(text, names), values);
}
