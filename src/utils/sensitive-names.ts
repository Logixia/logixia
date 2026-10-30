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
