/**
 * Defensive value coercion helpers for Logixia.
 *
 * Logger inputs come from third-party code (NestJS framework internals,
 * user payloads, error objects) where the runtime type is not always what
 * the TypeScript signature promises. The formatter / transport hot paths
 * call `.replace()` on string fields and crash if the field is anything
 * else. Use these helpers anywhere a downstream consumer assumes a string.
 */

/**
 * Coerce any value to a string without throwing.
 *
 * - `undefined` / `null` → `''` (so the field is rendered as empty rather
 *   than the literal string "undefined")
 * - strings → returned as-is (zero allocation on the hot path)
 * - Errors → `error.message` (matches what users would expect to see)
 * - everything else → `JSON.stringify` if possible, falling back to
 *   `String(value)` for circular refs / values without a stringifier.
 */
export function safeToString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined || value === null) return '';
  if (value instanceof Error) return value.message;
  if (typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean') {
    return String(value);
  }
  if (typeof value === 'symbol') return value.toString();
  if (typeof value === 'function') {
    return `[Function: ${(value as { name?: string }).name || 'anonymous'}]`;
  }
  // value is now narrowed to object — JSON-stringify, falling back to a
  // constructor-name tag for circular refs / throwing toJSON.
  try {
    return JSON.stringify(value);
  } catch {
    const ctor = (value as { constructor?: { name?: string } }).constructor?.name;
    return `[${ctor ?? 'object'}]`;
  }
}

/**
 * String-replace on a value that may not be a string.
 * Coerces non-strings before delegating to `String.prototype.replace`.
 */
export function safeReplace(value: unknown, pattern: string | RegExp, replacement: string): string {
  return safeToString(value).replace(pattern, replacement);
}
