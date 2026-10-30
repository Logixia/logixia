/**
 * Control-character stripping for text-mode log output.
 *
 * Line breaks become the visible escapes `\\n` / `\\r`; other C0 characters
 * (except tab), DEL and C1 characters are removed, so user-supplied text cannot
 * inject ANSI escapes, overwrite lines, or forge extra log entries.
 */

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS_RE = /[\x00-\x08\x0A-\x1F\x7F-\x9F]/g;

const VISIBLE_ESCAPES: Record<string, string> = { '\n': '\\n', '\r': '\\r' };

export function stripControlChars(value: string): string {
  return value.replace(CONTROL_CHARS_RE, (ch) => VISIBLE_ESCAPES[ch] ?? '');
}
