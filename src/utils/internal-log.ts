/**
 * Internal logging helpers for use within the logixia library itself.
 *
 * These functions write directly to stderr/stdout without going through
 * LogixiaLogger — this avoids circular dependencies and ensures internal
 * diagnostics still surface even when the logger is misconfigured.
 *
 * Library code must NEVER call console.log/warn/error directly. Use these
 * helpers instead so that internal output can be silenced in tests by setting
 * the LOGIXIA_SILENT_INTERNAL=1 environment variable.
 */

/**
 * Read the silence flag on each call rather than caching it at import time, so
 * setting LOGIXIA_SILENT_INTERNAL=1 AFTER the module is first imported (e.g. in
 * a test setup file) still takes effect — the documented test-silencing
 * behavior was previously unreliable because the value was frozen at load.
 */
function isSilent(): boolean {
  return process.env.LOGIXIA_SILENT_INTERNAL === '1';
}

/**
 * Emit an internal debug/info message to stderr.
 * Use for field-enable/disable notifications that a developer might want to see
 * during development but should not appear in production log streams.
 */
export function internalLog(message: string): void {
  if (!isSilent()) {
    process.stderr.write(`[logixia] ${message}\n`);
  }
}

/**
 * Emit an internal warning to stderr.
 * Use when something is misconfigured but logixia can continue operating.
 */
export function internalWarn(message: string): void {
  if (!isSilent()) {
    process.stderr.write(`[logixia:warn] ${message}\n`);
  }
}

/**
 * Emit an internal error to stderr.
 * Use when a transport write fails or a serious internal error occurs.
 */
export function internalError(message: string, error?: unknown): void {
  if (!isSilent()) {
    let errStr = '';
    if (error instanceof Error) {
      errStr = ` — ${error.message}`;
    } else if (error != null) {
      errStr = ` — ${String(error)}`;
    }
    process.stderr.write(`[logixia:error] ${message}${errStr}\n`);
  }
}
