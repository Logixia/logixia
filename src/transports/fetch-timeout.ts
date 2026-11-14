import { DEFAULT_REQUEST_TIMEOUT_MS } from './batch-buffer';

/**
 * fetch() with a hard deadline, so an endpoint that accepts the connection and
 * never answers cannot hang a flush (and with it close()) forever. Uses an
 * AbortController rather than AbortSignal.timeout(), which needs Node 17.3+
 * while `engines` allows 16; the timer is unref'd so it never holds the process.
 */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number = DEFAULT_REQUEST_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error(`Request timed out after ${timeoutMs}ms`, { cause: error });
    }
    throw error;
  }
}
