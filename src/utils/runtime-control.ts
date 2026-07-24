/**
 * logixia — Dynamic runtime log-level reconfiguration.
 *
 * Change log levels in a running process WITHOUT a restart — the single
 * most-requested logging feature across the Winston and Pino issue trackers
 * (winston#1107, pino#206/#677, nestjs-pino#371). The ecosystem even built a
 * standalone module for it (pino-arborsculpture); logixia ships it first-class.
 *
 * Two trigger surfaces:
 *  - {@link registerLevelSignal} — flip levels via an OS signal (default SIGUSR2),
 *    cycling through a level list. Zero HTTP surface, safe for any deployment.
 *  - {@link createLevelControlHandler} — a tiny HTTP handler so an ops dashboard
 *    can GET the current level and POST a new global / per-namespace level.
 *
 * @example Signal-based (cycle levels on each `kill -USR2 <pid>`)
 * ```ts
 * import { registerLevelSignal } from 'logixia';
 * const dispose = registerLevelSignal(logger);
 * // later: process.kill(process.pid, 'SIGUSR2') → info → debug → trace → info …
 * ```
 *
 * @example HTTP admin endpoint
 * ```ts
 * import { createLevelControlHandler } from 'logixia';
 * const handler = createLevelControlHandler(logger);
 * app.all('/admin/log-level', handler); // GET reads, POST { level, namespaceLevels } sets
 * ```
 */

import type { LogLevelString, NamespaceLevels } from '../types';
import { internalLog, internalWarn } from './internal-log';

/** Minimal logger surface the runtime controls need. */
export interface ReconfigurableLogger {
  getLevel(): LogLevelString;
  setLevel(level: LogLevelString): void;
  setNamespaceLevels?(levels: NamespaceLevels): void;
  getNamespaceLevels?(): NamespaceLevels;
}

const DEFAULT_CYCLE: readonly LogLevelString[] = [
  'error',
  'warn',
  'info',
  'debug',
  'trace',
  'verbose',
] as unknown as readonly LogLevelString[];

export interface LevelSignalOptions {
  /** Signal to listen on. Default: 'SIGUSR2' (SIGUSR1 is used by the Node debugger). */
  signal?: NodeJS.Signals;
  /** Ordered levels to cycle through on each signal. Default: error→…→verbose. */
  cycle?: LogLevelString[];
}

/**
 * Register an OS-signal handler that cycles the logger's global level on each
 * signal. Returns a dispose function that removes the listener.
 *
 * Cycling (rather than jumping straight to a fixed level) means a single,
 * memorizable command (`kill -USR2 <pid>`) is enough to ratchet verbosity up
 * while chasing a bug and back down again — no value to remember.
 */
export function registerLevelSignal(
  logger: ReconfigurableLogger,
  options: LevelSignalOptions = {}
): () => void {
  const signal = options.signal ?? 'SIGUSR2';
  const cycle = options.cycle && options.cycle.length > 0 ? options.cycle : [...DEFAULT_CYCLE];

  const handler = (): void => {
    const current = logger.getLevel();
    const idx = cycle.indexOf(current);
    const next = cycle[(idx + 1) % cycle.length]!;
    logger.setLevel(next);
    internalLog(`runtime level changed via ${signal}: ${current} → ${next}`);
  };

  process.on(signal, handler);
  return () => {
    process.removeListener(signal, handler);
  };
}

// ── HTTP admin handler ────────────────────────────────────────────────────────

interface MinimalReq {
  method?: string | undefined;
  on?: (event: string, cb: (chunk?: unknown) => void) => void;
}
interface MinimalRes {
  statusCode?: number;
  setHeader?: (k: string, v: string) => void;
  end: (body?: string) => void;
}

const VALID_LEVELS = new Set<string>([
  'error',
  'warn',
  'info',
  'debug',
  'trace',
  'verbose',
  'fatal',
]);

/**
 * Create an HTTP handler (Node `http`/Express-compatible) that reads and sets
 * the logger's level at runtime.
 *
 *  - `GET`  → `{ level, namespaceLevels }`
 *  - `POST` → body `{ level?, namespaceLevels? }` applies them, returns the new state
 *
 * Custom levels are accepted too: any level the logger already knows passes
 * through. Unknown levels are rejected with 400 so a typo can't silently mute
 * logging. Mount behind your own auth — this intentionally has none.
 */
export function createLevelControlHandler(
  logger: ReconfigurableLogger,
  options: { allowedLevels?: string[] } = {}
): (req: MinimalReq, res: MinimalRes) => void {
  const allowed =
    options.allowedLevels && options.allowedLevels.length > 0
      ? new Set(options.allowedLevels.map((l) => l.toLowerCase()))
      : VALID_LEVELS;

  const snapshot = (): { level: LogLevelString; namespaceLevels: NamespaceLevels } => ({
    level: logger.getLevel(),
    namespaceLevels: logger.getNamespaceLevels?.() ?? {},
  });

  const send = (res: MinimalRes, status: number, body: unknown): void => {
    res.statusCode = status;
    res.setHeader?.('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
  };

  const applyBody = (res: MinimalRes, raw: string): void => {
    let parsed: { level?: unknown; namespaceLevels?: unknown };
    try {
      parsed = raw ? (JSON.parse(raw) as typeof parsed) : {};
    } catch {
      send(res, 400, { error: 'invalid JSON body' });
      return;
    }

    if (parsed.level !== undefined) {
      const lvl = String(parsed.level).toLowerCase();
      if (!allowed.has(lvl)) {
        send(res, 400, { error: `unknown level "${parsed.level}"`, allowed: [...allowed] });
        return;
      }
      logger.setLevel(lvl as LogLevelString);
    }

    if (parsed.namespaceLevels !== undefined) {
      if (
        typeof parsed.namespaceLevels !== 'object' ||
        parsed.namespaceLevels === null ||
        Array.isArray(parsed.namespaceLevels)
      ) {
        send(res, 400, { error: 'namespaceLevels must be an object' });
        return;
      }
      const nl = parsed.namespaceLevels as Record<string, unknown>;
      for (const [pat, lvl] of Object.entries(nl)) {
        if (!allowed.has(String(lvl).toLowerCase())) {
          send(res, 400, { error: `unknown level "${String(lvl)}" for namespace "${pat}"` });
          return;
        }
      }
      if (logger.setNamespaceLevels) {
        const coerced: NamespaceLevels = {};
        for (const [pat, lvl] of Object.entries(nl)) {
          coerced[pat] = String(lvl).toLowerCase() as LogLevelString;
        }
        logger.setNamespaceLevels(coerced);
      } else {
        internalWarn('level control: logger does not support setNamespaceLevels — ignored');
      }
    }

    send(res, 200, snapshot());
  };

  return function levelControlHandler(req: MinimalReq, res: MinimalRes): void {
    const method = (req.method ?? 'GET').toUpperCase();

    if (method === 'GET') {
      send(res, 200, snapshot());
      return;
    }

    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      // Express already-parsed body (req.body) vs raw stream.
      const maybeBody = (req as unknown as { body?: unknown }).body;
      if (maybeBody !== undefined && typeof req.on !== 'function') {
        applyBody(res, typeof maybeBody === 'string' ? maybeBody : JSON.stringify(maybeBody));
        return;
      }
      if (typeof req.on === 'function') {
        let raw = '';
        req.on('data', (chunk?: unknown) => {
          raw += String(chunk ?? '');
        });
        req.on('end', () => applyBody(res, raw));
        return;
      }
      applyBody(res, '');
      return;
    }

    send(res, 405, { error: `method ${method} not allowed` });
  };
}
