/**
 * logixia — Canonical Log Lines / Wide Events.
 *
 * Emit ONE dense, structured event per unit of work (usually a request) instead
 * of scattering details across many narrow log lines. Fields are accumulated as
 * the request flows through middleware and business logic, then the whole event
 * is emitted ONCE — in a `finally`/teardown path so it fires even on errors.
 *
 * This is the "canonical log line" pattern (Stripe) / "wide events" /
 * "Observability 2.0" (Honeycomb): one pre-joined, queryable record per request,
 * so operators never JOIN across log lines during an incident. It composes with
 * logixia's existing trace correlation — when a trace is active, the event
 * carries `traceId`/`spanId`, making it OTel-friendly.
 *
 * @example Manual scope
 * ```ts
 * import { withWideEvent, addEventFields } from 'logixia';
 *
 * await withWideEvent(logger, { route: '/checkout' }, async () => {
 *   addEventFields({ userId, planTier });        // from anywhere in the call tree
 *   addEventFields({ dbQueries: 4, cacheHit });
 *   // ...one wide event is emitted automatically when this callback settles,
 *   //    even if it throws.
 * });
 * ```
 *
 * @example Express middleware (auto-emit on response finish/close)
 * ```ts
 * import { wideEventMiddleware } from 'logixia';
 * app.use(wideEventMiddleware(logger));
 * app.get('/x', (req, res) => { addEventFields({ handled: 'x' }); res.json({}); });
 * ```
 */

import { AsyncLocalStorage } from 'node:async_hooks';

import { getCurrentTraceId } from './utils/trace.utils';

/** The accumulating event fields for the current scope. */
export type WideEventFields = Record<string, unknown>;

interface WideEventState {
  fields: WideEventFields;
  startMs: number;
  emitted: boolean;
}

const _storage = new AsyncLocalStorage<WideEventState>();

/** Minimal logger surface a wide event needs to emit itself. */
export interface WideEventLogger {
  logLevel(level: string, message: string, data?: Record<string, unknown>): Promise<void> | void;
}

export interface WideEventOptions {
  /** Level the canonical event is logged at. Default: 'info'. */
  level?: string;
  /** Message for the canonical event line. Default: 'request'. */
  message?: string;
  /**
   * Attach `traceId` (and `spanId` when present) from the active trace context.
   * Default: true.
   */
  includeTrace?: boolean;
  /** Field name for the auto-computed duration in ms. Default: 'durationMs'. */
  durationField?: string;
}

/**
 * Merge fields into the wide event for the current async scope. No-op (with no
 * throw) when called outside a `withWideEvent` / middleware scope, so business
 * code can call it unconditionally.
 */
export function addEventFields(fields: WideEventFields): void {
  const state = _storage.getStore();
  if (!state || state.emitted) return;
  Object.assign(state.fields, fields);
}

/** Set a single field on the current wide event. */
export function setEventField(key: string, value: unknown): void {
  addEventFields({ [key]: value });
}

/** Read a shallow copy of the wide event accumulated so far, or undefined. */
export function getEventFields(): WideEventFields | undefined {
  const state = _storage.getStore();
  return state ? { ...state.fields } : undefined;
}

function emit(
  logger: WideEventLogger,
  state: WideEventState,
  options: WideEventOptions,
  extra?: WideEventFields
): void {
  if (state.emitted) return;
  state.emitted = true;

  const level = options.level ?? 'info';
  const message = options.message ?? 'request';
  const durationField = options.durationField ?? 'durationMs';
  const includeTrace = options.includeTrace ?? true;

  const payload: WideEventFields = { ...state.fields };
  if (extra) Object.assign(payload, extra);
  payload[durationField] = Date.now() - state.startMs;

  if (includeTrace) {
    const traceId = getCurrentTraceId();
    if (traceId !== undefined && payload['traceId'] === undefined) payload['traceId'] = traceId;
  }

  // logLevel may be async (transport-backed); fire-and-forget so the wide-event
  // emit never blocks request teardown. Swallow rejections (the logger surfaces
  // its own transport errors) so this never becomes an unhandled rejection.
  const p = logger.logLevel(level, message, payload);
  if (p && typeof (p as Promise<void>).catch === 'function') {
    (p as Promise<void>).catch(() => {});
  }
}

/**
 * Run `callback` inside a wide-event scope. `addEventFields` calls anywhere in
 * the (async) call tree accumulate onto one event, which is emitted exactly once
 * when the callback settles — on success OR error (the canonical "emit in
 * finally" guarantee). On error, `error` + `errorMessage` fields are added.
 */
export async function withWideEvent<T>(
  logger: WideEventLogger,
  initialFields: WideEventFields,
  callback: () => Promise<T> | T,
  options: WideEventOptions = {}
): Promise<T> {
  const state: WideEventState = {
    fields: { ...initialFields },
    startMs: Date.now(),
    emitted: false,
  };

  return _storage.run(state, async () => {
    try {
      const result = await callback();
      emit(logger, state, options);
      return result;
    } catch (error) {
      emit(logger, state, options, {
        error: true,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  });
}

// ── HTTP middleware ─────────────────────────────────────────────────────────

interface MwReq {
  method?: string | undefined;
  url?: string | undefined;
  originalUrl?: string | undefined;
  ip?: string | undefined;
  headers?: Record<string, unknown> | undefined;
  socket?: { remoteAddress?: string } | undefined;
}
interface MwRes {
  statusCode?: number;
  once?: (event: string, cb: () => void) => void;
}

export interface WideEventMiddlewareOptions extends WideEventOptions {
  /** Derive extra initial fields from the request. */
  enrich?: (req: MwReq) => WideEventFields;
  /** Skip wide-event emission for a request (e.g. health checks). */
  skip?: (req: MwReq) => boolean;
}

/**
 * Express/Connect middleware that opens a wide-event scope per request and
 * emits ONE canonical event on response `finish`/`close` — even if the handler
 * throws or the client disconnects. Pre-populates method/url/ip; handlers add
 * more via `addEventFields`. The completion event includes `statusCode` and the
 * request duration.
 */
export function wideEventMiddleware(
  logger: WideEventLogger,
  options: WideEventMiddlewareOptions = {}
): (req: MwReq, res: MwRes, next: () => void) => void {
  return function logixiaWideEventMiddleware(req: MwReq, res: MwRes, next: () => void): void {
    if (options.skip?.(req)) {
      next();
      return;
    }

    const base: WideEventFields = {
      method: req.method,
      url: req.originalUrl ?? req.url,
      ip: req.ip ?? req.socket?.remoteAddress,
      ...(options.enrich ? options.enrich(req) : {}),
    };

    const state: WideEventState = { fields: base, startMs: Date.now(), emitted: false };

    const finalize = (): void => {
      emit(logger, state, options, { statusCode: res.statusCode ?? 0 });
    };

    // Both 'finish' and 'close' may fire; emit() is idempotent (emitted guard),
    // so the canonical line is logged exactly once.
    res.once?.('finish', finalize);
    res.once?.('close', finalize);

    _storage.run(state, () => next());
  };
}
