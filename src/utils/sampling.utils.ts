/**
 * Log sampling & rate-limiting engine.
 *
 * Completely stateless between log calls — all state lives in the Sampler instance
 * so multiple loggers can have independent sampling budgets.
 */

import type { SamplingConfig } from '../types';

// Safety-critical levels that are NEVER sampled below 100 % by default.
// Per SamplingConfig docs, ERROR and WARN are always emitted unless explicitly
// overridden via `perLevel`; `fatal` (a common custom highest-severity level)
// is included for the same reason.
const ALWAYS_EMIT_LEVELS = new Set(['error', 'warn', 'fatal']);

const MAX_CACHED_TRACE_ID_LENGTH = 256;

function isCacheableTraceId(id: string): boolean {
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_CACHED_TRACE_ID_LENGTH) {
    return false;
  }
  for (let i = 0; i < id.length; i++) {
    const c = id.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return false;
  }
  return true;
}

// ── Sampler ───────────────────────────────────────────────────────────────────

export interface SamplingStats {
  /** Total calls evaluated since last reset. */
  evaluated: number;
  /** Total calls emitted (passed through). */
  emitted: number;
  /** Total calls dropped. */
  dropped: number;
  /** Per-level breakdown. */
  byLevel: Record<string, { evaluated: number; emitted: number }>;
  /** Window start (ms since epoch). */
  windowStart: number;
}

export class Sampler {
  private readonly config: SamplingConfig;
  /**
   * Per-trace decisions in LRU order (Map preserves insertion order; a hit
   * re-inserts the key). Survives resetStats() so a long trace is not re-decided
   * mid-flight. Bounded by size, by an idle TTL (refreshed on hit) and by a hard
   * lifetime measured from the first decision.
   */
  private readonly traceDecisions = new Map<
    string,
    { emit: boolean; firstAt: number; seenAt: number }
  >();
  private readonly maxTrackedTraces = 100_000;
  private readonly traceTtlMs = 5 * 60_000;
  private readonly traceMaxLifetimeMs = 60 * 60_000;

  // Rate-limiting state
  private _tokenBucket = 0;
  private _lastRefillMs = Date.now();

  // Adaptive (anomaly-driven) sampling state — a sliding window of recent
  // (timestamp, isError) samples. `_adaptiveHead` marks the oldest live entry so
  // eviction is O(1); the array is compacted once the dead prefix dominates.
  private _adaptiveWindow: Array<{ t: number; err: boolean }> = [];
  private _adaptiveHead = 0;
  private _adaptiveErrors = 0;

  // Stats
  private _stats: SamplingStats = {
    evaluated: 0,
    emitted: 0,
    dropped: 0,
    byLevel: {},
    windowStart: Date.now(),
  };
  private _statsTimer?: ReturnType<typeof setInterval>;

  constructor(config: SamplingConfig, onStats?: (stats: SamplingStats) => void) {
    this.config = config;

    // Initialise token bucket to the max cap
    if (config.maxLogsPerSecond && config.maxLogsPerSecond > 0) {
      this._tokenBucket = config.maxLogsPerSecond;
    }

    // Periodic stats reporter
    const interval = config.statsIntervalMs ?? 60_000;
    if (interval > 0 && onStats) {
      this._statsTimer = setInterval(() => {
        const snapshot = this.getStats();
        onStats(snapshot);
        this.resetStats();
      }, interval);
      // Don't prevent process exit
      if (this._statsTimer.unref) this._statsTimer.unref();
    }
  }

  /**
   * Decide whether a given log entry should be emitted.
   *
   * @param level    Log level string (lowercase)
   * @param traceId  Active trace ID, if any
   * @returns true → emit, false → drop
   */
  shouldEmit(level: string, traceId?: string): boolean {
    const lvl = level.toLowerCase();
    this._trackEvaluated(lvl);
    if (this.config.adaptive) this._recordAdaptiveSample(lvl);

    // ── 1. Safety: error/fatal always pass (unless explicitly overridden) ─────
    if (ALWAYS_EMIT_LEVELS.has(lvl) && this.config.perLevel?.[lvl] === undefined) {
      this._trackEmitted(lvl);
      return true;
    }

    // ── 2. Rate-based decision (cached per trace when traceConsistent) ────────
    const emit =
      this.config.traceConsistent && traceId
        ? this._decideForTrace(traceId, lvl)
        : this._sampleByRate(lvl);
    if (!emit) {
      this._trackDropped(lvl);
      return false;
    }

    // ── 3. Hard cap (token bucket) — applies to every kept entry ──────────────
    if (this.config.maxLogsPerSecond && this.config.maxLogsPerSecond > 0) {
      if (!this._consumeToken()) {
        this._trackDropped(lvl);
        return false;
      }
    }

    this._trackEmitted(lvl);
    return true;
  }

  getStats(): SamplingStats {
    return { ...this._stats, byLevel: { ...this._stats.byLevel } };
  }

  resetStats(): void {
    this._stats = {
      evaluated: 0,
      emitted: 0,
      dropped: 0,
      byLevel: {},
      windowStart: Date.now(),
    };
  }

  destroy(): void {
    if (this._statsTimer) clearInterval(this._statsTimer);
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private _sampleByRate(level: string): boolean {
    const baseRate =
      this.config.perLevel?.[level] ?? this.config.perLevel?.['*'] ?? this.config.rate ?? 1.0;

    // Adaptive boost: during an error anomaly, lift the rate so the incident is
    // captured in full, then relax back to the base rate in steady state.
    const rate = Math.max(baseRate, this._adaptiveBoostRate());

    if (rate >= 1.0) return true;
    if (rate <= 0.0) return false;
    // eslint-disable-next-line sonarjs/pseudo-random -- probabilistic sampling, not security-sensitive
    return Math.random() < rate;
  }

  /** Record one evaluated sample and evict entries older than the window. O(1) amortized. */
  private _recordAdaptiveSample(level: string): void {
    const now = Date.now();
    const windowMs = this.config.adaptive?.windowMs ?? 10_000;
    const err = level === 'error' || level === 'fatal';
    this._adaptiveWindow.push({ t: now, err });
    if (err) this._adaptiveErrors += 1;

    const cutoff = now - windowMs;
    const win = this._adaptiveWindow;
    while (this._adaptiveHead < win.length && win[this._adaptiveHead]!.t < cutoff) {
      if (win[this._adaptiveHead]!.err) this._adaptiveErrors -= 1;
      this._adaptiveHead += 1;
    }
    if (this._adaptiveHead >= 1024 && this._adaptiveHead * 2 >= win.length) {
      this._adaptiveWindow = win.slice(this._adaptiveHead);
      this._adaptiveHead = 0;
    }
  }

  /**
   * Effective boost rate (0 = no boost). Returns the configured boostRate when
   * the windowed error rate is at/above the threshold AND there are enough
   * samples to trust it; otherwise 0.
   */
  private _adaptiveBoostRate(): number {
    const cfg = this.config.adaptive;
    if (!cfg) return 0;
    const minSamples = cfg.minSamples ?? 20;
    const total = this._adaptiveWindow.length - this._adaptiveHead;
    if (total < minSamples) return 0;

    const errorRate = this._adaptiveErrors / total;
    const threshold = cfg.errorRateThreshold ?? 0.05;
    return errorRate >= threshold ? (cfg.boostRate ?? 1.0) : 0;
  }

  /** @internal Expose the current adaptive boost decision (tests / observability). */
  isBoosting(): boolean {
    return this._adaptiveBoostRate() > 0;
  }

  /**
   * Return the cached decision for a trace, or make and cache a new one. Entries
   * idle past the TTL, or older than the hard lifetime, are re-decided; the least
   * recently used entry is evicted once the cap is reached. IDs that are empty,
   * too long or contain control characters are sampled independently and never cached.
   */
  private _decideForTrace(traceId: string, level: string): boolean {
    if (!isCacheableTraceId(traceId)) return this._sampleByRate(level);

    const now = Date.now();
    const known = this.traceDecisions.get(traceId);
    if (
      known &&
      now - known.seenAt <= this.traceTtlMs &&
      now - known.firstAt <= this.traceMaxLifetimeMs
    ) {
      this.traceDecisions.delete(traceId);
      known.seenAt = now;
      this.traceDecisions.set(traceId, known);
      return known.emit;
    }

    const emit = this._sampleByRate(level);
    this.traceDecisions.delete(traceId);
    this.traceDecisions.set(traceId, { emit, firstAt: now, seenAt: now });
    if (this.traceDecisions.size > this.maxTrackedTraces) {
      const oldest = this.traceDecisions.keys().next().value;
      if (oldest !== undefined) this.traceDecisions.delete(oldest);
    }
    return emit;
  }

  private _consumeToken(): boolean {
    const now = Date.now();
    const elapsed = (now - this._lastRefillMs) / 1000;
    const max = this.config.maxLogsPerSecond!;

    // Refill tokens proportional to elapsed time
    this._tokenBucket = Math.min(max, this._tokenBucket + elapsed * max);
    this._lastRefillMs = now;

    if (this._tokenBucket >= 1) {
      this._tokenBucket -= 1;
      return true;
    }
    return false;
  }

  private _ensure(level: string): void {
    if (!this._stats.byLevel[level]) {
      this._stats.byLevel[level] = { evaluated: 0, emitted: 0 };
    }
  }

  private _trackEvaluated(level: string): void {
    this._stats.evaluated++;
    this._ensure(level);
    this._stats.byLevel[level]!.evaluated++;
  }

  private _trackEmitted(level: string): void {
    this._stats.emitted++;
    this._ensure(level);
    this._stats.byLevel[level]!.emitted++;
  }

  private _trackDropped(_level: string): void {
    this._stats.dropped++;
  }
}
