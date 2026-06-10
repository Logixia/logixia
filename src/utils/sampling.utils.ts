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
  /** Trace IDs that have been sampled in this window → always emit. */
  private readonly sampledTraces = new Set<string>();
  /** Trace IDs that have been dropped in this window → always drop. */
  private readonly droppedTraces = new Set<string>();
  /**
   * Upper bound on tracked trace IDs. resetStats() only clears these Sets when a
   * stats timer is running, so without an onStats callback they would otherwise
   * grow unbounded for the life of the process (one entry per unique traceId) —
   * a memory leak in any long-running service using traceConsistent sampling.
   * When a Set hits this cap it is cleared; a re-seen trace simply gets a fresh
   * sampling decision, which is acceptable for sampling consistency.
   */
  private readonly maxTrackedTraces = 100_000;

  // Rate-limiting state
  private _tokenBucket = 0;
  private _lastRefillMs = Date.now();

  // Adaptive (anomaly-driven) sampling state — a sliding window of recent
  // (timestamp, isError) samples used to compute the current error rate.
  private readonly _adaptiveWindow: Array<{ t: number; err: boolean }> = [];

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

    // ── 2. Trace-consistent sampling ──────────────────────────────────────────
    if (this.config.traceConsistent && traceId) {
      if (this.sampledTraces.has(traceId)) {
        this._trackEmitted(lvl);
        return true;
      }
      if (this.droppedTraces.has(traceId)) {
        this._trackDropped(lvl);
        return false;
      }
      // First time we see this traceId — make the sampling decision now
      const emit = this._sampleByRate(lvl);
      if (emit) {
        this._rememberTrace(this.sampledTraces, traceId);
      } else {
        this._rememberTrace(this.droppedTraces, traceId);
      }
      if (emit) this._trackEmitted(lvl);
      else this._trackDropped(lvl);
      return emit;
    }

    // ── 3. Rate-based sampling ─────────────────────────────────────────────────
    const emit = this._sampleByRate(lvl);
    if (!emit) {
      this._trackDropped(lvl);
      return false;
    }

    // ── 4. Hard cap (token bucket) ────────────────────────────────────────────
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
    // Clear trace sets so long-running processes don't accumulate unbounded memory
    this.sampledTraces.clear();
    this.droppedTraces.clear();
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

  /**
   * Record one evaluated sample into the adaptive sliding window and evict
   * entries older than the window. Cheap O(evicted) amortized.
   */
  private _recordAdaptiveSample(level: string): void {
    const now = Date.now();
    const windowMs = this.config.adaptive?.windowMs ?? 10_000;
    this._adaptiveWindow.push({ t: now, err: level === 'error' || level === 'fatal' });
    const cutoff = now - windowMs;
    while (this._adaptiveWindow.length > 0 && this._adaptiveWindow[0]!.t < cutoff) {
      this._adaptiveWindow.shift();
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
    const total = this._adaptiveWindow.length;
    if (total < minSamples) return 0;

    let errors = 0;
    for (const s of this._adaptiveWindow) if (s.err) errors += 1;
    const errorRate = errors / total;
    const threshold = cfg.errorRateThreshold ?? 0.05;
    return errorRate >= threshold ? (cfg.boostRate ?? 1.0) : 0;
  }

  /** @internal Expose the current adaptive boost decision (tests / observability). */
  isBoosting(): boolean {
    return this._adaptiveBoostRate() > 0;
  }

  /**
   * Record a trace decision, bounding the Set so it can't grow without limit.
   * If the Set has reached the cap, clear it before inserting — stale decisions
   * are simply re-made on next sight, which keeps memory bounded at the cost of
   * occasional re-sampling for very high-cardinality trace workloads.
   */
  private _rememberTrace(set: Set<string>, traceId: string): void {
    if (set.size >= this.maxTrackedTraces) {
      set.clear();
    }
    set.add(traceId);
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
