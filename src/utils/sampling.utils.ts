/**
 * Log sampling & rate-limiting engine.
 *
 * Completely stateless between log calls — all state lives in the Sampler instance
 * so multiple loggers can have independent sampling budgets.
 */

import type { SamplingConfig } from '../types';

// Safety-critical levels that are NEVER sampled below 100 % by default.
const ALWAYS_EMIT_LEVELS = new Set(['error', 'fatal']);

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

  // Rate-limiting state
  private _tokenBucket = 0;
  private _lastRefillMs = Date.now();

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
        this.sampledTraces.add(traceId);
      } else {
        this.droppedTraces.add(traceId);
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
    const rate =
      this.config.perLevel?.[level] ?? this.config.perLevel?.['*'] ?? this.config.rate ?? 1.0;

    if (rate >= 1.0) return true;
    if (rate <= 0.0) return false;
    // eslint-disable-next-line sonarjs/pseudo-random -- probabilistic sampling, not security-sensitive
    return Math.random() < rate;
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
