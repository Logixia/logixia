/**
 * Comprehensive tests for the Sampler (log sampling engine)
 *
 * Covers:
 *  - Global rate: 0.0 (drop all), 1.0 (keep all)
 *  - Per-level rate overrides
 *  - Error/fatal always pass through (unless explicitly overridden)
 *  - Hard cap (maxLogsPerSecond token bucket)
 *  - Trace-consistent sampling
 *  - Stats tracking: evaluated, emitted, dropped, byLevel
 *  - resetStats and destroy
 *  - Periodic stats timer (via jest fake timers)
 */

import { Sampler } from '../sampling.utils';

describe('Sampler', () => {
  // ── Global rate: 1.0 (keep all) ───────────────────────────────────────────

  describe('rate: 1.0 (keep all)', () => {
    it('emits all entries', () => {
      const s = new Sampler({ rate: 1.0 });
      for (let i = 0; i < 100; i++) {
        expect(s.shouldEmit('info')).toBe(true);
      }
      s.destroy();
    });

    it('emits debug entries', () => {
      const s = new Sampler({ rate: 1.0 });
      expect(s.shouldEmit('debug')).toBe(true);
      s.destroy();
    });
  });

  // ── Global rate: 0.0 (drop all) ───────────────────────────────────────────

  describe('rate: 0.0 (drop all)', () => {
    it('drops info-level entries', () => {
      const s = new Sampler({ rate: 0.0 });
      for (let i = 0; i < 20; i++) {
        expect(s.shouldEmit('info')).toBe(false);
      }
      s.destroy();
    });

    it('drops debug-level entries', () => {
      const s = new Sampler({ rate: 0.0 });
      expect(s.shouldEmit('debug')).toBe(false);
      s.destroy();
    });

    it('still emits error entries (safety override)', () => {
      const s = new Sampler({ rate: 0.0 });
      expect(s.shouldEmit('error')).toBe(true);
      s.destroy();
    });

    it('still emits fatal entries (safety override)', () => {
      const s = new Sampler({ rate: 0.0 });
      expect(s.shouldEmit('fatal')).toBe(true);
      s.destroy();
    });
  });

  // ── Error/fatal safety bypass ──────────────────────────────────────────────

  describe('error / fatal safety bypass', () => {
    it('error always passes with any global rate', () => {
      const s = new Sampler({ rate: 0.001 });
      let allPass = true;
      for (let i = 0; i < 50; i++) {
        if (!s.shouldEmit('error')) {
          allPass = false;
          break;
        }
      }
      expect(allPass).toBe(true);
      s.destroy();
    });

    it('fatal always passes with any global rate', () => {
      const s = new Sampler({ rate: 0.001 });
      let allPass = true;
      for (let i = 0; i < 50; i++) {
        if (!s.shouldEmit('fatal')) {
          allPass = false;
          break;
        }
      }
      expect(allPass).toBe(true);
      s.destroy();
    });

    it('error respects an explicit perLevel override', () => {
      const s = new Sampler({ rate: 1.0, perLevel: { error: 0.0 } });
      // With perLevel.error = 0.0, error should now be dropped
      let dropped = false;
      for (let i = 0; i < 50; i++) {
        if (!s.shouldEmit('error')) {
          dropped = true;
          break;
        }
      }
      expect(dropped).toBe(true);
      s.destroy();
    });
  });

  // ── Per-level overrides ────────────────────────────────────────────────────

  describe('perLevel rate overrides', () => {
    it('debug is dropped when perLevel.debug = 0', () => {
      const s = new Sampler({ rate: 1.0, perLevel: { debug: 0.0 } });
      for (let i = 0; i < 20; i++) {
        expect(s.shouldEmit('debug')).toBe(false);
      }
      s.destroy();
    });

    it('info falls back to global rate when not in perLevel', () => {
      const s = new Sampler({ rate: 1.0, perLevel: { debug: 0.0 } });
      expect(s.shouldEmit('info')).toBe(true);
      s.destroy();
    });

    it('specific level override does not affect other levels', () => {
      const s = new Sampler({ rate: 1.0, perLevel: { verbose: 0.0 } });
      expect(s.shouldEmit('info')).toBe(true);
      expect(s.shouldEmit('warn')).toBe(true);
      s.destroy();
    });
  });

  // ── Hard cap (maxLogsPerSecond token bucket) ───────────────────────────────

  describe('maxLogsPerSecond (token bucket)', () => {
    it('drops entries once the per-second cap is exhausted', () => {
      const cap = 5;
      const s = new Sampler({ rate: 1.0, maxLogsPerSecond: cap });
      const results: boolean[] = [];
      for (let i = 0; i < 20; i++) {
        results.push(s.shouldEmit('info'));
      }
      const emitted = results.filter(Boolean).length;
      // Initial bucket = cap, so first `cap` should pass, rest should not
      expect(emitted).toBeLessThanOrEqual(cap + 1); // +1 tolerance for token refill timing
      s.destroy();
    });

    it('refills tokens over time and allows more entries', () => {
      jest.useFakeTimers();
      const s = new Sampler({ rate: 1.0, maxLogsPerSecond: 5 });

      // Exhaust the bucket
      for (let i = 0; i < 10; i++) s.shouldEmit('info');

      // Advance time by 2 seconds to refill ~10 tokens
      jest.advanceTimersByTime(2000);

      // Should be able to emit again
      expect(s.shouldEmit('info')).toBe(true);

      jest.useRealTimers();
      s.destroy();
    });
  });

  // ── Trace-consistent sampling ──────────────────────────────────────────────

  describe('traceConsistent', () => {
    it('all entries with a sampled traceId are emitted', () => {
      // rate: 1.0 ensures first encounter is sampled
      const s = new Sampler({ rate: 1.0, traceConsistent: true });
      const tid = 'trace-abc';
      // First call decides: should be sampled (rate 1.0)
      expect(s.shouldEmit('info', tid)).toBe(true);
      // Subsequent calls with same traceId should also be emitted
      expect(s.shouldEmit('debug', tid)).toBe(true);
      expect(s.shouldEmit('warn', tid)).toBe(true);
      s.destroy();
    });

    it('all entries with a dropped traceId are dropped', () => {
      // rate: 0.0 ensures first encounter is dropped
      const s = new Sampler({ rate: 0.0, traceConsistent: true });
      const tid = 'trace-xyz';
      // Error bypasses sampling safety — but for non-error levels:
      expect(s.shouldEmit('info', tid)).toBe(false);
      expect(s.shouldEmit('debug', tid)).toBe(false);
      s.destroy();
    });

    it('different traceIds have independent decisions', () => {
      const s = new Sampler({ rate: 1.0, traceConsistent: true });
      expect(s.shouldEmit('info', 'trace-1')).toBe(true);
      expect(s.shouldEmit('info', 'trace-2')).toBe(true);
      s.destroy();
    });

    it('entries without traceId fall back to rate-based sampling', () => {
      const s = new Sampler({ rate: 1.0, traceConsistent: true });
      expect(s.shouldEmit('info')).toBe(true);
      s.destroy();
    });
  });

  // ── Stats tracking ────────────────────────────────────────────────────────

  describe('getStats', () => {
    it('initializes with zero counts', () => {
      const s = new Sampler({});
      const stats = s.getStats();
      expect(stats.evaluated).toBe(0);
      expect(stats.emitted).toBe(0);
      expect(stats.dropped).toBe(0);
      s.destroy();
    });

    it('tracks evaluated count', () => {
      const s = new Sampler({ rate: 1.0 });
      s.shouldEmit('info');
      s.shouldEmit('info');
      expect(s.getStats().evaluated).toBe(2);
      s.destroy();
    });

    it('tracks emitted count', () => {
      const s = new Sampler({ rate: 1.0 });
      s.shouldEmit('info');
      s.shouldEmit('debug');
      expect(s.getStats().emitted).toBe(2);
      s.destroy();
    });

    it('tracks dropped count', () => {
      const s = new Sampler({ rate: 0.0 });
      s.shouldEmit('info');
      s.shouldEmit('debug');
      // error is not dropped, so we only check non-safety levels
      expect(s.getStats().dropped).toBe(2);
      s.destroy();
    });

    it('tracks per-level stats', () => {
      const s = new Sampler({ rate: 1.0 });
      s.shouldEmit('info');
      s.shouldEmit('info');
      s.shouldEmit('debug');
      const stats = s.getStats();
      expect(stats.byLevel['info']?.evaluated).toBe(2);
      expect(stats.byLevel['debug']?.evaluated).toBe(1);
      s.destroy();
    });

    it('returns a snapshot (not a reference)', () => {
      const s = new Sampler({ rate: 1.0 });
      const stats1 = s.getStats();
      s.shouldEmit('info');
      const stats2 = s.getStats();
      expect(stats1.evaluated).toBe(0);
      expect(stats2.evaluated).toBe(1);
      s.destroy();
    });
  });

  // ── resetStats ────────────────────────────────────────────────────────────

  describe('resetStats', () => {
    it('resets all counts to zero', () => {
      const s = new Sampler({ rate: 1.0 });
      s.shouldEmit('info');
      s.shouldEmit('info');
      s.resetStats();
      const stats = s.getStats();
      expect(stats.evaluated).toBe(0);
      expect(stats.emitted).toBe(0);
      expect(stats.dropped).toBe(0);
      expect(stats.byLevel).toEqual({});
      s.destroy();
    });

    it('clears trace sets after reset', () => {
      const s = new Sampler({ rate: 1.0, traceConsistent: true });
      s.shouldEmit('info', 'trace-1');
      s.resetStats();
      // After reset, 'trace-1' is no longer in sampledTraces,
      // so it gets re-evaluated — with rate=1.0 it should still emit
      expect(s.shouldEmit('info', 'trace-1')).toBe(true);
      s.destroy();
    });
  });

  // ── destroy ───────────────────────────────────────────────────────────────

  describe('destroy', () => {
    it('clears the stats timer without error', () => {
      jest.useFakeTimers();
      const s = new Sampler({ statsIntervalMs: 1000 }, jest.fn());
      expect(() => s.destroy()).not.toThrow();
      jest.useRealTimers();
    });

    it('is safe to call multiple times', () => {
      const s = new Sampler({});
      expect(() => {
        s.destroy();
        s.destroy();
      }).not.toThrow();
    });
  });

  // ── Periodic stats timer ──────────────────────────────────────────────────

  describe('stats reporting interval', () => {
    it('calls onStats callback at the configured interval', () => {
      jest.useFakeTimers();
      const onStats = jest.fn();
      const s = new Sampler({ statsIntervalMs: 500 }, onStats);

      s.shouldEmit('info');

      jest.advanceTimersByTime(500);
      expect(onStats).toHaveBeenCalledTimes(1);

      jest.advanceTimersByTime(500);
      expect(onStats).toHaveBeenCalledTimes(2);

      s.destroy();
      jest.useRealTimers();
    });

    it('does not create a timer when statsIntervalMs is 0', () => {
      jest.useFakeTimers();
      const onStats = jest.fn();
      const s = new Sampler({ statsIntervalMs: 0 }, onStats);

      jest.advanceTimersByTime(60_000);
      expect(onStats).not.toHaveBeenCalled();

      s.destroy();
      jest.useRealTimers();
    });

    it('resets stats after each reporting cycle', () => {
      jest.useFakeTimers();
      let lastStats: unknown;
      const s = new Sampler({ statsIntervalMs: 1000 }, (stats) => {
        lastStats = stats;
      });

      s.shouldEmit('info');
      jest.advanceTimersByTime(1000);

      // After reset, a new emit should start from 0
      jest.advanceTimersByTime(1000);
      const stats = s.getStats();
      expect(stats.evaluated).toBe(0);

      s.destroy();
      jest.useRealTimers();
      // lastStats used for side-effect only
      expect(lastStats).toBeDefined();
    });
  });
});
