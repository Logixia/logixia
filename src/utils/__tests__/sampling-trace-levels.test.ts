import { Sampler } from '../sampling.utils';

describe('Sampler traceConsistent across levels', () => {
  it('is not poisoned by the level of the trace first log', () => {
    const s = new Sampler({ traceConsistent: true, perLevel: { debug: 0, info: 1 } });
    let kept = 0;
    for (let i = 0; i < 100; i++) {
      s.shouldEmit('debug', `trace-${i}`);
      if (s.shouldEmit('info', `trace-${i}`)) kept += 1;
    }
    expect(kept).toBe(100);
    s.destroy();
  });

  it('keeps a trace at a lower rate only if it is kept at every higher rate', () => {
    const s = new Sampler({ traceConsistent: true, perLevel: { debug: 0.3, info: 0.7 } });
    let debugKept = 0;
    let infoKept = 0;
    for (let i = 0; i < 2000; i++) {
      const id = `trace-${i}`;
      const debug = s.shouldEmit('debug', id);
      const info = s.shouldEmit('info', id);
      if (debug) {
        debugKept += 1;
        expect(info).toBe(true);
      }
      if (info) infoKept += 1;
      expect(s.shouldEmit('info', id)).toBe(info);
    }
    expect(debugKept / 2000).toBeGreaterThan(0.2);
    expect(debugKept / 2000).toBeLessThan(0.4);
    expect(infoKept / 2000).toBeGreaterThan(0.6);
    expect(infoKept / 2000).toBeLessThan(0.8);
    s.destroy();
  });

  it('gives the same decision from separate samplers', () => {
    const a = new Sampler({ rate: 0.5, traceConsistent: true });
    const b = new Sampler({ rate: 0.5, traceConsistent: true });
    for (let i = 0; i < 100; i++) {
      expect(a.shouldEmit('info', `t${i}`)).toBe(b.shouldEmit('info', `t${i}`));
    }
    a.destroy();
    b.destroy();
  });
});

describe('Sampler adaptive window sliding', () => {
  it('drops old buckets as time passes without new samples', () => {
    const nowSpy = jest.spyOn(Date, 'now');
    let t = 1_000_000;
    nowSpy.mockImplementation(() => t);
    const s = new Sampler({
      rate: 0,
      adaptive: { windowMs: 1000, errorRateThreshold: 0.5, minSamples: 10 },
    });
    for (let i = 0; i < 20; i++) s.shouldEmit('error');
    expect(s.isBoosting()).toBe(true);
    t += 1500;
    expect(s.isBoosting()).toBe(false);
    nowSpy.mockRestore();
    s.destroy();
  });
});
