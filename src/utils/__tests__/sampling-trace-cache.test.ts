import { Sampler } from '../sampling.utils';

type Internals = { traceDecisions: Map<string, unknown> };
const cache = (s: Sampler) => (s as unknown as Internals).traceDecisions;

describe('Sampler trace decision cache', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('does not cache invalid or oversized trace ids', () => {
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    s.shouldEmit('info', 'x'.repeat(16 * 1024));
    s.shouldEmit('info', 'a\r\nb');
    expect(cache(s).size).toBe(0);
    s.shouldEmit('info', 'valid-id');
    expect(cache(s).size).toBe(1);
    s.destroy();
  });

  it('keeps decisions consistent for a valid trace id', () => {
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    const first = s.shouldEmit('info', 'trace-1');
    for (let i = 0; i < 20; i++) expect(s.shouldEmit('info', 'trace-1')).toBe(first);
    s.destroy();
  });

  it('expires entries on an absolute TTL even when they keep being hit', () => {
    let now = 1_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    s.shouldEmit('info', 'trace-ttl');
    const entry = cache(s).get('trace-ttl') as { decidedAt: number };
    expect(entry.decidedAt).toBe(now);

    now += 4 * 60_000;
    s.shouldEmit('info', 'trace-ttl'); // hit must not refresh
    expect((cache(s).get('trace-ttl') as { decidedAt: number }).decidedAt).toBe(1_000_000);

    now += 2 * 60_000; // 6 minutes after the decision
    s.shouldEmit('info', 'trace-ttl');
    expect((cache(s).get('trace-ttl') as { decidedAt: number }).decidedAt).toBe(now);
    s.destroy();
  });

  it('evicts the oldest entries past the size cap', () => {
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    for (let i = 0; i < 10_050; i++) s.shouldEmit('info', `t-${i}`);
    expect(cache(s).size).toBe(10_000);
    expect(cache(s).has('t-0')).toBe(false);
    expect(cache(s).has('t-10049')).toBe(true);
    s.destroy();
  });
});
