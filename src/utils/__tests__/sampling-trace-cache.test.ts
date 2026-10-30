import { Sampler } from '../sampling.utils';

type Entry = { firstAt: number; seenAt: number };
type Internals = { traceDecisions: Map<string, Entry> };
const cache = (s: Sampler) => (s as unknown as Internals).traceDecisions;

describe('Sampler trace decision cache', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('does not cache empty, oversized or control-character trace ids', () => {
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    s.shouldEmit('info', 'x'.repeat(16 * 1024));
    s.shouldEmit('info', 'x'.repeat(257));
    s.shouldEmit('info', 'a\r\nb');
    s.shouldEmit('info', 'a\u009bb');
    expect(cache(s).size).toBe(0);
    s.shouldEmit('info', 'svc/123e4567-e89b-12d3-a456-426614174000');
    expect(cache(s).size).toBe(1);
    s.destroy();
  });

  it('keeps decisions consistent for a valid trace id', () => {
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    const first = s.shouldEmit('info', 'trace-1');
    for (let i = 0; i < 20; i++) expect(s.shouldEmit('info', 'trace-1')).toBe(first);
    s.destroy();
  });

  it('refreshes the idle TTL on hit but enforces a hard maximum lifetime', () => {
    let now = 1_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    s.shouldEmit('info', 'trace-ttl');
    const first = now;

    now += 4 * 60_000;
    s.shouldEmit('info', 'trace-ttl');
    expect(cache(s).get('trace-ttl')!.seenAt).toBe(now);
    expect(cache(s).get('trace-ttl')!.firstAt).toBe(first);

    // keep it active for just under an hour
    for (let i = 0; i < 14; i++) {
      now += 4 * 60_000;
      s.shouldEmit('info', 'trace-ttl');
    }
    expect(cache(s).get('trace-ttl')!.firstAt).toBe(first);

    now = first + 61 * 60_000; // past the hard lifetime, though recently seen
    s.shouldEmit('info', 'trace-ttl');
    expect(cache(s).get('trace-ttl')!.firstAt).toBe(now);
    s.destroy();
  });

  it('expires idle entries after the TTL', () => {
    let now = 5_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    s.shouldEmit('info', 't');
    now += 6 * 60_000;
    s.shouldEmit('info', 't');
    expect(cache(s).get('t')!.firstAt).toBe(now);
    s.destroy();
  });

  it('evicts the least recently used entry past the size cap', () => {
    const s = new Sampler({ rate: 0.5, traceConsistent: true });
    for (let i = 0; i < 100_010; i++) s.shouldEmit('info', `t-${i}`);
    expect(cache(s).size).toBe(100_000);
    expect(cache(s).has('t-0')).toBe(false);
    expect(cache(s).has('t-100009')).toBe(true);
    s.destroy();
  });
});
