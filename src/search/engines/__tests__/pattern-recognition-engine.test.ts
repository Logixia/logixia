import type { LogEntry } from '../../../types';
import { PatternRecognitionEngine } from '../pattern-recognition-engine';

// Local-time timestamps: the engine buckets by Date#getHours(), so build them in local time.
function at(hour: number, minute = 0): string {
  return new Date(2024, 0, 15, hour, minute).toISOString();
}

function makeLog(message: string, overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: at(12),
    level: 'info',
    appName: 'test-app',
    message,
    traceId: 't-1',
    context: 'ctx',
    ...overrides,
  };
}

function messagePatterns(patterns: Array<{ category?: string }>) {
  return patterns.filter((p) => p.category === 'message');
}

describe('PatternRecognitionEngine', () => {
  describe('analyzePatterns', () => {
    it('groups messages that differ only by numbers into one pattern', async () => {
      const engine = new PatternRecognitionEngine();
      const logs = [123, 456, 789, 1011].map((n) => makeLog(`User ${n} logged in`));

      const patterns = await engine.analyzePatterns(logs);
      const msg = messagePatterns(patterns) as Array<(typeof patterns)[number]>;

      expect(msg).toHaveLength(1);
      expect(msg[0]!.pattern).toBe('User <NUM> logged in');
      expect(msg[0]!.frequency).toBe(4);
      expect(msg[0]!.examples).toHaveLength(3);
    });

    it('drops patterns seen fewer than minFrequency times (default 3)', async () => {
      const engine = new PatternRecognitionEngine();
      const logs = [
        makeLog('User 1 logged in'),
        makeLog('User 2 logged in'),
        makeLog('Cache cleared'),
      ];

      const patterns = await engine.analyzePatterns(logs);
      expect(messagePatterns(patterns)).toHaveLength(0);
    });

    it('honours a custom minFrequency', async () => {
      const engine = new PatternRecognitionEngine({ minFrequency: 2 });
      const logs = [makeLog('User 1 logged in'), makeLog('User 2 logged in')];

      const patterns = await engine.analyzePatterns(logs);
      expect(messagePatterns(patterns)).toHaveLength(1);
    });

    it('caps the result at maxPatterns', async () => {
      const engine = new PatternRecognitionEngine({ maxPatterns: 1 });
      const logs = [
        ...[1, 2, 3].map((n) => makeLog(`Alpha ${n}`)),
        ...[1, 2, 3].map((n) => makeLog(`Beta ${n} done`)),
      ];

      const patterns = await engine.analyzePatterns(logs);
      expect(patterns).toHaveLength(1);
    });

    it('sorts by frequency, descending', async () => {
      const engine = new PatternRecognitionEngine();
      const logs = [
        ...[1, 2, 3].map((n) => makeLog(`Rare ${n} event`)),
        ...[1, 2, 3, 4, 5, 6].map((n) => makeLog(`Common ${n} event`)),
        ...[1, 2, 3, 4].map((n) => makeLog(`Medium ${n} event`)),
      ];

      const patterns = await engine.analyzePatterns(logs);
      const freqs = patterns.map((p) => p.frequency);
      expect(freqs).toEqual([...freqs].sort((a, b) => b - a));

      const msg = messagePatterns(patterns);
      expect(msg.map((p) => (p as (typeof patterns)[number]).pattern)).toEqual([
        'Common <NUM> event',
        'Medium <NUM> event',
        'Rare <NUM> event',
      ]);
    });

    it('extracts error patterns from entries carrying an error object', async () => {
      const engine = new PatternRecognitionEngine();
      const logs = [1, 2, 3].map((n) =>
        makeLog(`Request ${n} failed`, {
          level: 'error',
          error: { name: 'TypeError', message: `bad value ${n}` } as Error,
        })
      );

      const patterns = await engine.analyzePatterns(logs);
      const errors = patterns.filter((p) => p.category === 'error');

      expect(errors).toHaveLength(1);
      expect(errors[0]!.pattern).toBe('TypeError: bad value <NUM>');
      expect(errors[0]!.frequency).toBe(3);
      expect(errors[0]!.severity).toBe('high');
    });

    it('reports the peak activity hour as a timing pattern', async () => {
      const engine = new PatternRecognitionEngine();
      const logs = [
        ...[0, 1, 2, 3].map((m) => makeLog(`Tick ${m}`, { timestamp: at(9, m) })),
        makeLog('Late', { timestamp: at(15) }),
      ];

      const patterns = await engine.analyzePatterns(logs);
      const timing = patterns.find((p) => p.category === 'timing');

      expect(timing).toMatchObject({ id: 'timing_peak', frequency: 4 });
      expect(timing!.pattern).toBe('Peak activity at hour 9');
    });

    it('normalises UUIDs and hashes before numbers so they group together', async () => {
      const engine = new PatternRecognitionEngine();
      const uuids = [
        '550e8400-e29b-41d4-a716-446655440000',
        '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      ];
      const hashes = [
        'd41d8cd98f00b204e9800998ecf8427e',
        '0cc175b9c0f1b6a831c399e269772661',
        '900150983cd24fb0d6963f7d28e17f72',
      ];
      const logs = [
        ...uuids.map((u) => makeLog(`Session ${u} opened`)),
        ...hashes.map((h) => makeLog(`Blob ${h} stored`)),
      ];

      const patterns = messagePatterns(await engine.analyzePatterns(logs)) as Array<{
        pattern: string;
        frequency: number;
      }>;

      expect(patterns.map((p) => [p.pattern, p.frequency]).sort()).toEqual([
        ['Blob <HASH> stored', 3],
        ['Session <UUID> opened', 3],
      ]);
    });

    it('returns an empty array for no logs', async () => {
      const engine = new PatternRecognitionEngine();
      expect(await engine.analyzePatterns([])).toEqual([]);
    });
  });

  describe('getPatterns / getPattern', () => {
    it('is empty before any analysis', () => {
      expect(new PatternRecognitionEngine().getPatterns()).toEqual([]);
    });

    it('returns what analyzePatterns stored and looks patterns up by id', async () => {
      const engine = new PatternRecognitionEngine();
      const logs = [1, 2, 3].map((n) => makeLog(`Job ${n} finished`));

      const result = await engine.analyzePatterns(logs);

      expect(engine.getPatterns()).toEqual(result);
      const first = result[0]!;
      expect(engine.getPattern(first.id)).toBe(first);
      expect(engine.getPattern('nope')).toBeUndefined();
    });
  });

  describe('findMatchingPatterns', () => {
    it('matches a new log that fits an existing pattern', async () => {
      const engine = new PatternRecognitionEngine();
      await engine.analyzePatterns([1, 2, 3].map((n) => makeLog(`User ${n} logged in`)));

      const matches = engine.findMatchingPatterns(makeLog('User 98765 logged in'));
      expect(matches).toHaveLength(1);
      expect(matches[0]!.pattern).toBe('User <NUM> logged in');
    });

    it('returns nothing for a log that fits no pattern or before analysis', async () => {
      const engine = new PatternRecognitionEngine();
      expect(engine.findMatchingPatterns(makeLog('anything'))).toEqual([]);

      await engine.analyzePatterns([1, 2, 3].map((n) => makeLog(`User ${n} logged in`)));
      expect(engine.findMatchingPatterns(makeLog('Something else entirely'))).toEqual([]);
    });
  });

  describe('detectAnomalies', () => {
    const common = [1, 2, 3, 4, 5].map((n) => makeLog(`User ${n} logged in`));

    it('scores a rare error above the common info logs, which are not reported', async () => {
      const engine = new PatternRecognitionEngine();
      const rareError = makeLog('Disk 7 full', { level: 'error' });
      const logs = [...common, rareError];
      await engine.analyzePatterns(logs);

      const anomalies = await engine.detectAnomalies(logs);

      expect(anomalies).toHaveLength(1);
      expect(anomalies[0]!.log).toBe(rareError);
      expect(anomalies[0]!.anomalyScore).toBeCloseTo(0.6);
      expect(anomalies[0]!.reason).toContain('rare error type');
      expect(anomalies[0]!.reason).toContain('does not match any known patterns');
    });

    it('sorts anomalies by score, descending, and flags off-hours entries', async () => {
      const engine = new PatternRecognitionEngine();
      const offHours = makeLog('Cron woke up', { timestamp: at(3), traceId: undefined });
      const rareError = makeLog('Disk 7 full', { level: 'error' });
      const logs = [...common, offHours, rareError];
      await engine.analyzePatterns(logs);

      const anomalies = await engine.detectAnomalies(logs);

      expect(anomalies.map((a) => a.log)).toEqual([rareError, offHours]);
      expect(anomalies[0]!.anomalyScore).toBeCloseTo(0.6);
      expect(anomalies[1]!.anomalyScore).toBeCloseTo(0.5);
      expect(anomalies[1]!.reason).toContain('occurred during off-hours');
      expect(anomalies[1]!.deviations).toContain('Missing trace ID');
    });

    it('reports nothing when no patterns are known and nothing else is unusual', async () => {
      const engine = new PatternRecognitionEngine();
      // unknown pattern alone scores 0.3, which is not above the 0.3 threshold
      expect(await engine.detectAnomalies(common)).toEqual([]);
    });

    it('honours a custom anomalyThreshold', async () => {
      const engine = new PatternRecognitionEngine({ anomalyThreshold: 0.2 });
      const anomalies = await engine.detectAnomalies(common);
      expect(anomalies).toHaveLength(common.length);
      expect(anomalies[0]!.reason).toContain('Slightly unusual');
    });

    it('flags missing context, oversized payloads and stack traces in non-error logs', async () => {
      const engine = new PatternRecognitionEngine({ anomalyThreshold: 0.2 });
      const payload = Object.fromEntries(Array.from({ length: 21 }, (_, i) => [`k${i}`, i]));
      const odd = makeLog('crashed\n    at run (/app/job.js:10:5)', {
        context: undefined,
        payload,
      });

      const [anomaly] = await engine.detectAnomalies([odd]);

      expect(anomaly!.deviations).toEqual(
        expect.arrayContaining([
          'Missing context',
          'Unusually large payload',
          'Stack trace in non-error log',
        ])
      );
    });

    it('does not flag prose containing "at " as a stack trace', async () => {
      const engine = new PatternRecognitionEngine({ anomalyThreshold: 0.2 });
      const logs = [
        makeLog('chat started'),
        makeLog('Retry scheduled at 5pm'),
        makeLog('crashed at line 4'),
      ];

      const anomalies = await engine.detectAnomalies(logs);

      expect(anomalies).toHaveLength(3);
      for (const a of anomalies) {
        expect(a.deviations).not.toContain('Stack trace in non-error log');
      }
    });

    it('does not treat a frequent error as rare, only a one-off', async () => {
      const engine = new PatternRecognitionEngine();
      const frequent = [1, 2, 3, 4].map((n) => makeLog(`Disk ${n} full`, { level: 'error' }));
      const oneOff = makeLog('Network unreachable', { level: 'error' });
      const logs = [...frequent, oneOff];
      await engine.analyzePatterns(logs);

      const anomalies = await engine.detectAnomalies(logs);

      expect(anomalies.map((a) => a.log)).toEqual([oneOff]);
      expect(anomalies[0]!.reason).toContain('rare error type');
    });

    it('a frequent error scores zero and carries no rare-error reason', async () => {
      const engine = new PatternRecognitionEngine({ anomalyThreshold: 0 });
      const frequent = [1, 2, 3].map((n) => makeLog(`Disk ${n} full`, { level: 'error' }));
      await engine.analyzePatterns(frequent);

      const anomalies = await engine.detectAnomalies(frequent);

      expect(anomalies).toEqual([]);
    });
  });
});
