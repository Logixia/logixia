import type { AnalyticsTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { internalWarn } from '../../utils/internal-log';
import { AnalyticsTransport } from '../analytics.transport';
import { BufferCap, DEFAULT_BUFFER_CAP } from '../buffer-cap';

jest.mock('../../utils/internal-log', () => ({
  ...jest.requireActual('../../utils/internal-log'),
  internalWarn: jest.fn(),
  internalError: jest.fn(),
}));

function makeEntry(index: number): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `line-${index}`,
  };
}

class FailingTransport extends AnalyticsTransport {
  public sent: string[] = [];
  public failing = true;

  constructor(config: AnalyticsTransportConfig) {
    super('failing', config);
    this.isReady = true;
  }

  protected initialize(): void {}

  protected async sendEntry(): Promise<void> {}

  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    if (this.failing) throw new Error('provider down');
    this.sent.push(...entries.map((e) => e.message));
  }

  protected cleanup(): void {}

  public buffered(): number {
    return this.batch.length;
  }
}

describe('BufferCap', () => {
  beforeEach(() => jest.clearAllMocks());

  it('drops the oldest items in place and reports them', () => {
    const cap = new BufferCap('T', 3, 1);
    const items = [1, 2, 3, 4, 5];
    cap.enforce(items);
    expect(items).toEqual([3, 4, 5]);
    expect(internalWarn).toHaveBeenCalledWith(expect.stringContaining('dropped 2'));
  });

  it('defaults to 10000', () => {
    expect(new BufferCap('T', undefined, 1).max).toBe(DEFAULT_BUFFER_CAP);
  });

  it.each([0, -3, 1.5, Number.NaN])('falls back to the default for %s and warns', (bad) => {
    expect(new BufferCap('T', bad, 1).max).toBe(DEFAULT_BUFFER_CAP);
    expect(internalWarn).toHaveBeenCalledWith(expect.stringContaining('maxBufferSize'));
  });

  it('raises a cap below batchSize to batchSize', () => {
    expect(new BufferCap('T', 2, 50).max).toBe(50);
  });
});

describe('AnalyticsTransport buffer cap', () => {
  beforeEach(() => jest.clearAllMocks());

  it('keeps the buffer bounded across failed flushes and delivers the newest', async () => {
    const t = new FailingTransport({
      apiKey: 'k',
      batchSize: 5,
      flushInterval: 600_000,
      maxBufferSize: 10,
    });
    for (let round = 0; round < 5; round += 1) {
      for (let i = 0; i < 8; i += 1) t.addToBatch(makeEntry(round * 8 + i));
      await t.flush();
    }
    expect(t.buffered()).toBeLessThanOrEqual(10);
    expect(internalWarn).toHaveBeenCalledWith(expect.stringContaining('dropped'));

    t.failing = false;
    await t.flush();
    expect(t.sent.at(-1)).toBe('line-39');
    expect(t.sent.length).toBeLessThanOrEqual(10);
    await t.close();
  });

  it('never caps below batchSize', async () => {
    const t = new FailingTransport({
      apiKey: 'k',
      batchSize: 20,
      flushInterval: 600_000,
      maxBufferSize: 2,
    });
    for (let i = 0; i < 15; i += 1) t.addToBatch(makeEntry(i));
    expect(t.buffered()).toBe(15);
    await t.close();
  });
});
