import type { AnalyticsTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { internalWarn } from '../../utils/internal-log';
import { AnalyticsTransport } from '../analytics.transport';

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

describe('AnalyticsTransport buffer cap', () => {
  beforeEach(() => jest.clearAllMocks());

  it('drops the oldest entries past maxBufferSize and reports it', () => {
    const t = new FailingTransport({
      apiKey: 'k',
      batchSize: 1_000_000,
      flushInterval: 600_000,
      maxBufferSize: 5,
    });
    for (let i = 0; i < 12; i += 1) t.addToBatch(makeEntry(i));
    expect(t.buffered()).toBe(5);
    expect(internalWarn).toHaveBeenCalledWith(expect.stringContaining('dropped'));
    void t.close();
  });

  it('keeps the buffer bounded across failed flushes and delivers the newest', async () => {
    const t = new FailingTransport({
      apiKey: 'k',
      batchSize: 1_000_000,
      flushInterval: 600_000,
      maxBufferSize: 10,
    });
    for (let round = 0; round < 5; round += 1) {
      for (let i = 0; i < 8; i += 1) t.addToBatch(makeEntry(round * 8 + i));
      await t.flush();
    }
    expect(t.buffered()).toBe(10);

    t.failing = false;
    await t.flush();
    expect(t.sent).toHaveLength(10);
    expect(t.sent.at(-1)).toBe('line-39');
    await t.close();
  });

  it('defaults to 10000 entries', () => {
    const t = new FailingTransport({ apiKey: 'k', batchSize: 1_000_000, flushInterval: 600_000 });
    for (let i = 0; i < 10_010; i += 1) t.addToBatch(makeEntry(i));
    expect(t.buffered()).toBe(10_000);
    void t.close();
  });
});
