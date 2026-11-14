import { EventEmitter } from 'events';

import type { DatabaseTransportConfig } from '../../types/transport.types';
import { DatabaseTransport } from '../database.transport';

const clients: FakeClient[] = [];
let failConnect = false;

class FakeClient extends EventEmitter {
  queries: string[] = [];
  constructor() {
    super();
    clients.push(this);
  }
  async connect() {
    if (failConnect) throw new Error('ECONNREFUSED');
  }
  async query(sql: string) {
    this.queries.push(sql);
    return { rows: [] };
  }
  async end() {}
}

jest.mock('pg', () => ({ Client: jest.fn(() => new FakeClient()) }), { virtual: true });

function makeTransport(batchSize = 2) {
  return new DatabaseTransport({
    type: 'postgresql',
    database: 'x',
    table: 'logs',
    batchSize,
    flushInterval: 60000,
    maxBufferSize: 1000,
  } as unknown as DatabaseTransportConfig);
}

const entry = (i: number) => ({ timestamp: new Date(), level: 'info', message: `m${i}` });

beforeEach(() => {
  clients.length = 0;
  failConnect = false;
});

describe('DatabaseTransport connection loss', () => {
  it('survives an unhandled client error event and reconnects on the next flush', async () => {
    const transport = makeTransport();
    await transport.write(entry(1));
    await transport.write(entry(2));
    expect(clients).toHaveLength(1);
    expect(transport.getBatchInfo().isConnected).toBe(true);

    expect(() => clients[0]!.emit('error', new Error('terminating connection'))).not.toThrow();
    expect(transport.getBatchInfo().isConnected).toBe(false);

    await transport.write(entry(3));
    await transport.write(entry(4));
    expect(clients).toHaveLength(2);
    expect(clients[1]!.queries.some((q) => q.includes('INSERT'))).toBe(true);
    await transport.close();
  });

  it('marks the transport disconnected on the end event', async () => {
    const transport = makeTransport();
    await transport.write(entry(1));
    await transport.write(entry(2));
    clients[0]!.emit('end');
    expect(transport.getBatchInfo().isConnected).toBe(false);
    await transport.close();
  });
});

describe('DatabaseTransport while the database is down', () => {
  it('buffers every entry and makes one connect attempt, not one per log', async () => {
    failConnect = true;
    const transport = makeTransport(5);
    for (let i = 0; i < 200; i++) await transport.write(entry(i));
    expect(clients).toHaveLength(1);
    expect(transport.getBatchInfo().currentBatchLength).toBe(200);
    await transport.close();
  });
});
