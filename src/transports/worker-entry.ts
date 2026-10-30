import { parentPort, workerData } from 'node:worker_threads';

import type { ITransport, TransportLogEntry } from '../types/transport.types';
import { ConsoleTransport } from './console.transport';
import { DatabaseTransport } from './database.transport';
import { FileTransport } from './file.transport';
import { buildLevelValues, meetsTransportLevel } from './level-filter';

type WorkerMessage =
  { type: 'write'; entry: TransportLogEntry } | { type: 'flush' } | { type: 'shutdown' };

interface WorkerInit {
  transportType: 'file' | 'database' | 'console';
  transportConfig: Record<string, unknown>;
  levels?: Record<string, number>;
}

const port = parentPort;
if (!port) throw new Error('worker-entry must run inside a worker thread');

const { transportType, transportConfig, levels } = workerData as WorkerInit;
const levelValues = buildLevelValues(levels);

type WrappedTransport = ITransport & { flush?(): Promise<void>; close?(): Promise<void> };

function createTransport(): WrappedTransport {
  const config: unknown = transportConfig;
  switch (transportType) {
    case 'file':
      return new FileTransport(config as ConstructorParameters<typeof FileTransport>[0]);
    case 'database':
      return new DatabaseTransport(config as ConstructorParameters<typeof DatabaseTransport>[0]);
    default:
      return new ConsoleTransport(config as ConstructorParameters<typeof ConsoleTransport>[0]);
  }
}

const errorMessage = (err: unknown): string => (err instanceof Error ? err.message : String(err));

let transport: WrappedTransport;
try {
  transport = createTransport();
} catch (err) {
  port.postMessage({ type: 'error', error: errorMessage(err) });
  process.exit(1);
}

const flushTransport = async (): Promise<void> => {
  if (typeof transport.flush === 'function') await transport.flush();
};

async function handle(msg: WorkerMessage): Promise<void> {
  if (msg.type === 'write') {
    if (!meetsTransportLevel(transport.level, msg.entry.level, levelValues)) return;
    try {
      await transport.write(msg.entry);
    } catch (err) {
      port?.postMessage({ type: 'write-error', error: errorMessage(err), entry: msg.entry });
    }
  } else if (msg.type === 'flush') {
    try {
      await flushTransport();
      port?.postMessage({ type: 'flushed' });
    } catch (err) {
      port?.postMessage({ type: 'flush-error', error: errorMessage(err) });
    }
  } else {
    try {
      await flushTransport();
      if (typeof transport.close === 'function') await transport.close();
    } catch {
      // exiting anyway
    }
    process.exit(0);
  }
}

// Messages are handled one at a time so shutdown flushes after earlier writes.
let queue: Promise<void> = Promise.resolve();
port.on('message', (msg: WorkerMessage) => {
  queue = queue.then(() => handle(msg));
});

port.postMessage({ type: 'ready' });
