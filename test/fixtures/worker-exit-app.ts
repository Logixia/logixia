import path from 'path';

import { WorkerTransport } from '../../src/transports/worker.transport';

class IdleWorkerTransport extends WorkerTransport {
  protected override workerFile(): string {
    return path.join(__dirname, 'idle-worker.js');
  }
}

const transport = new IdleWorkerTransport({ transportType: 'console', transportConfig: {} });
for (let i = 0; i < 20; i++) {
  transport.write({ timestamp: new Date(), level: 'info', message: `line-${i}` });
}
