---
title: Worker Thread Transport
description: Run the logixia file, database or console transport in a Node.js worker thread to keep serialization and I/O off the main event loop, with automatic restarts.
order: 12
---

# Worker Thread Transport

`WorkerTransport` runs one of the built-in transports (file, database or console) inside a dedicated Node.js worker thread. The main thread only posts the entry to the worker. Formatting and I/O happen in the worker's own event loop.

Import it from `logixia/worker` (also available from `logixia/transports`) and add it through `transports.custom`. It needs Node.js worker threads, so it is not for browsers or edge runtimes.

## Quick start

```ts
import { createLogger } from 'logixia';
import { WorkerTransport } from 'logixia/worker';

const logger = createLogger({
  appName: 'api',
  transports: {
    custom: [
      new WorkerTransport({
        transportType: 'file',
        transportConfig: { filename: 'app.log', dirname: './logs', maxSize: '50MB' },
        bufferSize: 500,
        maxRestarts: 3,
      }),
    ],
  },
});

await logger.info('Logged from a worker thread');
await logger.close();
```

## Options

| Option            | Type                                | Default  | Description                                                                                                                           |
| ----------------- | ----------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `transportType`   | `'file' \| 'database' \| 'console'` | required | Which built-in transport runs in the worker.                                                                                          |
| `transportConfig` | `Record<string, unknown>`           | required | Config passed to that transport's constructor.                                                                                        |
| `bufferSize`      | `number`                            | `1000`   | Most entries held on the main thread while the worker is starting or restarting. Past it, the oldest entry is dropped with a warning. |
| `maxRestarts`     | `number`                            | `3`      | How many times to restart a crashed worker.                                                                                           |
| `level`           | `string`                            | unset    | Minimum level to forward to the worker.                                                                                               |

::: warning
`transportConfig` is copied to the worker with the structured clone algorithm, so it can only hold plain data. A `filter` function or a `rotation.shouldRotate` function inside it cannot be cloned. Put the `level` option on the `WorkerTransport` itself and keep functions out of `transportConfig`.
:::

## Lifecycle

- **Start.** The worker starts when the transport is created. Entries logged before the worker reports ready wait in the main-thread buffer and are sent in order once it is up.
- **Crash.** If the worker errors or exits with a non-zero code, the transport restarts it after a backoff of 500 ms times the attempt number. After `maxRestarts` restarts it gives up and logs an error. Entries buffered inside the crashed worker's wrapped transport are lost with it; the main-thread buffer only covers the start-up gap.
- **Errors.** Write errors inside the worker are reported to the main thread and logged to stderr. They do not throw into your `logger.info()` call.
- **Flush.** `flush()` asks the worker to flush its wrapped transport and waits up to 5 seconds for the answer.
- **Close.** `close()` sends any pending entries, then a shutdown message. The worker flushes and closes the wrapped transport and exits. If it has not exited after 5 seconds, it is terminated. `shutdown()` is an alias of `close()`.

::: tip
The worker entry file is built as CommonJS next to the transport's own output (`worker-entry.js`). If you bundle your app, make sure that file stays on disk next to the transport module.
:::

## When it helps

Moving work off the main thread helps when serializing and writing logs is a measurable cost in your service. It adds a message hop per entry and a thread, so for a low-volume service the plain [file transport](/guide/transports/file) is simpler. Measure before you switch.

## Related

- [File transport](/guide/transports/file) and [Database transport](/guide/transports/database), the transports you can run in the worker
- [Graceful shutdown](/guide/graceful-shutdown)
- [Transports overview](/guide/transports/)
