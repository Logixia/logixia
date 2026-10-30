---
title: Graceful shutdown
description: Flush logixia transports on SIGTERM and SIGINT so the last seconds of logs survive deploys and restarts, with timeout, exit mode and hook options.
order: 15
---

# Graceful shutdown

Batching transports hold entries in memory for a short while. If the process is killed during a deploy, those entries are lost. Graceful shutdown flushes and closes your loggers when the process receives a termination signal.

## Turn it on

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: { file: { filename: 'app.log', dirname: './logs' } },
  gracefulShutdown: { enabled: true, timeout: 5000 },
});

await logger.info('serving');
```

`gracefulShutdown: true` is shorthand for `{ enabled: true }`.

| Option    | Default                 | Description                                              |
| --------- | ----------------------- | -------------------------------------------------------- |
| `enabled` | required                | Register the handlers.                                   |
| `timeout` | `5000`                  | Milliseconds to wait for the flush before force-exiting. |
| `signals` | `['SIGTERM', 'SIGINT']` | Signals to handle.                                       |
| `exit`    | `'auto'`                | `'auto'`, `'always'` or `'never'`.                       |

## Who ends the process

- `'auto'` (default): logixia exits only if its handler is the only listener for that signal. If your app registered its own handler (for example `server.close()` or Nest shutdown hooks), logixia flushes and leaves the exit to you.
- `'always'`: always exit after the flush.
- `'never'`: flush only.

When logixia exits it uses status `128 + signal number`. The force-exit timer is only armed when logixia owns the exit, and exits with status 1 and a message on stderr if flushing hangs.

On signal, each registered logger has `close()` called, so the logger is closed afterwards. Loggers are also flushed, not closed, on `beforeExit`.

::: warning Do not add a second exit
Do not combine `gracefulShutdown` with a manual signal handler that calls `process.exit()` straight away; it can cut the flush short. Close your server in your handler and let the process end naturally, or set `exit: 'never'`.
:::

## flushOnExit for full control

`flushOnExit(options)` is the underlying function. It also supports hooks around the flush, which `gracefulShutdown` does not expose:

```ts
import { createLogger, flushOnExit, registerForShutdown } from 'logixia';

const logger = createLogger({ appName: 'api' });
registerForShutdown(logger);

flushOnExit({
  timeout: 8000,
  exit: 'never',
  beforeFlush: async () => {
    console.log('stop accepting traffic');
  },
  afterFlush: async () => {
    console.log('logs flushed');
  },
});
```

`flushOnExit` is idempotent: the first call wins, and a later call with different options prints a warning naming the conflicts. `deregisterFromShutdown(logger)` removes a logger and `resetShutdownHandlers()` removes the handlers, mainly for tests.

## Manual flushing

For scripts, jobs and tests, call `await logger.close()` before the process ends. It warns about unfinished timers, flushes and closes every transport, stops the sampler and runs plugin `onShutdown` hooks. Closing a child logger does not close the shared transports.

## NestJS

In NestJS, `app.enableShutdownHooks()` calls your lifecycle hooks on signals. Combine it with `gracefulShutdown: { enabled: true, exit: 'never' }` so logixia flushes while Nest controls the exit. See [NestJS](/guide/nestjs).
