import { flushOnExit, registerForShutdown } from '../../src/utils/shutdown.utils';

const mode = process.argv[2];
const log = (line: string) => process.stdout.write(`${line}\n`);

registerForShutdown({
  close: async () => {
    await new Promise((resolve) => setTimeout(resolve, 50));
    log('logger-closed');
  },
  flush: async () => {
    await new Promise((resolve) => setTimeout(resolve, 50));
    log('logger-flushed');
  },
});

if (mode === 'own-handler') {
  flushOnExit({ timeout: 2000 });
  const keepAlive = setInterval(() => {}, 1000);
  process.on('SIGTERM', () => {
    setTimeout(() => {
      log('app-cleanup-done');
      clearInterval(keepAlive);
    }, 300);
  });
  log('ready');
} else if (mode === 'sole-handler') {
  flushOnExit({ timeout: 2000 });
  setInterval(() => {}, 1000);
  log('ready');
} else if (mode === 'natural-exit') {
  flushOnExit({ timeout: 2000 });
  log('ready');
}
