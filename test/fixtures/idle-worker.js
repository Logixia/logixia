// Stand-in for worker-entry.js: appends every write to $IDLE_WORKER_OUT and
// stays alive on its own, like a worker holding a database connection.
const fs = require('node:fs');
const { parentPort } = require('node:worker_threads');

setInterval(() => {}, 1000);
parentPort.postMessage({ type: 'ready' });
parentPort.on('message', (msg) => {
  if (msg.type === 'write')
    fs.appendFileSync(process.env.IDLE_WORKER_OUT, `${msg.entry.message}\n`);
  else if (msg.type === 'flush') parentPort.postMessage({ type: 'flushed' });
  else if (msg.type === 'shutdown') process.exit(0);
});
