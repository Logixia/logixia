// Runs the built package, not src: jest only ever sees the TypeScript, so a bundler
// bug that changes what dist/ does at runtime would otherwise ship unnoticed.
//
// - No chunk may contain the broken static-field lowering `static #x = () => ...`,
//   an arrow that never runs, which left ConsoleTransport.COLORS undefined (2.0.4-2.0.10).
// - The CJS and ESM entries must log through the console transport (text and JSON,
//   colorized or not) without a single "Transport write failed".
// - Static state used by the NestJS entry must exist after load.
//
// Run via `npm run check:dist` after `npm run build`.
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
if (!fs.existsSync(path.join(dist, 'index.js'))) {
  console.error('dist/index.js missing - run `npm run build` first');
  process.exit(1);
}

const failures = [];

const brokenStatic = /static #\w+ = \(\) =>/;
for (const file of fs.readdirSync(dist)) {
  if (!/\.(?:c|m)?js$/.test(file)) continue;
  if (brokenStatic.test(fs.readFileSync(path.join(dist, file), 'utf8'))) {
    failures.push(`${file}: static class field lowered to an arrow that never runs`);
  }
}

async function logThroughConsole(label, createLogger) {
  const writes = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  const capture = (chunk) => {
    writes.push(String(chunk));
    return true;
  };
  process.stdout.write = capture;
  process.stderr.write = capture;
  try {
    for (const options of [
      { colorize: true, format: 'text' },
      { colorize: false, format: 'text' },
      { format: 'json' },
    ]) {
      const logger = createLogger({
        appName: 'dist-check',
        environment: 'test',
        transports: { console: options },
      });
      await logger.info('dist check', { n: 1 });
      await logger.warn('dist check');
      await logger.error(new Error('dist check'));
      await logger.close();
    }
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
  }
  const failed = writes.filter((w) => w.includes('Transport write failed'));
  if (failed.length > 0) {
    failures.push(`${label}: ${failed.length} console transport write failures`);
  }
}

const require = createRequire(import.meta.url);
const cjs = require(path.join(dist, 'index.js'));
await logThroughConsole('CJS', cjs.createLogger);
const esm = await import(pathToFileURL(path.join(dist, 'index.mjs')).href);
await logThroughConsole('ESM', esm.createLogger);

const nest = require(path.join(dist, 'nest.js'));
if (nest.KafkaTraceInterceptor?.metrics === undefined) {
  failures.push('nest: KafkaTraceInterceptor.metrics is undefined after load');
}

if (failures.length > 0) {
  console.error(`dist runtime check failed:\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log('dist runtime check passed');
