/**
 * Logixia benchmark suite
 * Compares logixia against pino and winston
 *
 * Methodology:
 *   - All libraries write to /dev/null (no I/O overhead)
 *   - Measures pure serialization + framework overhead
 *   - logixia console transport writes are intercepted via process.stdout/stderr
 *
 * Run: node benchmarks/run.mjs
 */

import { Writable } from 'node:stream';

import pino from 'pino';
import { Bench } from 'tinybench';
import winston from 'winston';

import { createLogger } from '../dist/index.js';

// ── Null stream for pino / winston ──────────────────────────────────────────
const devNull = new Writable({
  write(_chunk, _enc, cb) {
    cb();
  },
});

// Intercept process.stdout/stderr so logixia console transport output is swallowed
const _realOut = process.stdout.write.bind(process.stdout);
const _realErr = process.stderr.write.bind(process.stderr);
const silence = () => {
  process.stdout.write = () => true;
  process.stderr.write = () => true;
};
const restore = () => {
  process.stdout.write = _realOut;
  process.stderr.write = _realErr;
};

// ── Library instances ────────────────────────────────────────────────────────
const pinoLogger = pino({ level: 'info' }, devNull);
const winstonLogger = winston.createLogger({
  level: 'info',
  transports: [new winston.transports.Stream({ stream: devNull })],
});
// logixia — default console transport; output intercepted at stdout/stderr level
const logixia = createLogger({ appName: 'bench', environment: 'production' });

// ── Payloads ─────────────────────────────────────────────────────────────────
const META = {
  requestId: 'abc-123-xyz',
  userId: 42,
  action: 'login',
  ip: '127.0.0.1',
  latency: 14,
};
const ERR = new Error('Connection timeout');

// ── Helpers ──────────────────────────────────────────────────────────────────
function formatResults(bench) {
  return bench.tasks
    .filter((t) => t.result?.state === 'completed')
    .map((t) => ({
      Library: t.name,
      'ops/sec': Math.round(t.result.throughput.mean).toLocaleString(),
      'p99 (µs)': (t.result.latency.p99 * 1000).toFixed(1),
    }))
    .sort(
      (a, b) =>
        Number.parseInt(b['ops/sec'].replace(/,/g, ''), 10) -
        Number.parseInt(a['ops/sec'].replace(/,/g, ''), 10)
    );
}

// ── Suites ───────────────────────────────────────────────────────────────────
const simple = new Bench({ name: 'Simple string log', time: 3000 });
simple
  .add('pino', () => {
    pinoLogger.info('User logged in');
  })
  .add('winston', () => {
    winstonLogger.info('User logged in');
  })
  .add('logixia', async () => {
    await logixia.info('User logged in');
  });

const structured = new Bench({ name: 'Structured log (with metadata)', time: 3000 });
structured
  .add('pino', () => {
    pinoLogger.info(META, 'User logged in');
  })
  .add('winston', () => {
    winstonLogger.info('User logged in', META);
  })
  .add('logixia', async () => {
    await logixia.info('User logged in', META);
  });

const errorsBench = new Bench({ name: 'Error object logging', time: 3000 });
errorsBench
  .add('pino', () => {
    pinoLogger.error({ err: ERR }, 'Request failed');
  })
  .add('winston', () => {
    winstonLogger.error('Request failed', { error: ERR.message });
  })
  .add('logixia', async () => {
    await logixia.error('Request failed', ERR);
  });

// ── Runner ───────────────────────────────────────────────────────────────────
async function run() {
  _realOut('\nLogixia Benchmark Suite\n');
  _realOut('Node.js ' + process.version + ' | ' + process.platform + '-' + process.arch + '\n');
  _realOut('='.repeat(60) + '\n');

  const allResults = {};

  silence();
  try {
    for (const bench of [simple, structured, errorsBench]) {
      _realOut('\nRunning: "' + bench.name + '" ...');
      await bench.run();
      _realOut(' done\n\n');
      const rows = formatResults(bench);
      allResults[bench.name] = rows;
    }
  } finally {
    restore();
  }

  console.log('='.repeat(60));
  console.log('Results — higher ops/sec is better\n');
  for (const [name, rows] of Object.entries(allResults)) {
    console.log(name + ':');
    for (const row of rows) {
      console.log(
        '  ' +
          row.Library.padEnd(10) +
          row['ops/sec'].padStart(14) +
          ' ops/sec   p99: ' +
          row['p99 (µs)'] +
          'µs'
      );
    }
    console.log('');
  }
}

run().catch((e) => {
  restore();
  console.error(e);
  process.exit(1);
});
