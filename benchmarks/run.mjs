/**
 * Logixia benchmark suite — logixia vs pino, winston, bunyan.
 *
 * Methodology:
 *   - All libraries write to /dev/null (no real I/O) so we measure pure
 *     serialization + framework overhead, not disk/terminal speed.
 *   - logixia console output is intercepted at process.stdout/stderr.
 *   - bunyan is OPTIONAL — skipped automatically if not installed.
 *   - Two logixia configs are benched where relevant: the default (text/console)
 *     and JSON mode (the apples-to-apples comparison vs pino's JSON output).
 *
 * Scenarios:
 *   1. Simple string log
 *   2. Structured log (5-field metadata)
 *   3. Error object logging
 *   4. Child / per-request logger
 *   5. Deep nested object (3 levels)
 *   6. High-cardinality metadata (12 fields)
 *
 * Run: node benchmarks/run.mjs   (build first: npm run build)
 */

import { Writable } from 'node:stream';

import pino from 'pino';
import { Bench } from 'tinybench';
import winston from 'winston';

import { createLogger } from '../dist/index.js';

// bunyan is optional — don't fail the suite if it isn't installed.
let bunyan = null;
try {
  bunyan = (await import('bunyan')).default;
} catch {
  /* bunyan not installed — its rows are simply omitted */
}

// ── Null sink for pino / winston / bunyan ───────────────────────────────────
const devNull = new Writable({
  write(_chunk, _enc, cb) {
    cb();
  },
});

// Intercept stdout/stderr so logixia console output is swallowed during timing.
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
  format: winston.format.json(),
  transports: [new winston.transports.Stream({ stream: devNull })],
});
const bunyanLogger = bunyan
  ? bunyan.createLogger({ name: 'bench', streams: [{ level: 'info', stream: devNull }] })
  : null;

// logixia: default (text/console) + an explicit JSON-mode instance.
const logixia = createLogger({ appName: 'bench', environment: 'production' });
const logixiaJson = createLogger({
  appName: 'bench',
  environment: 'production',
  format: { json: true, timestamp: true, colorize: false },
});
const logixiaChild = logixia.child('request-42');

// ── Payloads ─────────────────────────────────────────────────────────────────
const META = { requestId: 'abc-123-xyz', userId: 42, action: 'login', ip: '127.0.0.1', latency: 14 };
const ERR = new Error('Connection timeout');
const DEEP = { req: { headers: { authorization: 'Bearer x' }, query: { q: 'shoes', page: 2 } }, user: { id: 7, roles: ['admin'] } };
const WIDE_META = {
  requestId: 'abc',
  userId: 42,
  action: 'checkout',
  ip: '10.0.0.1',
  latency: 22,
  method: 'POST',
  path: '/checkout',
  status: 200,
  region: 'us-east-1',
  build: 'v1.4.0',
  tenant: 't_88',
  cartId: 'c_991',
};

// ── Result formatting ──────────────────────────────────────────────────────────
function formatResults(bench) {
  const tasks = bench.tasks
    .filter((t) => t.result?.state === 'completed')
    .map((t) => ({
      name: t.name,
      opsPerSec: Math.round(t.result.throughput.mean),
      p99: (t.result.latency.p99 * 1000).toFixed(1),
    }))
    .sort((a, b) => b.opsPerSec - a.opsPerSec);

  const baseline = tasks.find((t) => t.name === 'pino') ?? tasks[0];
  return tasks.map((t) => {
    const diffPct = Math.round((t.opsPerSec / baseline.opsPerSec - 1) * 100);
    const vsPino =
      t.name === baseline.name ? '(baseline)' : `${diffPct >= 0 ? '+' : ''}${diffPct}% vs pino`;
    return {
      Library: t.name,
      'ops/sec': t.opsPerSec.toLocaleString(),
      'p99 (µs)': t.p99,
      'vs pino': vsPino,
    };
  });
}

// ── Suite builder ──────────────────────────────────────────────────────────────
function suite(name, fns) {
  const bench = new Bench({ name, time: 3000 });
  bench.add('pino', fns.pino);
  bench.add('winston', fns.winston);
  if (bunyanLogger && fns.bunyan) bench.add('bunyan', fns.bunyan);
  bench.add('logixia', fns.logixia);
  if (fns.logixiaJson) bench.add('logixia (json)', fns.logixiaJson);
  return bench;
}

const suites = [
  suite('Simple string log', {
    pino: () => pinoLogger.info('User logged in'),
    winston: () => winstonLogger.info('User logged in'),
    bunyan: () => bunyanLogger.info('User logged in'),
    logixia: async () => logixia.info('User logged in'),
    logixiaJson: async () => logixiaJson.info('User logged in'),
  }),
  suite('Structured log (5 fields)', {
    pino: () => pinoLogger.info(META, 'User logged in'),
    winston: () => winstonLogger.info('User logged in', META),
    bunyan: () => bunyanLogger.info(META, 'User logged in'),
    logixia: async () => logixia.info('User logged in', META),
    logixiaJson: async () => logixiaJson.info('User logged in', META),
  }),
  suite('Error object logging', {
    pino: () => pinoLogger.error({ err: ERR }, 'Request failed'),
    winston: () => winstonLogger.error('Request failed', { error: ERR.message }),
    bunyan: () => bunyanLogger.error({ err: ERR }, 'Request failed'),
    logixia: async () => logixia.error('Request failed', ERR),
  }),
  suite('Child / per-request logger', {
    pino: () => pinoLogger.child({ reqId: 'r-42' }).info(META, 'handled'),
    winston: () => winstonLogger.child({ reqId: 'r-42' }).info('handled', META),
    bunyan: () => bunyanLogger.child({ reqId: 'r-42' }).info(META, 'handled'),
    logixia: async () => logixiaChild.info('handled', META),
  }),
  suite('Deep nested object', {
    pino: () => pinoLogger.info(DEEP, 'request'),
    winston: () => winstonLogger.info('request', DEEP),
    bunyan: () => bunyanLogger.info(DEEP, 'request'),
    logixia: async () => logixia.info('request', DEEP),
  }),
  suite('High-cardinality metadata (12 fields)', {
    pino: () => pinoLogger.info(WIDE_META, 'event'),
    winston: () => winstonLogger.info('event', WIDE_META),
    bunyan: () => bunyanLogger.info(WIDE_META, 'event'),
    logixia: async () => logixia.info('event', WIDE_META),
  }),
];

// ── Runner ───────────────────────────────────────────────────────────────────
async function run() {
  _realOut('\nLogixia Benchmark Suite\n');
  _realOut('Node.js ' + process.version + ' | ' + process.platform + '-' + process.arch + '\n');
  _realOut('Comparing: pino, winston' + (bunyan ? ', bunyan' : '') + ', logixia\n');
  _realOut('='.repeat(60) + '\n');

  const allResults = {};
  silence();
  try {
    for (const bench of suites) {
      _realOut('\nRunning: "' + bench.name + '" ...');
      await bench.run();
      _realOut(' done\n');
      allResults[bench.name] = formatResults(bench);
    }
  } finally {
    restore();
  }

  console.log('\n' + '='.repeat(72));
  console.log('Results — higher ops/sec is better\n');
  for (const [name, rows] of Object.entries(allResults)) {
    console.log(name + ':');
    for (const row of rows) {
      console.log(
        '  ' +
          row.Library.padEnd(16) +
          row['ops/sec'].padStart(13) +
          ' ops/sec   p99: ' +
          row['p99 (µs)'].padStart(6) +
          'µs   ' +
          row['vs pino']
      );
    }
    console.log('');
  }

  // Head-to-head summary (logixia default vs pino).
  console.log('='.repeat(72));
  console.log('logixia vs pino — head-to-head:\n');
  for (const [suiteName, rows] of Object.entries(allResults)) {
    const l = rows.find((r) => r.Library === 'logixia');
    const p = rows.find((r) => r.Library === 'pino');
    if (!l || !p) continue;
    const lOps = Number.parseInt(l['ops/sec'].replace(/,/g, ''), 10);
    const pOps = Number.parseInt(p['ops/sec'].replace(/,/g, ''), 10);
    const pct = Math.round((lOps / pOps - 1) * 100);
    console.log(
      `  ${suiteName}: logixia ${pct >= 0 ? `${pct}% faster` : `${Math.abs(pct)}% slower`} than pino`
    );
  }
  console.log('');
}

run().catch((e) => {
  restore();
  console.error(e);
  process.exit(1);
});
