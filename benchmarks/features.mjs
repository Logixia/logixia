/**
 * Logixia feature benchmark suite.
 *
 * Measures the throughput of logixia's distinctive APIs (no cross-library
 * equivalent), so the README can quote real ops/sec for them:
 *   - wide events (canonical log line accumulation + emit)
 *   - safeStringify (BigInt + circular safe) vs JSON.stringify baseline
 *   - decycle/retrocycle round-trip
 *   - adaptive sampling decision (shouldEmit hot path)
 *   - per-namespace runtime level resolution on a child logger
 *
 * Run: node benchmarks/features.mjs   (build first: npm run build)
 */

import { Bench } from 'tinybench';

import {
  addEventFields,
  createLogger,
  retrocycle,
  safeStringify,
  withWideEvent,
} from '../dist/index.js';

// Swallow console output so transport writes don't pollute timing.
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

const logger = createLogger({ appName: 'bench', environment: 'production', silent: true });

// Sampling logger with adaptive config — exercise the shouldEmit hot path.
const sampledLogger = createLogger({
  appName: 'bench',
  environment: 'production',
  silent: true,
  sampling: { rate: 0.5, adaptive: { errorRateThreshold: 0.05, boostRate: 1.0 } },
});

// Child logger in a namespace with a runtime-resolved level.
logger.setNamespaceLevels({ 'db.*': 'debug', '*': 'info' });
const dbChild = logger.child('db.queries');

// Payloads.
const META = { requestId: 'abc-123', userId: 42, action: 'login', ip: '127.0.0.1', latency: 14 };
const circular = { id: 7n, name: 'node' };
circular.self = circular;
const wide = { method: 'GET', url: '/checkout', userId: 'u1', planTier: 'pro', dbQueries: 4 };

function rows(bench) {
  return bench.tasks
    .filter((t) => t.result?.state === 'completed')
    .map((t) => ({
      name: t.name,
      ops: Math.round(t.result.throughput.mean),
      p99: (t.result.latency.p99 * 1000).toFixed(1),
    }))
    .sort((a, b) => b.ops - a.ops);
}

const wideBench = new Bench({ name: 'Wide event (accumulate + emit)', time: 2500 });
wideBench
  .add('withWideEvent (5 fields)', async () => {
    await withWideEvent(logger, wide, () => {
      addEventFields({ cacheHit: true });
    });
  })
  .add('plain structured log', async () => {
    await logger.info('request', { ...wide, cacheHit: true });
  });

const serializeBench = new Bench({ name: 'Serialization', time: 2500 });
serializeBench
  .add('JSON.stringify (no cycles)', () => {
    JSON.stringify(META);
  })
  .add('safeStringify (no cycles)', () => {
    safeStringify(META);
  })
  .add('safeStringify (BigInt + circular)', () => {
    safeStringify(circular);
  })
  .add('decycle + retrocycle round-trip', () => {
    retrocycle(JSON.parse(safeStringify(circular, { decycle: true })));
  });

const samplingBench = new Bench({ name: 'Adaptive sampling decision', time: 2500 });
samplingBench
  .add('logixia.info (sampling on)', async () => {
    await sampledLogger.info('hot path', META);
  })
  .add('logixia.info (no sampling)', async () => {
    await logger.info('hot path', META);
  });

const nsBench = new Bench({ name: 'Namespace child logging', time: 2500 });
nsBench.add('child(db.queries).debug', async () => {
  await dbChild.debug('query', META);
});

async function run() {
  _realOut('\nLogixia Feature Benchmarks\n');
  _realOut('Node.js ' + process.version + ' | ' + process.platform + '-' + process.arch + '\n');
  _realOut('='.repeat(60) + '\n');

  const all = {};
  silence();
  try {
    for (const bench of [wideBench, serializeBench, samplingBench, nsBench]) {
      _realOut('\nRunning: "' + bench.name + '" ...');
      await bench.run();
      _realOut(' done\n');
      all[bench.name] = rows(bench);
    }
  } finally {
    restore();
  }

  console.log('\n' + '='.repeat(70));
  console.log('Feature results — higher ops/sec is better\n');
  for (const [name, list] of Object.entries(all)) {
    console.log(name + ':');
    for (const r of list) {
      console.log(
        '  ' + r.name.padEnd(34) + r.ops.toLocaleString().padStart(14) + ' ops/sec   p99: ' + r.p99 + 'µs'
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
