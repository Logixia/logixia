/**
 * Soak test: logs many entries through logixia (default + JSON config, console
 * transport swallowed) in awaited batches and asserts the heap returns near
 * baseline after GC. Fails the process if retained growth exceeds the limit.
 *
 * Run: npm run build && node --expose-gc scripts/check-memory.mjs [entriesPerConfig]
 */
import { createLogger } from '../dist/index.js';

if (typeof globalThis.gc !== 'function') {
  console.error('Run with --expose-gc');
  process.exit(2);
}

const TOTAL = Number(process.argv[2] ?? 500_000);
const BATCH = 1000;
const PHASES = 5;
const MAX_GROWTH_MB = 15;

const realErr = process.stderr.write.bind(process.stderr);
const say = (s) => realErr(s + '\n');
const silence = () => {
  process.stdout.write = () => true;
  process.stderr.write = () => true;
};

const META = {
  requestId: 'abc-123-xyz',
  userId: 42,
  action: 'login',
  ip: '127.0.0.1',
  latency: 14,
};
const heapMb = () => {
  globalThis.gc();
  return process.memoryUsage().heapUsed / 1048576;
};

const configs = {
  default: { appName: 'soak', environment: 'production' },
  json: {
    appName: 'soak',
    environment: 'production',
    format: { json: true, timestamp: true, colorize: false },
  },
};

let failed = false;
const outStd = process.stdout.write;
const outErr = process.stderr.write;
for (const [name, cfg] of Object.entries(configs)) {
  const logger = createLogger(cfg);
  silence();
  const perPhase = Math.floor(TOTAL / PHASES);
  const samples = [];
  for (let phase = 0; phase < PHASES; phase++) {
    for (let done = 0; done < perPhase; done += BATCH) {
      const batch = [];
      for (let i = 0; i < BATCH; i++) batch.push(logger.info('User logged in', META));
      await Promise.all(batch);
    }
    await new Promise((r) => setTimeout(r, 5));
    samples.push(heapMb());
  }
  process.stdout.write = outStd;
  process.stderr.write = outErr;
  const growth = samples[samples.length - 1] - samples[0];
  say(
    `${name}: ${TOTAL} entries, heap per phase (MB): ${samples.map((s) => s.toFixed(1)).join(', ')}; growth ${growth.toFixed(1)}MB`
  );
  if (growth > MAX_GROWTH_MB) {
    say(`FAIL: ${name} heap grew ${growth.toFixed(1)}MB (> ${MAX_GROWTH_MB}MB)`);
    failed = true;
  }
}
process.exit(failed ? 1 : 0);
