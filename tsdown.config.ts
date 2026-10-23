import { defineConfig } from 'tsdown';

// Every optional runtime dependency logixia supports via `await import(...)`
// in its transports / adapters. These MUST NOT be bundled — consumers install
// the ones they actually use, and bundling them balloons the package from
// ~150 KB to ~8 MB and drags pg/mongodb/mysql2 platform code into the tree.
const OPTIONAL_RUNTIME_DEPS = [
  // DB drivers (database.transport.ts)
  'pg',
  'mongodb',
  'mysql2',
  'mysql2/promise',
  'sqlite',
  'sqlite3',
  // Alt loggers (adapter entry points)
  'pino',
  'pino-pretty',
  'winston',
  // NestJS ecosystem (nest.ts + kafka-trace.interceptor.ts)
  '@nestjs/common',
  '@nestjs/core',
  '@nestjs/microservices',
  '@nestjs/platform-express',
  '@nestjs/websockets',
  'rxjs',
  'rxjs/operators',
  'reflect-metadata',
  // HTTP frameworks
  'express',
  // Streaming / messaging
  'kafkajs',
  'socket.io',
];

export default defineConfig([
  {
    entry: [
      'src/index.ts',
      'src/nest.ts',
      'src/transports.ts',
      'src/search.ts',
      'src/testing.ts',
      'src/middleware.ts',
      'src/correlation.ts',
      'src/worker.ts',
      'src/cloudwatch.ts',
      'src/gcp.ts',
      'src/azure.ts',
    ],
    outDir: 'dist',
    format: ['cjs', 'esm'],
    dts: true,
    clean: false,
    sourcemap: true,
    target: 'node16',
    platform: 'node',
    shims: true,
    external: OPTIONAL_RUNTIME_DEPS,
  },
  // Worker thread entry loaded by WorkerTransport (dist/worker-entry.js).
  {
    entry: { 'worker-entry': 'src/transports/worker-entry.ts' },
    outDir: 'dist',
    format: ['cjs'],
    dts: false,
    clean: false,
    target: 'node16',
    platform: 'node',
    external: OPTIONAL_RUNTIME_DEPS,
  },
  // Browser / edge entry: must stay free of Node built-ins.
  {
    entry: ['src/browser.ts'],
    outDir: 'dist',
    format: ['cjs', 'esm'],
    dts: true,
    clean: false,
    sourcemap: true,
    platform: 'neutral',
    external: OPTIONAL_RUNTIME_DEPS,
  },
  // The `logixia` bin (package.json "bin" -> dist/cli/index.js).
  {
    entry: { 'cli/index': 'src/cli/index.ts' },
    outDir: 'dist',
    format: ['cjs'],
    dts: false,
    clean: false,
    target: 'node16',
    platform: 'node',
    external: OPTIONAL_RUNTIME_DEPS,
  },
]);
