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

// Shared by every entry: keep .js/.mjs output names and never bundle optional deps.
const base = {
  outDir: 'dist',
  clean: false,
  fixedExtension: false,
  deps: { neverBundle: OPTIONAL_RUNTIME_DEPS },
} as const;

export default defineConfig([
  {
    ...base,
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
    format: ['cjs', 'esm'],
    dts: true,
    sourcemap: true,
    target: 'node16',
    platform: 'node',
    shims: true,
  },
  // Worker thread entry loaded by WorkerTransport (dist/worker-entry.js).
  {
    ...base,
    entry: { 'worker-entry': 'src/transports/worker-entry.ts' },
    format: ['cjs'],
    dts: false,
    target: 'node16',
    platform: 'node',
  },
  // Browser / edge entry: must stay free of Node built-ins.
  {
    ...base,
    entry: ['src/browser.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    sourcemap: true,
    platform: 'neutral',
  },
  // The `logixia` bin (package.json "bin" -> dist/cli/index.js).
  {
    ...base,
    entry: { 'cli/index': 'src/cli/index.ts' },
    format: ['cjs'],
    dts: false,
    target: 'node16',
    platform: 'node',
  },
]);
