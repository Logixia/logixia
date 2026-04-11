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

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/nest.ts',
    'src/transports.ts',
    'src/search.ts',
    'src/testing.ts',
    'src/middleware.ts',
  ],
  outDir: 'dist',
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'node16',
  platform: 'node',
  external: OPTIONAL_RUNTIME_DEPS,
});
