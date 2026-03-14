import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', 'src/nest.ts', 'src/transports.ts', 'src/search.ts'],
  outDir: 'dist',
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'node16',
  external: [
    'pino',
    'winston',
    'pino-pretty',
    '@nestjs/common',
    'express',
    'async_hooks',
    'crypto',
    'util',
  ],
});
