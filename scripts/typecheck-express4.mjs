// Typechecks the express-facing sources against @types/express@4, because
// the repo devDependency is v5 while the peer range is ^4 || ^5.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = mkdtempSync(path.join(tmpdir(), 'logixia-express4-'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

try {
  writeFileSync(path.join(tmp, 'package.json'), '{"private":true}');
  execFileSync(
    npm,
    ['install', '--ignore-scripts', '--no-audit', '--no-fund', '@types/express@4'],
    {
      cwd: tmp,
      stdio: 'inherit',
    }
  );
  const config = path.join(tmp, 'tsconfig.json');
  writeFileSync(
    config,
    JSON.stringify({
      extends: path.join(root, 'tsconfig.json'),
      compilerOptions: {
        noEmit: true,
        incremental: false,
        rootDir: root,
        baseUrl: root,
        types: ['node'],
        typeRoots: [path.join(root, 'node_modules/@types')],
        paths: { express: [path.join(tmp, 'node_modules/@types/express')] },
      },
      include: [
        path.join(root, 'src/middleware/http-logger.ts'),
        path.join(root, 'src/metrics.ts'),
        path.join(root, 'src/core/logitron-logger.module.ts'),
        path.join(root, 'src/core/trace.middleware.ts'),
      ],
      exclude: [],
    })
  );
  execFileSync(
    process.execPath,
    [path.join(root, 'node_modules/typescript/bin/tsc'), '-p', config],
    {
      stdio: 'inherit',
    }
  );
  console.log('express@4 types: OK');
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
