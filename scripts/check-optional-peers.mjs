// Installs the packed tarball WITHOUT optional peer dependencies and checks that
// every non-nest entry loads via require() and import(); then installs the Nest
// peers and checks that `logixia/nest` loads too.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const run = (cmd, args, cwd, opts = {}) =>
  execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts });
const installFlags = ['install', '--ignore-scripts', '--no-audit', '--no-fund'];

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-peers-'));
const failures = [];
const fail = (msg) => {
  failures.push(msg);
  console.error(`FAIL ${msg}`);
};

const newProject = (name) => {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'package.json'), `{"name":"${name}","private":true}`);
  return dir;
};

const probe = (project, kind, specifier) => {
  const code =
    kind === 'require'
      ? `console.log('EXPORTS=' + Object.keys(require(${JSON.stringify(specifier)})).length)`
      : `import(${JSON.stringify(specifier)}).then(m => console.log('EXPORTS=' + Object.keys(m).length))`;
  // Read only our marker line, so an entry that prints on load can't turn the count into NaN.
  const out = run(process.execPath, ['-e', code], project);
  const match = /^EXPORTS=(\d+)$/m.exec(out);
  if (!match) throw new Error(`could not read export count from output: ${out.slice(0, 200)}`);
  return Number(match[1]);
};

const check = (project, specifier) => {
  for (const kind of ['require', 'import']) {
    try {
      const count = probe(project, kind, specifier);
      if (count === 0) fail(`${specifier} (${kind}): exports nothing`);
      else console.log(`ok   ${kind.padEnd(7)} ${specifier} (${count} exports)`);
    } catch (err) {
      const line = String(err.stderr || err.message)
        .split('\n')
        .find((l) => /Error/.test(l));
      fail(`${specifier} (${kind}): ${line ?? err.message}`);
    }
  }
};

try {
  const packOut = JSON.parse(
    run(npm, ['pack', '--json', '--ignore-scripts', '--pack-destination', tmp], root)
  );
  const tarball = path.join(tmp, packOut[0].filename);

  const bare = newProject('bare');
  run(npm, [...installFlags, '--omit=peer', '--legacy-peer-deps', tarball], bare);
  for (const peer of [
    '@nestjs/common',
    '@opentelemetry/api',
    'reflect-metadata',
    'express',
    'rxjs',
  ]) {
    if (fs.existsSync(path.join(bare, 'node_modules', peer)))
      fail(`bare install unexpectedly contains ${peer}`);
  }
  const specifiers = Object.keys(pkg.exports)
    .filter((k) => k !== './package.json' && k !== './nest')
    .map((k) => (k === '.' ? 'logixia' : `logixia/${k.slice(2)}`));
  for (const specifier of specifiers) check(bare, specifier);

  const withNest = newProject('with-nest');
  run(npm, [...installFlags, tarball, '@nestjs/common', 'reflect-metadata', 'rxjs'], withNest);
  check(withNest, 'logixia/nest');
  check(withNest, 'logixia');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.error(`\n${failures.length} problem(s) found`);
  process.exit(1);
}
console.log('\nOptional peers are not required by non-nest entries');
