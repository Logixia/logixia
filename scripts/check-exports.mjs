// Packs the package, installs the tarball into a clean folder and loads every
// `exports` entry through both require() and import().
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const run = (cmd, args, cwd, opts = {}) =>
  execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...opts });

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-exports-'));
const failures = [];
const fail = (msg) => {
  failures.push(msg);
  console.error(`FAIL ${msg}`);
};

try {
  const packOut = JSON.parse(
    run(npm, ['pack', '--json', '--ignore-scripts', '--pack-destination', tmp], root)
  );
  const tarball = path.join(tmp, packOut[0].filename);
  const project = path.join(tmp, 'project');
  fs.mkdirSync(project);
  fs.writeFileSync(path.join(project, 'package.json'), '{"name":"check","private":true}');
  // The main entry still requires @nestjs/common; installing it keeps that
  // separate problem from hiding a missing subpath.
  run(
    npm,
    [
      'install',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      tarball,
      '@nestjs/common',
      'reflect-metadata',
      'rxjs',
    ],
    project
  );

  const installed = path.join(project, 'node_modules', 'logixia');
  const expectedNames = { './search': 'SearchManager', './worker': 'WorkerTransport' };
  const probe = (kind, specifier) => {
    const code =
      kind === 'require'
        ? `console.log(JSON.stringify(Object.keys(require(${JSON.stringify(specifier)}))))`
        : `import(${JSON.stringify(specifier)}).then(m => console.log(JSON.stringify(Object.keys(m))))`;
    return JSON.parse(
      run(process.execPath, ['-e', code], project, { stdio: ['ignore', 'pipe', 'pipe'] })
    );
  };

  for (const [key, target] of Object.entries(pkg.exports)) {
    if (key === './package.json') continue;
    const specifier = key === '.' ? 'logixia' : `logixia/${key.slice(2)}`;
    const files = [
      target.import?.types,
      target.import?.default,
      target.require?.types,
      target.require?.default,
    ];
    for (const file of files) {
      if (!file || !fs.existsSync(path.join(installed, file)))
        fail(`${specifier}: missing file ${file}`);
    }
    for (const kind of ['require', 'import']) {
      try {
        const names = probe(kind, specifier);
        const expected = expectedNames[key];
        if (names.length === 0) fail(`${specifier} (${kind}): exports nothing`);
        else if (expected && !names.includes(expected))
          fail(`${specifier} (${kind}): ${expected} not exported`);
        else console.log(`ok   ${kind.padEnd(7)} ${specifier} (${names.length} exports)`);
      } catch (err) {
        fail(
          `${specifier} (${kind}): ${
            String(err.stderr || err.message)
              .split('\n')
              .find((l) => /Error/.test(l)) ?? err.message
          }`
        );
      }
    }
  }

  const bin = path.join(installed, pkg.bin.logixia);
  try {
    const help = run(process.execPath, [bin, '--help'], project);
    if (!/Usage: logixia/.test(help)) fail('cli --help did not print usage');
    else console.log('ok   cli --help');
  } catch (err) {
    fail(`cli --help: ${err.message}`);
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.error(`\n${failures.length} problem(s) found`);
  process.exit(1);
}
console.log('\nAll exports resolve');
