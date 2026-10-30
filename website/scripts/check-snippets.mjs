// Typechecks every ```ts / ```typescript block in website/**/*.md against the library source,
// using the path mapping in the repo-root tsconfig.examples.json.
//
// Opt out of a partial snippet with an HTML comment just before the fence (blank lines allowed):
//   <!-- snippet-check: skip -->
// or with an info string flag: ```ts no-check
//
// Ambient `app`, `fastify` (any) and `logger` (a logixia logger) are declared when a snippet uses
// them without defining them, so short framework snippets stay readable.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteDir = fileURLToPath(new URL('..', import.meta.url));
const rootDir = join(websiteDir, '..');
const tmpDir = join(rootDir, '.snippet-check');
const SKIP_MARKER = /^\s*<!--\s*snippet-check:\s*skip\s*-->\s*$/;
const FENCE = /^(\s*)(`{3,}|~{3,})\s*(\S*)(.*)$/;

function* markdownFiles(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* markdownFiles(path);
    else if (entry.name.endsWith('.md')) yield path;
  }
}

function previousNonBlank(lines, index) {
  let i = index - 1;
  while (i >= 0 && lines[i].trim() === '') i--;
  return i >= 0 ? lines[i] : '';
}

function extractSnippets(file) {
  const lines = readFileSync(file, 'utf8').split('\n');
  const snippets = [];
  for (let i = 0; i < lines.length; i++) {
    const open = FENCE.exec(lines[i]);
    if (!open) continue;
    const [, , fence, lang, rest] = open;
    const body = [];
    let j = i + 1;
    while (j < lines.length && !lines[j].trimStart().startsWith(fence)) body.push(lines[j++]);
    const checked =
      ['ts', 'typescript'].includes(lang) &&
      !/\bno-check\b/.test(rest) &&
      !SKIP_MARKER.test(previousNonBlank(lines, i));
    if (checked) snippets.push({ file, line: i + 2, code: body.join('\n') });
    i = j;
  }
  return snippets;
}

const declares = (code, name) =>
  new RegExp(`\\b(?:const|let|var|function|class)\\s+${name}\\b`).test(code) ||
  new RegExp(`import[^;]*\\b${name}\\b[^;]*from`).test(code);
const uses = (code, name) => new RegExp(`\\b${name}\\b`).test(code);

function withAmbients(code) {
  const extra = [];
  if (uses(code, 'logger') && !declares(code, 'logger')) {
    extra.push(
      "import { createLogger as __createLogger } from 'logixia';",
      'declare const logger: ReturnType<typeof __createLogger>;'
    );
  }
  for (const name of ['app', 'fastify']) {
    if (uses(code, name) && !declares(code, name)) extra.push(`declare const ${name}: any;`);
  }
  // Appended after the snippet so reported line numbers match the markdown.
  return `${code}\n${extra.join('\n')}\nexport {};\n`;
}

const snippets = [...markdownFiles(websiteDir)].flatMap(extractSnippets);
if (snippets.length === 0) {
  console.log('No ts snippets found.');
  process.exit(0);
}

rmSync(tmpDir, { recursive: true, force: true });
mkdirSync(tmpDir);
try {
  const origins = new Map();
  snippets.forEach((snippet, index) => {
    const name = `s${String(index).padStart(4, '0')}.ts`;
    origins.set(name, snippet);
    writeFileSync(join(tmpDir, name), withAmbients(snippet.code));
  });
  writeFileSync(
    join(tmpDir, 'tsconfig.json'),
    JSON.stringify({
      extends: '../tsconfig.examples.json',
      compilerOptions: {
        module: 'ESNext',
        moduleResolution: 'Bundler',
        target: 'ES2022',
        lib: ['ES2022', 'DOM', 'DOM.Iterable'],
        skipLibCheck: true,
        types: ['node', 'jest'],
        rootDir: '..',
      },
      include: ['./*.ts'],
      exclude: [],
    })
  );

  const tsc = createRequire(join(rootDir, 'package.json')).resolve('typescript/bin/tsc');
  let output = '';
  try {
    execFileSync(
      process.execPath,
      [tsc, '-p', join(tmpDir, 'tsconfig.json'), '--pretty', 'false'],
      {
        cwd: rootDir,
        encoding: 'utf8',
        stdio: 'pipe',
      }
    );
  } catch (error) {
    output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
  }

  const failures = [];
  for (const line of output.split('\n')) {
    const match = /^\.snippet-check\/(s\d+\.ts)\((\d+),(\d+)\): (.*)$/.exec(line);
    if (!match) {
      if (line.trim()) failures.push(line);
      continue;
    }
    const origin = origins.get(match[1]);
    const where = origin
      ? `${relative(rootDir, origin.file)}:${origin.line + Number(match[2]) - 1}`
      : match[1];
    failures.push(`${where}:${match[3]} ${match[4]}`);
  }

  if (failures.length > 0) {
    console.error(failures.join('\n'));
    console.error(`\nSnippet check failed (${snippets.length} snippets checked).`);
    process.exitCode = 1;
  } else {
    console.log(`Snippet check passed (${snippets.length} snippets).`);
  }
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}
