// Loads the built `dist/browser.mjs` (ESM, plus any relative chunks) and `dist/browser.js`
// (CJS) inside node:vm contexts that mimics a Cloudflare Worker: web globals only, and NO
// process, Buffer, require or module. Any ReferenceError means the browser/edge
// entry touches a Node global without a guard.
//
// Run via `npm run check:browser` (needs --experimental-vm-modules, set in the script).
import { webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const entryEsm = path.join(dist, 'browser.mjs');
const entryCjs = path.join(dist, 'browser.js');
if (!fs.existsSync(entryEsm) || !fs.existsSync(entryCjs)) {
  console.error('dist/browser.{mjs,js} missing - run `npm run build` first');
  process.exit(1);
}

const assert = (cond, msg) => {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
};

function createSandbox(extra = {}) {
  const state = { calls: [], failNext: true, keepaliveRejects: 0, errors: [], consoleCalls: [] };
  const fetchStub = async (url, init) => {
    state.calls.push({ url, init });
    if (init && 'keepalive' in init && state.keepaliveRejects > 0) {
      state.keepaliveRejects -= 1;
      throw new TypeError('keepalive is not supported');
    }
    if (state.failNext) {
      state.failNext = false;
      throw new TypeError('Failed to parse URL from /x?token=SECRET');
    }
    return new Response('{}', { status: 200 });
  };
  const record =
    (name) =>
    (...a) => {
      state.consoleCalls.push(name);
      if (name === 'error') state.errors.push(a.join(' '));
    };
  const console = Object.fromEntries(
    [
      'log',
      'info',
      'debug',
      'warn',
      'error',
      'groupCollapsed',
      'groupEnd',
      'dir',
      'table',
      'group',
    ].map((n) => [n, record(n)])
  );
  const context = vm.createContext({
    fetch: fetchStub,
    Request,
    Response,
    Headers,
    URL,
    URLSearchParams,
    TextEncoder,
    TextDecoder,
    crypto: webcrypto,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    queueMicrotask,
    ...extra,
  });
  return { context, state };
}

function assertNoNodeGlobals(context, allowed = []) {
  for (const name of ['process', 'Buffer', 'require', 'module', '__dirname', 'setImmediate']) {
    if (allowed.includes(name)) continue;
    if (vm.runInContext(`typeof ${name}`, context) !== 'undefined') {
      throw new Error(`sandbox leaks ${name}`);
    }
  }
}

async function exercise(api, state, label) {
  const logger = api.createBrowserLogger({ appName: 'edge', level: 'verbose', json: true });
  for (const level of ['verbose', 'debug', 'info', 'warn', 'error', 'critical']) {
    logger[level](`hello ${level}`, { level });
  }
  logger.child({ context: 'child', password: 'hunter2' }).info('from child');

  // Non-JSON (devtools) console transport formatting.
  const pretty = api.createBrowserLogger({ appName: 'edge', level: 'verbose', json: false });
  for (const level of ['debug', 'info', 'warn', 'error']) pretty[level]('pretty', { a: 1 });
  assert(
    state.consoleCalls.includes('groupCollapsed'),
    `${label}: pretty output used console groups`
  );

  const schema = api.defineLogSchema({ id: { type: 'string', required: true } });
  assert(schema.validate({}).length === 1, `${label}: validate reports a missing field`);
  const asyncLogger = Object.fromEntries(
    ['error', 'warn', 'info', 'debug', 'verbose'].map((l) => [l, async (m, d) => logger[l](m, d)])
  );
  state.consoleCalls.length = 0;
  await api.createTypedLogger(asyncLogger, schema).info('typed', {});
  assert(state.consoleCalls.includes('warn'), `${label}: schema warning surfaced via console.warn`);

  // OTel: no require available -> must resolve to "unavailable" without throwing.
  assert(api.getActiveOtelContext() === undefined, `${label}: OTel context is undefined`);
  api.getOtelMetaFields();

  const entry = {
    timestamp: new Date().toISOString(),
    level: 'info',
    appName: 'edge',
    message: 'm',
  };
  const transport = new api.BrowserRemoteTransport({
    url: 'https://logs.example/ingest?api_key=SECRET',
    batchSize: 1000,
    flushIntervalMs: 0,
  });
  transport.write(entry);
  await transport.flush();
  assert(transport.failedFlushes === 1, `${label}: failed flush is counted`);
  const report = state.errors.find((m) => m.includes('[logixia:error]'));
  assert(
    report && report.includes('TypeError') && report.includes('host logs.example'),
    `${label}: delivery failure surfaced`
  );
  assert(!report.includes('SECRET') && !report.includes('token'), `${label}: report leaks no URL`);
  await transport.flush();
  assert(state.calls.length === 2, `${label}: second flush delivered through stub fetch`);

  // keepalive retry branch: runtime rejects keepalive, transport retries without it.
  state.calls.length = 0;
  state.keepaliveRejects = 1;
  transport.write(entry);
  await transport.flush();
  assert(state.calls.length === 2, `${label}: keepalive rejection retried`);
  assert(!('keepalive' in state.calls[1].init), `${label}: retry omitted keepalive`);
  assert(transport.failedFlushes === 1, `${label}: keepalive retry is not counted as a failure`);
  transport.destroy();
}

async function checkEsm() {
  const { context, state } = createSandbox();
  assertNoNodeGlobals(context);
  const modules = new Map();
  const load = (file) => {
    const key = pathToFileURL(file).href;
    if (!modules.has(key)) {
      modules.set(
        key,
        new vm.SourceTextModule(fs.readFileSync(file, 'utf8'), { identifier: key, context })
      );
    }
    return modules.get(key);
  };
  const linker = (specifier, referencing) => {
    if (!specifier.startsWith('.')) {
      throw new Error(`browser entry imports non-relative module "${specifier}"`);
    }
    const from = fileURLToPath(referencing.identifier);
    return load(path.resolve(path.dirname(from), specifier));
  };
  const main = load(entryEsm);
  await main.link(linker);
  await main.evaluate();
  await exercise(main.namespace, state, 'esm');
}

async function checkCjs() {
  const requireCalls = [];
  const throwingRequire = (id) => {
    requireCalls.push(id);
    throw new Error(`unexpected require("${id}")`);
  };
  const { context, state } = createSandbox();
  assertNoNodeGlobals(context);
  const module = { exports: {} };
  const wrapper = new vm.Script(
    `(function (module, exports, require) {${fs.readFileSync(entryCjs, 'utf8')}\n})`,
    {
      filename: entryCjs,
    }
  ).runInContext(context);
  wrapper(module, module.exports, throwingRequire);
  await exercise(module.exports, state, 'cjs');
  assert(
    requireCalls.every((id) => id === '@opentelemetry/api'),
    `cjs: browser entry required unexpected modules: ${requireCalls.join(', ')}`
  );
}

// Node ESM must still resolve the optional OTel peer (via the createRequire shim).
function checkNodeEsmOtel() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-otel-'));
  try {
    // Reuse the repo's installed runtime deps; only the OTel peer is faked.
    const repoModules = path.join(dist, '..', 'node_modules');
    fs.mkdirSync(path.join(tmp, 'node_modules'));
    for (const name of fs.readdirSync(repoModules)) {
      if (name === 'logixia' || name === '@opentelemetry' || name.startsWith('.')) continue;
      fs.symlinkSync(path.join(repoModules, name), path.join(tmp, 'node_modules', name));
    }
    const pkgDir = path.join(tmp, 'node_modules', 'logixia');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.cpSync(dist, path.join(pkgDir, 'dist'), { recursive: true });
    fs.copyFileSync(path.join(dist, '..', 'package.json'), path.join(pkgDir, 'package.json'));
    const otel = path.join(tmp, 'node_modules', '@opentelemetry', 'api');
    fs.mkdirSync(otel, { recursive: true });
    fs.writeFileSync(
      path.join(otel, 'package.json'),
      '{"name":"@opentelemetry/api","version":"0.0.0","main":"index.js"}'
    );
    fs.writeFileSync(
      path.join(otel, 'index.js'),
      `exports.context = { active: () => ({}) };
exports.trace = {
  getSpanContext: () => ({ traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), traceFlags: 1 }),
  isSpanContextValid: () => true,
  TraceFlags: { SAMPLED: 1 },
};`
    );
    const probe = path.join(tmp, 'probe.mjs');
    fs.writeFileSync(
      probe,
      `import { getActiveOtelContext } from 'logixia';
const ctx = getActiveOtelContext();
if (!ctx || ctx.traceId !== 'a'.repeat(32)) { console.error('OTel not resolved in Node ESM', ctx); process.exit(1); }`
    );
    execFileSync(process.execPath, [probe], { cwd: tmp, stdio: 'inherit' });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function checkProductionLiteral() {
  for (const file of [entryEsm, entryCjs]) {
    const src = fs.readFileSync(file, 'utf8');
    assert(
      /try \{\s*return process\.env\.NODE_ENV === "production";/.test(src),
      `${path.basename(file)} keeps a literal, try-wrapped process.env.NODE_ENV`
    );
  }
}

try {
  checkProductionLiteral();
  checkNodeEsmOtel();
  await checkEsm();
  await checkCjs();
} catch (error) {
  console.error('FAIL logixia/browser is not edge-safe:', error);
  process.exit(1);
}
console.log('OK logixia/browser (ESM + CJS) ran in a Worker-like sandbox without Node globals');
