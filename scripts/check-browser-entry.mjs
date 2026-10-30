// Loads the built `dist/browser.mjs` (plus any relative chunks it imports) inside a
// node:vm context that mimics a Cloudflare Worker: web globals only, and NO
// process, Buffer, require or module. Any ReferenceError means the browser/edge
// entry touches a Node global without a guard.
//
// Run via `npm run check:browser` (needs --experimental-vm-modules, set in the script).
import { webcrypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const entry = path.join(dist, 'browser.mjs');
if (!fs.existsSync(entry)) {
  console.error('dist/browser.mjs missing - run `npm run build` first');
  process.exit(1);
}

const stubCalls = [];
let failNext = true;
const stubFetch = async (url, init) => {
  stubCalls.push({ url, init });
  if (failNext) {
    failNext = false;
    throw new TypeError('network down');
  }
  return new Response('{}', { status: 200 });
};

const consoleErrors = [];
const sandboxConsole = {
  log() {},
  info() {},
  debug() {},
  warn() {},
  error: (...a) => consoleErrors.push(a.join(' ')),
};

const context = vm.createContext({
  fetch: stubFetch,
  Request,
  Response,
  Headers,
  URL,
  URLSearchParams,
  TextEncoder,
  TextDecoder,
  crypto: webcrypto,
  console: sandboxConsole,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  queueMicrotask,
});
for (const name of ['process', 'Buffer', 'require', 'module', '__dirname', 'setImmediate']) {
  if (vm.runInContext(`typeof ${name}`, context) !== 'undefined') {
    throw new Error(`sandbox leaks ${name}`);
  }
}

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

const assert = (cond, msg) => {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
};

try {
  const main = load(entry);
  await main.link(linker);
  await main.evaluate();
  const api = main.namespace;

  const logger = api.createBrowserLogger({ appName: 'edge', level: 'verbose', json: true });
  for (const level of ['verbose', 'debug', 'info', 'warn', 'error', 'critical']) {
    logger[level](`hello ${level}`, { level });
  }
  logger.child({ context: 'child', password: 'hunter2' }).info('from child');

  const schema = api.defineLogSchema({ id: { type: 'string', required: true } });
  assert(schema.validate({}).length === 1, 'validate reports a missing field');
  const asyncLogger = Object.fromEntries(
    ['error', 'warn', 'info', 'debug', 'verbose'].map((l) => [l, async (m, d) => logger[l](m, d)])
  );
  await api.createTypedLogger(asyncLogger, schema).info('typed', {});
  assert(
    consoleErrors.some((m) => m.includes('[logixia:warn]') && m.includes('id')),
    'schema warning surfaced through console.error'
  );

  api.getActiveOtelContext();
  api.getOtelMetaFields();

  const transport = new api.BrowserRemoteTransport({
    url: 'https://logs.example/ingest',
    batchSize: 1000,
    flushIntervalMs: 0,
  });
  transport.write({
    timestamp: new Date().toISOString(),
    level: 'info',
    appName: 'edge',
    message: 'm',
  });
  await transport.flush();
  assert(transport.failedFlushes === 1, 'failed flush is counted');
  assert(
    consoleErrors.some((m) => m.includes('[logixia:error]') && m.includes('network down')),
    'delivery failure surfaced via console.error'
  );
  await transport.flush();
  assert(stubCalls.length === 2, 'second flush delivered through stub fetch');
  transport.destroy();
} catch (error) {
  console.error('FAIL logixia/browser is not edge-safe:', error);
  process.exit(1);
}
console.log('OK logixia/browser ran in a Worker-like sandbox without Node globals');
