// Loads the built `dist/hono.mjs` in a node:vm context shaped like a Cloudflare Worker with the
// `nodejs_compat` flag: web globals only (no process, Buffer or require), and nothing importable
// except `node:async_hooks` and `node:crypto`. Any other import or Node global fails the check.
//
// Run via `npm run check:browser` (needs --experimental-vm-modules, set in the script).
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const entry = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'hono.mjs');
if (!fs.existsSync(entry)) {
  console.error('dist/hono.mjs missing - run `npm run build` first');
  process.exit(1);
}

const assert = (cond, msg) => {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
};

const sandbox = vm.createContext({
  Response,
  Headers,
  URL,
  console,
  Date,
  Promise,
  setTimeout,
  queueMicrotask,
});
assert(
  vm.runInContext('typeof process + typeof Buffer + typeof require', sandbox) ===
    'undefinedundefinedundefined',
  'sandbox must not expose Node globals'
);

const provided = {
  'node:async_hooks': { AsyncLocalStorage },
  'node:crypto': { randomUUID },
};
const synthetic = new Map();
function builtin(specifier) {
  if (!Object.hasOwn(provided, specifier)) {
    throw new Error(
      `hono entry imports '${specifier}', which Workers nodejs_compat is not guaranteed to provide`
    );
  }
  if (!synthetic.has(specifier)) {
    const names = Object.keys(provided[specifier]);
    const mod = new vm.SyntheticModule(
      names,
      function () {
        for (const name of names) this.setExport(name, provided[specifier][name]);
      },
      { context: sandbox, identifier: specifier }
    );
    synthetic.set(specifier, mod);
  }
  return synthetic.get(specifier);
}

const source = new vm.SourceTextModule(fs.readFileSync(entry, 'utf8'), {
  context: sandbox,
  identifier: entry,
});
await source.link((specifier) => builtin(specifier));
await source.evaluate();
const { createHonoMiddleware } = source.namespace;
assert(typeof createHonoMiddleware === 'function', 'createHonoMiddleware is exported');

const calls = [];
const record = (level) => (message, data) => calls.push({ level, message, data });
const logger = { info: record('info'), warn: record('warn'), error: record('error') };

const responseHeaders = new Headers();
const context = {
  req: {
    method: 'GET',
    url: 'https://worker.example/items?token=SECRET&page=2',
    header: (name) => (name === 'x-request-id' ? 'edge-req-1' : undefined),
  },
  res: new Response('ok', { status: 200 }),
  header: (name, value) => responseHeaders.set(name, value),
  set() {},
};

await createHonoMiddleware(logger)(context, async () => {});

assert(responseHeaders.get('x-trace-id') === 'edge-req-1', 'trace id echoed on the response');
assert(calls.length === 1 && calls[0].level === 'info', 'one info entry');
const data = calls[0].data;
assert(data.traceId === 'edge-req-1', 'entry carries the trace id');
assert(data.status === 200 && data.method === 'GET', 'entry carries status and method');
assert(
  !String(data.path).includes('SECRET') && String(data.path).includes('page=2'),
  'query secret redacted'
);
console.log('ok   dist/hono.mjs runs in a Workers-like sandbox (async_hooks + crypto only)');
