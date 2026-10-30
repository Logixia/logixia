/**
 * ts-node resolver hook for running the examples straight from source:
 *  - maps the published entry points ('logixia', 'logixia/browser', ...) to src/
 *  - strips '.js' extensions from relative imports so they resolve to .ts files
 */
const Module = require('module');
const path = require('path');

const srcDir = path.resolve(__dirname, '..', 'src');
const originalResolve = Module._resolveFilename.bind(Module);

Module._resolveFilename = function (request, parent, isMain, options) {
  if (request === 'logixia') {
    return originalResolve(path.join(srcDir, 'index.ts'), parent, isMain, options);
  }
  if (request.startsWith('logixia/')) {
    const entry = request.slice('logixia/'.length) + '.ts';
    return originalResolve(path.join(srcDir, entry), parent, isMain, options);
  }
  if (request.endsWith('.js') && !request.includes('node_modules')) {
    try {
      return originalResolve(request.slice(0, -3), parent, isMain, options);
    } catch {
      // fall through to the original resolver
    }
  }
  return originalResolve(request, parent, isMain, options);
};
