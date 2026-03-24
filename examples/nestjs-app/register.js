/**
 * Custom module resolver for ts-node: strips the .js extension so that
 * TypeScript source files with `import ... from './foo.js'` resolve
 * correctly in CommonJS mode during development.
 */
const Module = require('module');
const originalResolve = Module._resolveFilename.bind(Module);

Module._resolveFilename = function (request, parent, isMain, options) {
  // Strip .js extension and let Node resolve the .ts file via ts-node
  if (request.endsWith('.js') && !request.includes('node_modules')) {
    const stripped = request.slice(0, -3);
    try {
      return originalResolve(stripped, parent, isMain, options);
    } catch {
      // fall through to original
    }
  }
  return originalResolve(request, parent, isMain, options);
};
