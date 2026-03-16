// CJS chalk mock for Jest — returns strings unchanged (identity passthrough).
// All chained property accesses (.bold, .red, .bgWhite, etc.) return another
// proxy so tests can exercise chalk-using code without ESM import errors.
'use strict';

function makeProxy() {
  const fn = (...args) => args.join('');
  return new Proxy(fn, {
    get(_target, _prop) {
      return makeProxy();
    },
    apply(_target, _thisArg, args) {
      return args.join('');
    },
  });
}

const chalk = makeProxy();
module.exports = chalk;
module.exports.default = chalk;
