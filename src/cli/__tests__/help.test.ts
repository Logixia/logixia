import { program } from '../index';

describe('logixia --help', () => {
  it('ends with the sponsor links', () => {
    let out = '';
    program.configureOutput({ writeOut: (s) => (out += s) });
    program.outputHelp();
    expect(out).toContain('https://github.com/sponsors/webcoderspeed');
    expect(out).toContain('https://paypal.me/Sniperspeed');
  });
});
