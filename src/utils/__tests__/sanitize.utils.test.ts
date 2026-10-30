import { stripControlChars } from '../sanitize.utils';

describe('stripControlChars', () => {
  it('escapes line breaks and removes ESC and DEL', () => {
    expect(stripControlChars('a\nb\rc\x1b[2Jd\x7fe')).toBe('a\\nb\\rc[2Jde');
  });

  it('removes C1 control characters', () => {
    expect(stripControlChars('x\u0085y\u009bz')).toBe('xyz');
  });

  it('keeps tabs and printable text', () => {
    expect(stripControlChars('a\tb ünï')).toBe('a\tb ünï');
  });
});
