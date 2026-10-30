import { applyRedaction, redactObject } from '../redact.utils';

const CENSOR = '[REDACTED]';

describe('redactObject — array element paths', () => {
  it('matches users.*.password', () => {
    const out = redactObject(
      { users: [{ password: 'p', name: 'a' }] },
      { paths: ['users.*.password'] }
    );
    expect(out).toEqual({ users: [{ password: CENSOR, name: 'a' }] });
  });

  it('matches a numeric index segment', () => {
    const out = redactObject(
      { users: [{ password: 'a' }, { password: 'b' }] },
      { paths: ['users.1.password'] }
    );
    expect(out).toEqual({ users: [{ password: 'a' }, { password: CENSOR }] });
  });

  it('keeps the index-free users.password form working', () => {
    const out = redactObject({ users: [{ password: 'p' }] }, { paths: ['users.password'] });
    expect(out).toEqual({ users: [{ password: CENSOR }] });
  });

  it('keeps *.password and **.password working inside arrays', () => {
    const input = { users: [{ password: 'p' }] };
    expect(redactObject(input, { paths: ['*.password'] })).toEqual({
      users: [{ password: CENSOR }],
    });
    expect(redactObject(input, { paths: ['**.password'] })).toEqual({
      users: [{ password: CENSOR }],
    });
  });

  it('redacts whole elements by index or wildcard', () => {
    const out = redactObject({ keys: ['a', 'b'] }, { paths: ['keys.0'] });
    expect(out).toEqual({ keys: [CENSOR, 'b'] });
    expect(redactObject({ keys: ['a', 'b'] }, { paths: ['keys.*'] })).toEqual({
      keys: [CENSOR, CENSOR],
    });
  });

  it('does not match an unrelated index', () => {
    const out = redactObject({ users: [{ password: 'a' }] }, { paths: ['users.5.password'] });
    expect(out).toEqual({ users: [{ password: 'a' }] });
  });
});

describe('redactObject — nested arrays', () => {
  it('redacts paths inside arrays of arrays', () => {
    const out = redactObject({ g: [[{ password: 'p' }]] }, { paths: ['g.*.*.password'] });
    expect(out).toEqual({ g: [[{ password: CENSOR }]] });
  });

  it('redacts via **.password inside nested arrays', () => {
    const out = redactObject({ g: [[{ password: 'p' }]] }, { paths: ['**.password'] });
    expect(out).toEqual({ g: [[{ password: CENSOR }]] });
  });

  it('applies patterns to strings in nested arrays', () => {
    const out = redactObject(
      { g: [['sk-abcdefghijklmnopqrstuvwxyz123456']] },
      { patterns: [/sk-[a-z0-9]{32,}/gi] }
    );
    expect(out).toEqual({ g: [[CENSOR]] });
  });

  it('honours excludePaths for nested array strings', () => {
    const out = redactObject(
      { g: [['secret-x']], keep: [['secret-x']] },
      { patterns: [/secret-x/g], excludePaths: ['keep.*.*'] }
    );
    expect(out).toEqual({ g: [[CENSOR]], keep: [['secret-x']] });
  });
});

describe('redactObject — circular references', () => {
  it('replaces a self reference with [Circular]', () => {
    const a: Record<string, unknown> = { name: 'a', password: 'p' };
    a.self = a;
    const out = redactObject(a, { paths: ['password'] });
    expect(out).toEqual({ name: 'a', password: CENSOR, self: '[Circular]' });
  });

  it('handles cycles through arrays', () => {
    const a: Record<string, unknown> = { list: [] as unknown[] };
    (a.list as unknown[]).push(a);
    expect(redactObject(a, { paths: ['x'] })).toEqual({ list: ['[Circular]'] });
  });

  it('does not flag a shared, non-circular reference', () => {
    const shared = { password: 'p' };
    const out = redactObject({ a: shared, b: shared }, { paths: ['**.password'] });
    expect(out).toEqual({ a: { password: CENSOR }, b: { password: CENSOR } });
  });

  it('applyRedaction does not throw on a cyclic payload', () => {
    const a: Record<string, unknown> = { token: 't' };
    a.me = a;
    expect(() => applyRedaction(a, { paths: ['token'] })).not.toThrow();
  });
});

describe('redactObject — class instances and built-ins', () => {
  class Creds {
    constructor(
      public password: string,
      public user = 'u'
    ) {}
  }

  it('redacts fields of class instances by wildcard path', () => {
    const out = redactObject({ entity: new Creds('p') }, { paths: ['*.password'] });
    expect(out).toEqual({ entity: { password: CENSOR, user: 'u' } });
  });

  it('redacts fields of class instances by exact and deep path', () => {
    expect(redactObject({ entity: new Creds('p') }, { paths: ['entity.password'] })).toEqual({
      entity: { password: CENSOR, user: 'u' },
    });
    expect(redactObject({ list: [new Creds('p')] }, { paths: ['**.password'] })).toEqual({
      list: [{ password: CENSOR, user: 'u' }],
    });
  });

  it('does not mutate a class instance', () => {
    const c = new Creds('p');
    redactObject({ c }, { paths: ['**.password'] });
    expect(c.password).toBe('p');
  });

  it('leaves URL, Date, Buffer, Map, Set and friends untouched', () => {
    const values = {
      url: new URL('https://example.com/a'),
      params: new URLSearchParams('a=1'),
      date: new Date(0),
      re: /x/g,
      buf: Buffer.from('x'),
      ab: new ArrayBuffer(2),
      typed: new Uint8Array(2),
      view: new DataView(new ArrayBuffer(2)),
      map: new Map([['password', 1]]),
      set: new Set([1]),
    };
    const out = redactObject(values, { paths: ['nothing'], patterns: [/zzz/g] });
    for (const [k, v] of Object.entries(values)) expect(out[k]).toBe(v);
  });

  it('still redacts a built-in when a rule targets it', () => {
    const url = new URL('https://example.com/a');
    expect(redactObject({ url }, { paths: ['url'] })).toEqual({ url: CENSOR });
  });

  it('handles null-prototype objects', () => {
    const o = Object.assign(Object.create(null), { password: 'p' });
    expect(redactObject({ o }, { paths: ['o.password'] })).toEqual({ o: { password: CENSOR } });
  });
});

describe('redactObject — case-insensitive paths', () => {
  it('matches header keys regardless of case', () => {
    const out = redactObject(
      { req: { headers: { Authorization: 'Bearer x', Cookie: 'c' } } },
      { paths: ['req.headers.authorization', 'req.headers.COOKIE'] }
    );
    expect(out).toEqual({ req: { headers: { Authorization: CENSOR, Cookie: CENSOR } } });
  });

  it('matches wildcard rules case-insensitively', () => {
    expect(redactObject({ a: { PassWord: 'p' } }, { paths: ['**.password'] })).toEqual({
      a: { PassWord: CENSOR },
    });
  });
});

describe('redactObject — no mutation and sharing', () => {
  it('never mutates the input', () => {
    const input = { users: [{ password: 'p', tags: ['sk-abcdefghijklmnopqrstuvwxyz123456'] }] };
    const snapshot = JSON.parse(JSON.stringify(input));
    redactObject(input, { paths: ['users.*.password'], patterns: [/sk-[a-z0-9]{32,}/gi] });
    expect(input).toEqual(snapshot);
  });

  it('shares subtrees that need no redaction', () => {
    const untouched = { list: [{ a: 1 }] };
    const out = redactObject({ untouched, secret: 's' }, { paths: ['secret'] });
    expect(out.untouched).toBe(untouched);
  });

  it('returns a new top-level object even when nothing matched', () => {
    const input = { a: 1 };
    const out = redactObject(input, { paths: ['zzz'] });
    expect(out).toEqual(input);
    expect(out).not.toBe(input);
  });
});
