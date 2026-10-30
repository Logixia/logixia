/* eslint-disable sonarjs/no-hardcoded-passwords -- fake credentials are the point of this suite */
/**
 * Secret handling beyond construction time: fields assigned later, relative and
 * odd URLs, password spellings, shared name lists, and centralized error scrubbing.
 */

import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as util from 'node:util';

import { BrowserRemoteTransport } from '../../browser';
import { LogixiaLoggerService } from '../../core/logitron-nestjs.service';
import type { TransportLogEntry } from '../../types/transport.types';
import { redactObject } from '../../utils/redact.utils';
import { DEFAULT_REDACT_QUERY_PARAMS, SENSITIVE_KEY_NAMES } from '../../utils/sensitive-names';
import { AnalyticsTransport } from '../analytics.transport';
import { AwsCredentialProvider } from '../aws-credentials';
import { BatchBuffer, httpRequest } from '../batch-buffer';
import { DatabaseTransport } from '../database.transport';
import {
  collectSecrets,
  protectSecrets,
  redactConfig,
  REDACTED,
  redactUrl,
  scrubSecrets,
  urlSecrets,
} from '../secret-config';

const logged: string[] = [];
const pgState: { insertError?: string } = {};

jest.mock(
  'pg',
  () => ({
    Client: class {
      password: string;
      constructor(config: { password: string }) {
        this.password = config.password;
      }
      connect(): Promise<void> {
        return Promise.resolve();
      }
      query(sql: string): Promise<unknown> {
        if (pgState.insertError && /INSERT/i.test(sql)) {
          return Promise.reject(new Error(pgState.insertError));
        }
        return Promise.resolve({ rows: [] });
      }
    },
  }),
  { virtual: true }
);

jest.mock('../../utils/internal-log', () => {
  const text = (msg: unknown, err?: unknown): string =>
    [msg, err instanceof Error ? `${err.message}\n${err.stack}` : err].join(' ');
  return {
    internalLog: (msg: string) => void logged.push(text(msg)),
    internalWarn: (msg: string, err?: unknown) => void logged.push(text(msg, err)),
    internalError: (msg: string, err?: unknown) => void logged.push(text(msg, err)),
  };
});

const entry: TransportLogEntry = {
  timestamp: new Date('2026-01-01T00:00:00.000Z'),
  level: 'error',
  message: 'boom',
};

function dumps(subject: unknown): string[] {
  const safe = (fn: () => string): string => {
    try {
      return fn();
    } catch {
      return '';
    }
  };
  return [
    safe(() => JSON.stringify(subject)),
    safe(() => util.inspect(subject, { depth: 10 })),
    safe(() => util.inspect(subject, { depth: 10, showHidden: true })),
    safe(() => JSON.stringify({ ...(subject as object) })),
    safe(() => JSON.stringify(Object.keys(subject as object))),
  ];
}

function expectNoLeak(subject: unknown, secrets: string[]): void {
  for (const text of dumps(subject)) {
    for (const secret of secrets) expect(text).not.toContain(secret);
  }
}

beforeEach(() => {
  logged.length = 0;
  delete pgState.insertError;
});

describe('fields assigned after construction stay hidden', () => {
  it('DatabaseTransport: the live driver client is hidden once connected', async () => {
    const t = new DatabaseTransport({
      type: 'postgresql',
      database: 'logs',
      password: 'LATE-DRIVER-PASSWORD',
      flushInterval: 60_000,
    });
    await t.write(entry);
    expect((t as unknown as { connection: unknown }).connection).toBeDefined();
    expect(Object.keys(t)).not.toContain('connection');
    expectNoLeak(t, ['LATE-DRIVER-PASSWORD']);
    await t.close().catch(() => {});
  });

  it('AwsCredentialProvider: credentials loaded later are hidden, including when explicit is absent', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-secret-'));
    const file = path.join(dir, 'credentials');
    fs.writeFileSync(
      file,
      '[default]\naws_access_key_id=AKIALATEKEYID\naws_secret_access_key=LATE-AWS-SECRET\naws_session_token=LATE-AWS-SESSION\n'
    );
    const saved = { ...process.env };
    for (const k of Object.keys(process.env)) if (k.startsWith('AWS_')) delete process.env[k];
    process.env['AWS_SHARED_CREDENTIALS_FILE'] = file;
    try {
      const provider = new AwsCredentialProvider({});
      expect(Object.keys(provider)).not.toEqual(expect.arrayContaining(['cached']));
      expect(Object.keys(provider)).not.toContain('explicit');
      const creds = await provider.get();
      expect(creds.secretAccessKey).toBe('LATE-AWS-SECRET');
      expect(Object.keys(provider)).not.toEqual(expect.arrayContaining(['cached']));
      expect(Object.keys(provider)).not.toContain('explicit');
      expectNoLeak(provider, ['LATE-AWS-SECRET', 'LATE-AWS-SESSION']);
      expect(provider.secretValues()).toContain('LATE-AWS-SECRET');
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('protectSecrets covers keys that do not exist yet, and rejects frozen targets', () => {
    class Lazy {
      refreshed?: string;
    }
    const lazy = new Lazy();
    protectSecrets(lazy, ['refreshed', 'neverAssigned']);
    lazy.refreshed = 'LAZY-REFRESH-VALUE';
    (lazy as unknown as Record<string, unknown>)['neverAssigned'] = 'LAZY-OTHER-VALUE';
    expect(Object.keys(lazy)).toEqual([]);
    expect(lazy.refreshed).toBe('LAZY-REFRESH-VALUE');
    expectNoLeak(lazy, ['LAZY-REFRESH-VALUE', 'LAZY-OTHER-VALUE']);
    expect(() => protectSecrets(Object.freeze({ a: 1 }), ['a'])).toThrow(TypeError);
  });
});

describe('NestJS service', () => {
  it('hides the merged config, including in child services', () => {
    const service = new LogixiaLoggerService({
      appName: 'svc',
      transports: { analytics: { datadog: { apiKey: 'NEST-DD-API-KEY' } } },
    });
    expectNoLeak(service, ['NEST-DD-API-KEY']);
    expectNoLeak(service.child('ctx'), ['NEST-DD-API-KEY']);
  });
});

describe('URL handling', () => {
  it('BrowserRemoteTransport hides relative URLs with query strings', () => {
    const t = new BrowserRemoteTransport({
      url: '/api/logs?token=REL-QUERY-TOKEN#frag-secret',
      flushIntervalMs: 0,
    });
    expectNoLeak(t, ['REL-QUERY-TOKEN', 'frag-secret']);
    expect(JSON.stringify(t)).toContain('/api/logs');
  });

  it('BrowserRemoteTransport never echoes an invalid URL', () => {
    const make = () =>
      new BrowserRemoteTransport({
        url: 'https://[bad?token=INVALID-URL-TOKEN',
        flushIntervalMs: 0,
      });
    expect(make).toThrow(TypeError);
    expect(make).not.toThrow(/INVALID-URL-TOKEN/);
  });

  it('redactUrl keeps a relative path and drops its query and fragment', () => {
    expect(redactUrl('/api/logs?token=X#y')).toBe('/api/logs');
    expect(redactUrl('https://user:pw@h.io:8443/p?q=1')).toBe('https://h.io:8443');
  });

  it('strips userinfo up to the last @, so passwords containing @ do not leave a tail', () => {
    const text = 'connect to postgres://user:p@ss@db.host/app failed';
    expect(scrubSecrets(text, [])).toBe(`connect to postgres://${REDACTED}@db.host/app failed`);
    const secrets = urlSecrets('postgres://user:p%40ss@db.host/app');
    expect(secrets).toContain('p%40ss');
    expect(secrets).toContain('p@ss');
    expect(scrubSecrets('bad password p@ss here', secrets)).not.toContain('p@ss');
    expect(scrubSecrets('bad password p%40ss here', secrets)).not.toContain('p%40ss');
  });

  it('only scrubs query values whose parameter name is sensitive, in decoded and encoded form', () => {
    const secrets = urlSecrets(
      'https://h.io/x?mode=admin&debug=true&api_key=ab%2Fcd%3D&token=plain-token'
    );
    expect(secrets).toEqual(expect.arrayContaining(['ab%2Fcd%3D', 'ab/cd=', 'plain-token']));
    expect(secrets).not.toContain('admin');
    expect(secrets).not.toContain('true');
    const scrubbed = scrubSecrets('mode=admin debug=true key=ab/cd= and ab%2Fcd%3D', secrets);
    expect(scrubbed).toContain('mode=admin debug=true');
    expect(scrubbed).not.toContain('ab/cd=');
    expect(scrubbed).not.toContain('ab%2Fcd%3D');
  });

  it('collectSecrets finds secret-keyed values, header values and URL secrets at depth', () => {
    const found = collectSecrets({
      db: { password: 'COLLECT-PW', host: 'h' },
      headers: { 'X-Team': 'COLLECT-HEADER' },
      endpoint: 'https://u:COLLECT-URL-PW@h.io/?secret=COLLECT-QUERY&mode=plain',
    });
    expect(found).toEqual(
      expect.arrayContaining(['COLLECT-PW', 'COLLECT-HEADER', 'COLLECT-URL-PW', 'COLLECT-QUERY'])
    );
    expect(found).not.toContain('plain');
    expect(found).not.toContain('h');
  });
});

describe('one list of sensitive names', () => {
  it('redactConfig and log redaction both honour every name in the shared list', () => {
    const data = Object.fromEntries(SENSITIVE_KEY_NAMES.map((name) => [name, `value-of-${name}`]));
    const viaTransport = JSON.stringify(redactConfig(data));
    const viaLogs = JSON.stringify(
      redactObject(data, { paths: SENSITIVE_KEY_NAMES.map((n) => `**.${n}`) })
    );
    for (const name of SENSITIVE_KEY_NAMES) {
      expect(viaTransport).not.toContain(`value-of-${name}`);
      expect(viaLogs).not.toContain(`value-of-${name}`);
    }
  });

  it('exposes the default query parameter names used by the HTTP logger', () => {
    expect(DEFAULT_REDACT_QUERY_PARAMS).toEqual(expect.arrayContaining(['token', 'api_key']));
  });

  it('treats unknown config keys as plain data', () => {
    const out = redactConfig({
      tokenExpiry: 3600,
      region: 'eu',
      writeKey: 'WK-VALUE',
      azureClientSecret: 's',
    });
    expect(out).toEqual({
      tokenExpiry: 3600,
      region: 'eu',
      writeKey: REDACTED,
      azureClientSecret: REDACTED,
    });
  });
});

describe('error scrubbing is central, not per catch', () => {
  class NewPathTransport extends AnalyticsTransport {
    constructor() {
      super('new-path', { apiKey: 'NEW-PATH-API-KEY', batchSize: 1 } as never);
    }
    protected initialize(): void {
      this.isReady = true;
    }
    protected async sendEntry(): Promise<void> {
      throw new Error('brand new path failed for key NEW-PATH-API-KEY');
    }
    protected async sendBatch(): Promise<void> {
      throw new Error('brand new batch failed for key NEW-PATH-API-KEY');
    }
    protected async cleanup(): Promise<void> {}
  }

  it('AnalyticsTransport scrubs errors from a subclass written after the fact (write and flush)', async () => {
    const t = new NewPathTransport();
    const writeError = (await t.write(entry).catch((e: Error) => e)) as Error;
    expect(writeError.message).not.toContain('NEW-PATH-API-KEY');
    expect(writeError.message).toContain('brand new path failed');

    const batched = new NewPathTransport();
    (batched as unknown as { config: { batchSize: number } }).config.batchSize = 5;
    batched.addToBatch(entry);
    await batched.flush();
    expect(logged.join('\n')).toContain('brand new batch failed');
    expect(logged.join('\n')).not.toContain('NEW-PATH-API-KEY');
  });

  it('BatchBuffer scrubs whatever its send callback throws', async () => {
    const buffer = new BatchBuffer<string>({
      name: 'NewTransport',
      batchSize: 1,
      send: async () => {
        throw new Error('exploded with NEW-BUFFER-TOKEN');
      },
      secrets: () => ['NEW-BUFFER-TOKEN'],
    });
    buffer.push('x');
    await buffer.flush();
    expect(logged.join('\n')).toContain('exploded with');
    expect(logged.join('\n')).not.toContain('NEW-BUFFER-TOKEN');
  });

  it('httpRequest scrubs errors that echo the request, and URL userinfo', async () => {
    const server = http.createServer((req, res) => {
      res.statusCode = 401;
      res.end(`denied ${req.headers['authorization']}`);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const error = (await httpRequest({
        url: new URL(`http://127.0.0.1:${port}/`),
        headers: { authorization: 'Bearer HTTP-ECHO-SECRET' },
        timeoutMs: 2000,
        label: 'Echo',
        secrets: () => ['HTTP-ECHO-SECRET'],
      }).catch((e: Error) => e)) as Error;
      expect(error.message).toContain('HTTP 401');
      expect(error.message).not.toContain('HTTP-ECHO-SECRET');
    } finally {
      server.close();
    }
  });

  it('DatabaseTransport scrubs flush errors', async () => {
    const connectionString = 'postgres://appuser:DB-FLUSH-PW@db.example.com/logs';
    pgState.insertError = `lost ${connectionString} for DB-FLUSH-PW`;
    const t = new DatabaseTransport({
      type: 'postgresql',
      connectionString,
      database: 'logs',
      password: 'DB-FLUSH-PW',
      flushInterval: 60_000,
    });
    await t.write(entry);
    const error = (await t.flush().catch((e: Error) => e)) as Error;
    expect(error).toBeInstanceOf(Error);
    expect(error.message).not.toContain('DB-FLUSH-PW');
    expect(logged.join('\n')).not.toContain('DB-FLUSH-PW');
    await t.close().catch(() => {});
  });
});
