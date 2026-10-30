/* eslint-disable sonarjs/no-hardcoded-passwords -- fake credentials are the point of this suite */
/**
 * Credentials must not show up in JSON.stringify / util.inspect / spreads of a
 * transport (or the logger and manager that hold them), in health-check output,
 * or in the errors and internal logs raised when a request fails.
 */

import { generateKeyPairSync } from 'node:crypto';
import * as util from 'node:util';

import { BrowserRemoteTransport } from '../../browser';
import { LogixiaLogger } from '../../core/logitron-logger';
import type { TransportLogEntry } from '../../types/transport.types';
import { AzureMonitorTransport } from '../azure-monitor.transport';
import { HttpError } from '../batch-buffer';
import { CloudWatchTransport } from '../cloudwatch.transport';
import { DatabaseTransport } from '../database.transport';
import { DataDogTransport } from '../datadog.transport';
import { DiscordTransport } from '../discord.transport';
import { GCPTransport } from '../gcp.transport';
import { GoogleAnalyticsTransport } from '../google-analytics.transport';
import { MixpanelTransport } from '../mixpanel.transport';
import { OtlpLogTransport } from '../otlp.transport';
import {
  protectSecrets,
  redactConfig,
  REDACTED,
  redactUrl,
  scrubError,
  scrubSecrets,
} from '../secret-config';
import { SegmentTransport } from '../segment.transport';
import { SlackTransport } from '../slack.transport';
import { TransportManager } from '../transport.manager';
import { WorkerTransport } from '../worker.transport';

const logged: string[] = [];

jest.mock('../../utils/internal-log', () => {
  const text = (msg: unknown, err?: unknown): string =>
    [msg, err instanceof Error ? `${err.message}\n${err.stack}` : err].join(' ');
  return {
    internalLog: (msg: string) => void logged.push(text(msg)),
    internalWarn: (msg: string, err?: unknown) => void logged.push(text(msg, err)),
    internalError: (msg: string, err?: unknown) => void logged.push(text(msg, err)),
  };
});

// Every outbound request fails with a body that echoes what was sent, like a hostile proxy would.
const requests: { url: string; headers: unknown; body: unknown }[] = [];
jest.mock('../batch-buffer', () => {
  const actual = jest.requireActual('../batch-buffer');
  return {
    ...actual,
    httpRequest: jest.fn((opts: { url: URL; headers?: unknown; body?: string; label: string }) => {
      requests.push({ url: opts.url.href, headers: opts.headers, body: opts.body });
      if (opts.url.hostname === 'oauth2.googleapis.com') {
        return Promise.resolve({
          status: 200,
          body: JSON.stringify({ access_token: 'ya29.GCP-ACCESS-TOKEN' }),
        });
      }
      if (opts.url.hostname === 'login.microsoftonline.com') {
        return Promise.resolve({
          status: 200,
          body: JSON.stringify({ access_token: 'AZURE-ACCESS-TOKEN', expires_in: 3600 }),
        });
      }
      return Promise.reject(
        new actual.HttpError(
          400,
          JSON.stringify({ echoedHeaders: opts.headers, echoedBody: opts.body }),
          opts.label
        )
      );
    }),
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
    safe(() => util.format('%s %j %o', subject, subject, subject)),
  ];
}

function expectNoLeak(subject: unknown, secrets: string[]): void {
  for (const text of dumps(subject)) {
    for (const secret of secrets) expect(text).not.toContain(secret);
  }
}

function expectNoSecretIn(texts: string[], secrets: string[]): void {
  for (const text of texts) {
    for (const secret of secrets) expect(text).not.toContain(secret);
  }
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 20));
}

beforeEach(() => {
  logged.length = 0;
  requests.length = 0;
});

describe('analytics transports', () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn(async (url: string, init: { body?: string; headers?: unknown }) => ({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      text: async () => `echo ${url} ${JSON.stringify(init.headers)} ${init.body}`,
    }));
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  it('DataDog hides the api key and scrubs request errors', async () => {
    const t = new DataDogTransport({ apiKey: 'DD-API-KEY-VALUE-123', batchSize: 1 });
    expectNoLeak(t, ['DD-API-KEY-VALUE-123']);
    expect(JSON.stringify(t)).toContain('datadogConfig');
    expect(JSON.stringify(t)).toContain(REDACTED);
    await expect(t.write(entry)).rejects.toThrow();
    const error = await t.write(entry).catch((e: Error) => e);
    expectNoSecretIn(
      [String((error as Error).message), String((error as Error).stack)],
      ['DD-API-KEY-VALUE-123']
    );
    expect(t['datadogConfig'].apiKey).toBe('DD-API-KEY-VALUE-123');
  });

  it('Mixpanel hides the token and scrubs request errors', async () => {
    fetchMock.mockImplementation(async () => {
      throw new Error('socket hang up for token MIXPANEL-TOKEN-XYZ');
    });
    const t = new MixpanelTransport({ token: 'MIXPANEL-TOKEN-XYZ', batchSize: 1 });
    expectNoLeak(t, ['MIXPANEL-TOKEN-XYZ']);
    const error = (await t.write(entry).catch((e: Error) => e)) as Error;
    expect(error).toBeInstanceOf(Error);
    expectNoSecretIn([error.message, String(error.stack)], ['MIXPANEL-TOKEN-XYZ']);
    expect(String((error.cause as Error).message)).not.toContain('MIXPANEL-TOKEN-XYZ');
  });

  it('Segment hides the write key (and its basic-auth form) and scrubs errors', async () => {
    const auth = Buffer.from('SEGMENT-WRITE-KEY:').toString('base64');
    fetchMock.mockImplementation(
      async (_url: string, init: { headers: Record<string, string> }) => {
        throw new Error(`failed with ${JSON.stringify(init.headers)}`);
      }
    );
    const t = new SegmentTransport({
      writeKey: 'SEGMENT-WRITE-KEY',
      batchSize: 1,
      enableBatching: false,
    });
    expectNoLeak(t, ['SEGMENT-WRITE-KEY', auth]);
    const error = (await t.write(entry).catch((e: Error) => e)) as Error;
    expect(error).toBeInstanceOf(Error);
    expectNoSecretIn([error.message, String(error.stack)], ['SEGMENT-WRITE-KEY', auth]);
  });

  it('Google Analytics hides the api secret and scrubs the error text', async () => {
    const t = new GoogleAnalyticsTransport({
      measurementId: 'G-ABC123',
      apiSecret: 'GA-API-SECRET-VALUE',
      batchSize: 1,
    });
    expectNoLeak(t, ['GA-API-SECRET-VALUE']);
    const error = (await t.write(entry).catch((e: Error) => e)) as Error;
    expect(error).toBeInstanceOf(Error);
    expectNoSecretIn([error.message, String(error.stack)], ['GA-API-SECRET-VALUE']);
  });
});

describe('cloud transports', () => {
  it('CloudWatch hides AWS credentials and scrubs failed-request errors', async () => {
    const t = new CloudWatchTransport({
      logGroupName: 'g',
      accessKeyId: 'AKIAFAKEACCESSKEYID',
      secretAccessKey: 'AWS-SECRET-ACCESS-KEY-VALUE',
      sessionToken: 'AWS-SESSION-TOKEN-VALUE',
      flushIntervalMs: 60_000,
    });
    expectNoLeak(t, ['AWS-SECRET-ACCESS-KEY-VALUE', 'AWS-SESSION-TOKEN-VALUE']);
    t.write(entry);
    await t.flush();
    await settle();
    expect(requests.length).toBeGreaterThan(0);
    expect(logged.join('\n')).toContain('HTTP 400');
    expectNoSecretIn(logged, ['AWS-SECRET-ACCESS-KEY-VALUE', 'AWS-SESSION-TOKEN-VALUE']);
    await t.close();
  });

  it('GCP hides the private key and access token and scrubs errors', async () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const body = privateKey.split('\n')[1] as string;
    const t = new GCPTransport({
      projectId: 'p',
      credentials: { client_email: 'svc@p.iam.gserviceaccount.com', private_key: privateKey },
      flushIntervalMs: 60_000,
    });
    expectNoLeak(t, [body]);
    t.write(entry);
    await t.flush();
    await settle();
    expect(logged.join('\n')).toContain('HTTP 400');
    expectNoLeak(t, [body, 'ya29.GCP-ACCESS-TOKEN']);
    expectNoSecretIn(logged, [body, 'ya29.GCP-ACCESS-TOKEN']);
    await t.close();
  }, 20_000);

  it('Azure Monitor hides the client secret and access token and scrubs errors', async () => {
    const t = new AzureMonitorTransport({
      endpoint: 'https://dce.example.com',
      ruleId: 'dcr-1',
      streamName: 'Custom-Logs',
      tenantId: 'contoso.onmicrosoft.com',
      clientId: 'client-id',
      clientSecret: 'AZURE-CLIENT-SECRET-VALUE',
      flushIntervalMs: 60_000,
    });
    expectNoLeak(t, ['AZURE-CLIENT-SECRET-VALUE']);
    t.write(entry);
    await t.flush();
    await settle();
    expect(logged.join('\n')).toContain('HTTP 400');
    expectNoLeak(t, ['AZURE-CLIENT-SECRET-VALUE', 'AZURE-ACCESS-TOKEN']);
    expectNoSecretIn(logged, ['AZURE-CLIENT-SECRET-VALUE', 'AZURE-ACCESS-TOKEN']);
    await t.close();
  });

  it('OTLP hides headers and URL credentials and scrubs fetch errors', async () => {
    const url =
      'https://otel-user:OTLP-URL-PASSWORD@collector.example.com/v1/logs?key=OTLP-QUERY-KEY';
    global.fetch = jest.fn(async () => {
      throw new TypeError(
        `Request cannot be constructed from a URL that includes credentials: ${url}`
      );
    }) as unknown as typeof fetch;
    const t = new OtlpLogTransport({
      url,
      headers: {
        Authorization: 'Bearer OTLP-BEARER-VALUE',
        'x-honeycomb-team': 'HONEYCOMB-TEAM-KEY',
      },
      flushIntervalMs: 60_000,
    });
    const secrets = [
      'OTLP-URL-PASSWORD',
      'OTLP-QUERY-KEY',
      'OTLP-BEARER-VALUE',
      'HONEYCOMB-TEAM-KEY',
    ];
    expectNoLeak(t, secrets);
    expect(JSON.stringify(t)).toContain('collector.example.com');
    t.write(entry);
    await t.flush();
    await settle();
    expect(logged.join('\n')).toContain('flush error');
    expectNoSecretIn(logged, secrets);
    await t.close();
  });
});

describe('DatabaseTransport', () => {
  it('hides the password and connection string and scrubs connection errors', async () => {
    const connectionString = 'postgres://appuser:DB-PASSWORD-VALUE@db.example.com:5432/logs';
    jest.doMock(
      'pg',
      () => ({
        Client: class {
          connect(): Promise<void> {
            return Promise.reject(new Error(`could not connect using ${connectionString}`));
          }
        },
      }),
      { virtual: true }
    );
    const t = new DatabaseTransport({
      type: 'postgresql',
      connectionString,
      database: 'logs',
      username: 'appuser',
      password: 'DB-PASSWORD-VALUE',
      flushInterval: 60_000,
    });
    const secrets = ['DB-PASSWORD-VALUE', connectionString];
    expectNoLeak(t, secrets);
    const error = (await t.write(entry).catch((e: Error) => e)) as Error;
    expect(error).toBeInstanceOf(Error);
    expectNoSecretIn(
      [error.message, String(error.stack), String((error.cause as Error).message)],
      secrets
    );
    expectNoLeak(t, secrets);
    await t.close().catch(() => {});
    jest.dontMock('pg');
  });

  it('hides a mongodb connection string', () => {
    const t = new DatabaseTransport({
      type: 'mongodb',
      connectionString: 'mongodb://root:MONGO-PASSWORD@mongo.example.com/logs',
      database: 'logs',
      flushInterval: 60_000,
    });
    expectNoLeak(t, ['MONGO-PASSWORD']);
    void t.close();
  });
});

describe('webhook transports', () => {
  it('Slack and Discord keep the webhook URL out of every dump', () => {
    const slack = new SlackTransport({
      webhookUrl: 'https://hooks.slack.com/services/T000/B000/SLACK-WEBHOOK-SECRET',
    });
    const discord = new DiscordTransport({
      webhookUrl: 'https://discord.com/api/webhooks/123456/DISCORD-WEBHOOK-TOKEN',
    });
    expectNoLeak(slack, ['SLACK-WEBHOOK-SECRET']);
    expectNoLeak(discord, ['DISCORD-WEBHOOK-TOKEN']);
  });
});

describe('WorkerTransport', () => {
  it('hides the config forwarded to the worker', async () => {
    const t = new WorkerTransport({
      transportType: 'datadog',
      transportConfig: { apiKey: 'WORKER-DD-API-KEY', password: 'WORKER-PASSWORD' },
    });
    expectNoLeak(t, ['WORKER-DD-API-KEY', 'WORKER-PASSWORD']);
    await t.close();
  });
});

describe('BrowserRemoteTransport', () => {
  it('hides headers and URL query tokens', () => {
    const t = new BrowserRemoteTransport({
      url: 'https://logs.example.com/ingest?token=BROWSER-URL-TOKEN',
      headers: { Authorization: 'Bearer BROWSER-BEARER-VALUE' },
      flushIntervalMs: 0,
    });
    expectNoLeak(t, ['BROWSER-URL-TOKEN', 'BROWSER-BEARER-VALUE']);
  });

  it('does not echo credentials from an invalid URL', () => {
    const make = () =>
      new BrowserRemoteTransport({ url: 'https://user:BROWSER-PW@[bad', flushIntervalMs: 0 });
    expect(make).toThrow(TypeError);
    expect(make).not.toThrow(/BROWSER-PW/);
  });
});

describe('TransportManager and logger', () => {
  it('the manager, its transports and healthCheck() output carry no secrets', async () => {
    const manager = new TransportManager({
      analytics: {
        datadog: { apiKey: 'MGR-DD-KEY' },
        mixpanel: { token: 'MGR-MIXPANEL-TOKEN' },
        segment: { writeKey: 'MGR-SEGMENT-KEY' },
        googleAnalytics: { measurementId: 'G-1', apiSecret: 'MGR-GA-SECRET' },
      },
      database: {
        type: 'postgresql',
        database: 'x',
        password: 'MGR-DB-PASSWORD',
        flushInterval: 60_000,
      },
    });
    const secrets = [
      'MGR-DD-KEY',
      'MGR-MIXPANEL-TOKEN',
      'MGR-SEGMENT-KEY',
      'MGR-GA-SECRET',
      'MGR-DB-PASSWORD',
    ];
    expectNoLeak(manager, secrets);
    expectNoLeak(
      manager.getTransports().map((id) => manager.getTransport(id)),
      secrets
    );
    expectNoLeak(await manager.healthCheck(), secrets);
    expectNoLeak(manager.getMetrics(), secrets);
    await manager.close?.();
  });

  it('the logger does not serialize its transport config', () => {
    const logger = new LogixiaLogger({
      appName: 'app',
      transports: { analytics: { datadog: { apiKey: 'LOGGER-DD-KEY' } } },
    });
    expectNoLeak(logger, ['LOGGER-DD-KEY']);
    expectNoLeak({ transports: logger.getAvailableTransports() }, ['LOGGER-DD-KEY']);
  });
});

describe('secret-config helpers', () => {
  it('protectSecrets keeps fields readable and writable but not enumerable', () => {
    const target = {
      name: 't',
      token: 'abcd1234',
      inner: { password: 'pw-value' },
      url: 'https://u:p@h.io/x?k=v',
    };
    protectSecrets(target, ['inner', 'token']);
    expect(target.inner.password).toBe('pw-value');
    target.token = 'changed-token';
    expect(Object.keys(target)).toEqual(['name', 'url']);
    expect(JSON.parse(JSON.stringify(target))).toEqual({
      class: 'Object',
      name: 't',
      token: REDACTED,
      url: 'https://h.io',
      inner: { password: REDACTED },
    });
    expect(util.inspect(target)).not.toContain('changed-token');
  });

  it('redactConfig masks secret keys, header values and URL credentials at any depth', () => {
    const out = JSON.stringify(
      redactConfig({
        a: {
          b: { clientSecret: 's1', headers: { 'X-Custom': 'v1' }, endpoint: 'https://u:p@h.io/p' },
        },
        list: [{ api_key: 'k1' }],
        note: 'plain',
      })
    );
    for (const leaked of ['s1', 'v1', 'u:p', 'k1']) expect(out).not.toContain(leaked);
    expect(out).toContain('plain');
    expect(out).toContain('https://h.io');
  });

  it('scrubSecrets and scrubError remove listed values and URL credentials', () => {
    expect(scrubSecrets('x postgres://u:pw@h/db y SECRET-VALUE', ['SECRET-VALUE'])).toBe(
      `x postgres://${REDACTED}@h/db y ${REDACTED}`
    );
    const err = new Error('has SECRET-VALUE', { cause: new Error('cause SECRET-VALUE') });
    scrubError(err, ['SECRET-VALUE']);
    expect(err.message).not.toContain('SECRET-VALUE');
    expect(String((err.cause as Error).message)).not.toContain('SECRET-VALUE');
    expect(redactUrl('not a url')).toBe(REDACTED);
  });

  it('keeps HttpError bodies readable when nothing secret is in them', () => {
    expect(new HttpError(500, 'oops', 'X').message).toContain('oops');
  });
});
