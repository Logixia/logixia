/**
 * CloudWatch specifics: SigV4 against the published AWS test vectors, the
 * credential sources, and log group/stream creation against a local server.
 */

import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

import type { TransportLogEntry } from '../../types/transport.types';
import { AwsCredentialProvider, parseIni } from '../aws-credentials';
import { signV4 } from '../aws-sigv4';
import { CloudWatchTransport } from '../cloudwatch.transport';

process.env['LOGIXIA_SILENT_INTERNAL'] = '1';

const AWS_ENV_KEYS = [
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AWS_PROFILE',
  'AWS_SHARED_CREDENTIALS_FILE',
  'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
  'AWS_CONTAINER_CREDENTIALS_FULL_URI',
  'AWS_CONTAINER_AUTHORIZATION_TOKEN',
  'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE',
  'AWS_EC2_METADATA_SERVICE_ENDPOINT',
  'AWS_EC2_METADATA_DISABLED',
];

let saved: Record<string, string | undefined>;
let tmp: string;

beforeEach(() => {
  saved = Object.fromEntries(AWS_ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of AWS_ENV_KEYS) delete process.env[k];
  process.env['AWS_EC2_METADATA_DISABLED'] = 'true';
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-aws-'));
  process.env['AWS_SHARED_CREDENTIALS_FILE'] = path.join(tmp, 'missing');
});

afterEach(() => {
  for (const k of AWS_ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

// From the AWS Signature Version 4 test suite.
const VECTOR_CREDS = {
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
};
const VECTOR_DATE = new Date('2015-08-30T12:36:00Z');

describe('signV4 against the AWS test suite', () => {
  it('get-vanilla', () => {
    const headers = signV4({
      method: 'GET',
      path: '/',
      headers: { Host: 'example.amazonaws.com' },
      body: '',
      region: 'us-east-1',
      service: 'service',
      credentials: VECTOR_CREDS,
      date: VECTOR_DATE,
    });
    expect(headers['authorization']).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' +
        'SignedHeaders=host;x-amz-date, ' +
        'Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31'
    );
  });

  it('post-x-www-form-urlencoded, with mixed-case input header names', () => {
    const headers = signV4({
      method: 'POST',
      path: '/',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Host: 'example.amazonaws.com',
      },
      body: 'Param1=value1',
      region: 'us-east-1',
      service: 'service',
      credentials: VECTOR_CREDS,
      date: VECTOR_DATE,
    });
    expect(headers['authorization']).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' +
        'SignedHeaders=content-type;host;x-amz-date, ' +
        'Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a'
    );
  });

  it('signs the security token header when a session token is present', () => {
    const headers = signV4({
      method: 'GET',
      path: '/',
      headers: { host: 'example.amazonaws.com' },
      body: '',
      region: 'us-east-1',
      service: 'service',
      credentials: { ...VECTOR_CREDS, sessionToken: 'tok' },
      date: VECTOR_DATE,
    });
    expect(headers['authorization']).toContain(
      'SignedHeaders=host;x-amz-date;x-amz-security-token'
    );
  });
});

describe('parseIni', () => {
  it('reads sections, ignores comments and blank lines', () => {
    expect(parseIni('# c\n[default]\nk = v\n\n[dev]\n; x\na=b=c\n')).toEqual({
      default: { k: 'v' },
      dev: { a: 'b=c' },
    });
  });
});

async function listen(
  handler: http.RequestListener
): Promise<{ url: string; close(): Promise<void> }> {
  const sockets = new Set<Socket>();
  const server = http.createServer(handler);
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () =>
      new Promise<void>((r) => {
        for (const s of sockets) s.destroy();
        server.close(() => r());
      }),
  };
}

describe('AwsCredentialProvider', () => {
  it('prefers explicit config, then env', async () => {
    process.env['AWS_ACCESS_KEY_ID'] = 'ENVKEY';
    process.env['AWS_SECRET_ACCESS_KEY'] = 'envsecret';
    expect((await new AwsCredentialProvider({}).get()).accessKeyId).toBe('ENVKEY');
    const explicit = new AwsCredentialProvider({ accessKeyId: 'CFG', secretAccessKey: 's' });
    expect((await explicit.get()).accessKeyId).toBe('CFG');
  });

  it('reads the shared credentials file and honours AWS_PROFILE', async () => {
    const file = path.join(tmp, 'credentials');
    fs.writeFileSync(
      file,
      '[default]\naws_access_key_id=DEF\naws_secret_access_key=d\n[work]\naws_access_key_id=WORK\naws_secret_access_key=w\naws_session_token=st\n'
    );
    process.env['AWS_SHARED_CREDENTIALS_FILE'] = file;
    expect((await new AwsCredentialProvider({}).get()).accessKeyId).toBe('DEF');
    process.env['AWS_PROFILE'] = 'work';
    expect(await new AwsCredentialProvider({}).get()).toMatchObject({
      accessKeyId: 'WORK',
      sessionToken: 'st',
    });
  });

  it('reads ECS container credentials and sends the authorization token', async () => {
    let auth: string | undefined;
    const srv = await listen((req, res) => {
      auth = req.headers['authorization'];
      res.end(
        JSON.stringify({
          AccessKeyId: 'ECSKEY',
          SecretAccessKey: 'ecs',
          Token: 'ecstok',
          Expiration: new Date(Date.now() + 3600_000).toISOString(),
        })
      );
    });
    try {
      process.env['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = `${srv.url}/creds`;
      process.env['AWS_CONTAINER_AUTHORIZATION_TOKEN'] = 'secret-token';
      const creds = await new AwsCredentialProvider({}).get();
      expect(creds).toMatchObject({ accessKeyId: 'ECSKEY', sessionToken: 'ecstok' });
      expect(auth).toBe('secret-token');
    } finally {
      await srv.close();
    }
  });

  it('reads EC2 instance metadata through IMDSv2', async () => {
    const seen: string[] = [];
    const srv = await listen((req, res) => {
      seen.push(`${req.method} ${req.url}`);
      if (req.method === 'PUT') return void res.end('imds-token');
      if (req.headers['x-aws-ec2-metadata-token'] !== 'imds-token') {
        res.statusCode = 401;
        return void res.end();
      }
      if (req.url?.endsWith('/security-credentials/')) return void res.end('my-role\n');
      res.end(JSON.stringify({ AccessKeyId: 'IMDSKEY', SecretAccessKey: 'i', Token: 't' }));
    });
    try {
      delete process.env['AWS_EC2_METADATA_DISABLED'];
      process.env['AWS_EC2_METADATA_SERVICE_ENDPOINT'] = srv.url;
      const creds = await new AwsCredentialProvider({}).get();
      expect(creds.accessKeyId).toBe('IMDSKEY');
      expect(seen[0]).toBe('PUT /latest/api/token');
      expect(seen[2]).toBe('GET /latest/meta-data/iam/security-credentials/my-role');
    } finally {
      await srv.close();
    }
  });

  it('throws when nothing yields credentials', async () => {
    await expect(new AwsCredentialProvider({}).get()).rejects.toThrow(/no AWS credentials/);
  });
});

function entry(i: number, ts = 0): TransportLogEntry {
  return {
    timestamp: new Date(1_700_000_000_000 + ts),
    level: 'info',
    message: `cw-${i}`,
    data: { duration: 5 },
  };
}

describe('CloudWatchTransport against a local endpoint', () => {
  interface Call {
    target: string;
    headers: http.IncomingHttpHeaders;
    body: Record<string, any>;
  }
  let calls: Call[];
  let respond: (call: Call, res: http.ServerResponse) => void;
  let srv: { url: string; close(): Promise<void> };

  beforeEach(async () => {
    calls = [];
    respond = (_call, res) => void res.end('{}');
    srv = await listen((req, res) => {
      let raw = '';
      req.on('data', (c: Buffer) => (raw += c.toString()));
      req.on('end', () => {
        const call = {
          target: String(req.headers['x-amz-target']),
          headers: req.headers,
          body: JSON.parse(raw) as Record<string, any>,
        };
        calls.push(call);
        respond(call, res);
      });
    });
    process.env['AWS_ACCESS_KEY_ID'] = 'AKID';
    process.env['AWS_SECRET_ACCESS_KEY'] = 'secret';
  });

  afterEach(async () => {
    await srv.close();
  });

  const make = (over: Record<string, unknown> = {}) =>
    new CloudWatchTransport({
      logGroupName: '/app',
      logStreamName: 'web-1',
      endpoint: srv.url,
      region: 'us-east-1',
      flushIntervalMs: 999_999,
      ...over,
    });

  it('creates the group and stream once, then puts events with a lowercase sorted signature', async () => {
    const t = make();
    t.write(entry(1));
    await t.flush();
    t.write(entry(2));
    await t.close();

    expect(calls.map((c) => c.target)).toEqual([
      'Logs_20140328.CreateLogGroup',
      'Logs_20140328.CreateLogStream',
      'Logs_20140328.PutLogEvents',
      'Logs_20140328.PutLogEvents',
    ]);
    const auth = String(calls[2]!.headers['authorization']);
    const signed = /SignedHeaders=([^,]+),/.exec(auth)![1]!;
    expect(signed).toBe('content-type;host;x-amz-date;x-amz-target');
    expect(signed).toBe(signed.toLowerCase());
  });

  it('treats ResourceAlreadyExistsException as success', async () => {
    respond = (call, res) => {
      if (call.target.endsWith('PutLogEvents')) return void res.end('{}');
      res.statusCode = 400;
      res.end(JSON.stringify({ __type: 'ResourceAlreadyExistsException' }));
    };
    const t = make();
    t.write(entry(1));
    await t.close();
    expect(calls.at(-1)!.target).toBe('Logs_20140328.PutLogEvents');
    expect(calls.at(-1)!.body['logEvents']).toHaveLength(1);
  });

  it('recreates the stream and retries after ResourceNotFoundException', async () => {
    let putFailures = 1;
    respond = (call, res) => {
      if (call.target.endsWith('PutLogEvents') && putFailures-- > 0) {
        res.statusCode = 400;
        return void res.end(JSON.stringify({ __type: 'ResourceNotFoundException' }));
      }
      res.end('{}');
    };
    const t = make();
    t.write(entry(1));
    await t.close();
    expect(calls.map((c) => c.target.split('.')[1])).toEqual([
      'CreateLogGroup',
      'CreateLogStream',
      'PutLogEvents',
      'CreateLogGroup',
      'CreateLogStream',
      'PutLogEvents',
    ]);
  });

  it('retries a throttled batch (HTTP 400 ThrottlingException) but drops other 400s', async () => {
    let n = 0;
    respond = (call, res) => {
      if (!call.target.endsWith('PutLogEvents')) return void res.end('{}');
      n += 1;
      if (n === 1) {
        res.statusCode = 400;
        return void res.end(JSON.stringify({ __type: 'ThrottlingException' }));
      }
      if (n === 2) {
        res.statusCode = 400;
        return void res.end(JSON.stringify({ __type: 'InvalidParameterException' }));
      }
      res.end('{}');
    };
    const t = make();
    t.write(entry(1));
    await t.flush();
    await t.flush();
    await t.flush();
    expect(n).toBe(2);
  });

  it('sorts events by timestamp inside a batch', async () => {
    const t = make();
    t.write(entry(1, 30));
    t.write(entry(2, 10));
    t.write(entry(3, 20));
    await t.close();
    const put = calls.find((c) => c.target.endsWith('PutLogEvents'))!;
    expect(put.body['logEvents'].map((e: { message: string }) => e.message)).toEqual([
      expect.stringContaining('cw-2'),
      expect.stringContaining('cw-3'),
      expect.stringContaining('cw-1'),
    ]);
  });

  it('keeps events buffered when no credentials are available, then delivers them', async () => {
    delete process.env['AWS_ACCESS_KEY_ID'];
    delete process.env['AWS_SECRET_ACCESS_KEY'];
    const t = make();
    t.write(entry(1));
    await t.flush();
    expect(calls).toHaveLength(0);

    process.env['AWS_ACCESS_KEY_ID'] = 'AKID';
    process.env['AWS_SECRET_ACCESS_KEY'] = 'secret';
    await t.close();
    expect(calls.at(-1)!.body['logEvents']).toHaveLength(1);
  });

  it('puts EMF metrics under the Logixia namespace by default', async () => {
    const t = make({ emf: true });
    t.write(entry(1));
    await t.close();
    const put = calls.find((c) => c.target.endsWith('PutLogEvents'))!;
    const emf = JSON.parse(put.body['logEvents'][0].message);
    expect(emf._aws.CloudWatchMetrics[0].Namespace).toBe('Logixia');
    expect(emf._aws.CloudWatchMetrics[0].Metrics).toEqual([{ Name: 'duration', Unit: 'None' }]);
  });
});
