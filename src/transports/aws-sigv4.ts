/**
 * AWS Signature Version 4 request signing, dependency-free.
 */

import * as crypto from 'node:crypto';

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string | undefined;
  /** Epoch ms after which the credentials are no longer valid. */
  expiresAt?: number | undefined;
}

export interface SignV4Options {
  method: string;
  path: string;
  query?: string;
  /** Must include `host`. Names are lowercased before signing. */
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  credentials: AwsCredentials;
  date?: Date;
}

const sha256Hex = (data: string): string => crypto.createHash('sha256').update(data).digest('hex');

const hmac = (key: Buffer | string, msg: string): Buffer =>
  crypto.createHmac('sha256', key).update(msg).digest();

/** Returns the request headers (lowercase names) with `x-amz-date` and `authorization` added. */
export function signV4(opts: SignV4Options): Record<string, string> {
  const {
    method,
    path,
    query = '',
    body,
    region,
    service,
    credentials,
    headers: input,
    date,
  } = opts;
  const amzDate = (date ?? new Date()).toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(input)) headers[k.toLowerCase()] = v;
  headers['x-amz-date'] = amzDate;
  if (credentials.sessionToken) headers['x-amz-security-token'] = credentials.sessionToken;

  const names = Object.keys(headers).sort();
  const canonicalHeaders = names
    .map((n) => `${n}:${headers[n]!.trim().replace(/\s+/g, ' ')}\n`)
    .join('');
  const signedHeaders = names.join(';');

  const canonicalRequest = [
    method,
    path,
    query,
    canonicalHeaders,
    signedHeaders,
    sha256Hex(body),
  ].join('\n');
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');

  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${credentials.secretAccessKey}`, dateStamp), region), service),
    'aws4_request'
  );
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  headers['authorization'] =
    `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return headers;
}
