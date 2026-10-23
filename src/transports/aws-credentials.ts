/**
 * AWS credential resolution without the SDK.
 *
 * Order: explicit config, environment variables, shared credentials file,
 * ECS/container credentials, EC2 instance metadata (IMDSv2).
 * Not supported: SSO, assume-role profiles, credential_process, web identity.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { type AwsCredentials } from './aws-sigv4';
import { httpRequest } from './batch-buffer';

const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const FAILURE_BACKOFF_MS = 30 * 1000;
const METADATA_TIMEOUT_MS = 2000;

export interface AwsCredentialConfig {
  accessKeyId?: string | undefined;
  secretAccessKey?: string | undefined;
  sessionToken?: string | undefined;
}

/** Parse the sections of an AWS ini file into `{ section: { key: value } }`. */
export function parseIni(text: string): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  let section: Record<string, string> | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const header = /^\[(.+)\]$/.exec(line);
    if (header) {
      section = out[header[1]!.trim()] = out[header[1]!.trim()] ?? {};
      continue;
    }
    const eq = line.indexOf('=');
    if (eq > 0 && section) section[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}

function fromEnv(): AwsCredentials | undefined {
  const accessKeyId = process.env['AWS_ACCESS_KEY_ID'];
  const secretAccessKey = process.env['AWS_SECRET_ACCESS_KEY'];
  if (!accessKeyId || !secretAccessKey) return undefined;
  return { accessKeyId, secretAccessKey, sessionToken: process.env['AWS_SESSION_TOKEN'] };
}

function fromSharedFile(): AwsCredentials | undefined {
  const file =
    process.env['AWS_SHARED_CREDENTIALS_FILE'] ?? path.join(os.homedir(), '.aws', 'credentials');
  const profile = process.env['AWS_PROFILE'] ?? 'default';
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
  const section = parseIni(text)[profile];
  const accessKeyId = section?.['aws_access_key_id'];
  const secretAccessKey = section?.['aws_secret_access_key'];
  if (!accessKeyId || !secretAccessKey) return undefined;
  return { accessKeyId, secretAccessKey, sessionToken: section?.['aws_session_token'] };
}

interface CredentialDocument {
  AccessKeyId?: string;
  SecretAccessKey?: string;
  Token?: string;
  Expiration?: string;
}

function fromDocument(raw: string): AwsCredentials | undefined {
  const doc = JSON.parse(raw) as CredentialDocument;
  if (!doc.AccessKeyId || !doc.SecretAccessKey) return undefined;
  const expiresAt = doc.Expiration ? Date.parse(doc.Expiration) : Number.NaN;
  return {
    accessKeyId: doc.AccessKeyId,
    secretAccessKey: doc.SecretAccessKey,
    sessionToken: doc.Token,
    expiresAt: Number.isNaN(expiresAt) ? undefined : expiresAt,
  };
}

async function fromContainer(): Promise<AwsCredentials | undefined> {
  const relative = process.env['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'];
  const full = process.env['AWS_CONTAINER_CREDENTIALS_FULL_URI'];
  if (!relative && !full) return undefined;
  const url = new URL(relative ? `http://169.254.170.2${relative}` : (full as string));
  const headers: Record<string, string> = {};
  const tokenFile = process.env['AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE'];
  const token = tokenFile
    ? fs.readFileSync(tokenFile, 'utf8').trim()
    : process.env['AWS_CONTAINER_AUTHORIZATION_TOKEN'];
  if (token) headers['Authorization'] = token;
  const res = await httpRequest({
    url,
    method: 'GET',
    headers,
    timeoutMs: METADATA_TIMEOUT_MS,
    label: 'AWS container credentials',
  });
  return fromDocument(res.body);
}

async function fromInstanceMetadata(): Promise<AwsCredentials | undefined> {
  if (process.env['AWS_EC2_METADATA_DISABLED'] === 'true') return undefined;
  const base = process.env['AWS_EC2_METADATA_SERVICE_ENDPOINT'] ?? 'http://169.254.169.254';
  const get = (p: string, method: string, headers: Record<string, string>) =>
    httpRequest({
      url: new URL(p, base),
      method,
      headers,
      timeoutMs: METADATA_TIMEOUT_MS,
      label: 'EC2 instance metadata',
    });
  const session = await get('/latest/api/token', 'PUT', {
    'X-aws-ec2-metadata-token-ttl-seconds': '21600',
  });
  const auth = { 'X-aws-ec2-metadata-token': session.body.trim() };
  const roles = await get('/latest/meta-data/iam/security-credentials/', 'GET', auth);
  const role = roles.body.split('\n')[0]?.trim();
  if (!role) return undefined;
  const creds = await get(
    `/latest/meta-data/iam/security-credentials/${encodeURIComponent(role)}`,
    'GET',
    auth
  );
  return fromDocument(creds.body);
}

export class AwsCredentialProvider {
  private cached: AwsCredentials | undefined;
  private failedAt = 0;
  private readonly explicit: AwsCredentials | undefined;

  constructor(config: AwsCredentialConfig) {
    if (config.accessKeyId && config.secretAccessKey) {
      this.explicit = {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
        sessionToken: config.sessionToken,
      };
    }
  }

  /** Throws when no source yields credentials, so the caller keeps its buffer. */
  async get(): Promise<AwsCredentials> {
    if (this.explicit) return this.explicit;
    const env = fromEnv();
    if (env) return env;
    if (this.cached && !this.isExpiring(this.cached)) return this.cached;
    if (Date.now() - this.failedAt < FAILURE_BACKOFF_MS) {
      throw new Error('no AWS credentials found (retrying shortly)');
    }

    let found = fromSharedFile();
    for (const source of [fromContainer, fromInstanceMetadata]) {
      if (found) break;
      try {
        found = await source();
      } catch {
        /* source not available here; try the next */
      }
    }
    if (!found) {
      this.failedAt = Date.now();
      throw new Error(
        'no AWS credentials found: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, a shared credentials file, container credentials, or run on EC2 with an instance role'
      );
    }
    this.cached = found;
    return found;
  }

  invalidate(): void {
    this.cached = undefined;
    this.failedAt = 0;
  }

  private isExpiring(c: AwsCredentials): boolean {
    return c.expiresAt !== undefined && c.expiresAt - Date.now() < REFRESH_MARGIN_MS;
  }
}
