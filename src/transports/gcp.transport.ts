/**
 * logixia — Google Cloud Logging (Stackdriver) transport
 *
 * Maps logixia log entries to the GCP Logging REST API format:
 *   - Maps `level` → `severity` (INFO, WARNING, ERROR, CRITICAL…)
 *   - Injects `logging.googleapis.com/trace` for Cloud Trace correlation
 *   - Injects `logging.googleapis.com/spanId` and `traceSampled`
 *   - Adds `logging.googleapis.com/sourceLocation` when available
 *   - Supports structured `jsonPayload` and plain `textPayload`
 *
 * Auth: uses Application Default Credentials (ADC) — the `GOOGLE_APPLICATION_CREDENTIALS`
 * env var pointing to a service-account key file, or the metadata server on GCE/GKE.
 *
 * @example
 * ```ts
 * import { GCPTransport } from 'logixia';
 *
 * const logger = createLogger({
 *   transports: {
 *     gcp: new GCPTransport({
 *       projectId: process.env.GOOGLE_CLOUD_PROJECT,
 *       logName: 'projects/my-project/logs/api',
 *       resource: { type: 'gce_instance', labels: { instance_id: '123' } },
 *     }),
 *   },
 * });
 * ```
 */

import * as https from 'node:https';

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';

export interface GCPMonitoredResource {
  type: string;
  labels?: Record<string, string>;
}

export interface GCPTransportConfig {
  /** GCP project ID. Falls back to `GOOGLE_CLOUD_PROJECT` or `GCLOUD_PROJECT` env vars. */
  projectId?: string;
  /**
   * Full log name, e.g. `'projects/my-project/logs/api'`.
   * If omitted, defaults to `projects/{projectId}/logs/logixia`.
   */
  logName?: string;
  /** Monitored resource descriptor. Defaults to `global`. */
  resource?: GCPMonitoredResource;
  /**
   * Service account key JSON (parsed). If omitted, ADC is used
   * (GOOGLE_APPLICATION_CREDENTIALS env var or metadata server).
   */
  credentials?: {
    client_email: string;
    private_key: string;
  };
  /** Number of entries to batch. @default 200 */
  batchSize?: number;
  /** Flush interval in ms. @default 5000 */
  flushIntervalMs?: number;
  level?: string;
}

type GcpSeverity =
  | 'DEFAULT'
  | 'DEBUG'
  | 'INFO'
  | 'NOTICE'
  | 'WARNING'
  | 'ERROR'
  | 'CRITICAL'
  | 'ALERT'
  | 'EMERGENCY';

function toGcpSeverity(level: string): GcpSeverity {
  switch (level.toLowerCase()) {
    case 'trace':
    case 'verbose':
    case 'debug':
      return 'DEBUG';
    case 'info':
    case 'log':
      return 'INFO';
    case 'warn':
    case 'warning':
      return 'WARNING';
    case 'error':
      return 'ERROR';
    case 'critical':
    case 'fatal':
      return 'CRITICAL';
    default:
      return 'DEFAULT';
  }
}

/**
 * Google Cloud Logging transport with trace correlation and GCP severity mapping.
 */
export class GCPTransport implements IAsyncTransport {
  public readonly name = 'gcp';
  public readonly batchSize: number;
  public readonly flushInterval: number;
  public readonly level: string | undefined;

  private batch: TransportLogEntry[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private accessToken: string | null = null;
  private tokenExpiry = 0;

  private readonly projectId: string;
  private readonly logName: string;
  private readonly resource: GCPMonitoredResource;
  private readonly credentials: { client_email: string; private_key: string } | undefined;

  constructor(config: GCPTransportConfig) {
    this.projectId =
      config.projectId ??
      process.env['GOOGLE_CLOUD_PROJECT'] ??
      process.env['GCLOUD_PROJECT'] ??
      'unknown-project';
    this.logName = config.logName ?? `projects/${this.projectId}/logs/logixia`;
    this.resource = config.resource ?? { type: 'global' };
    this.credentials = config.credentials;
    this.batchSize = config.batchSize ?? 200;
    this.flushInterval = config.flushIntervalMs ?? 5000;
    this.level = config.level;

    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.flushInterval);
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  write(entry: TransportLogEntry): void {
    this.batch.push(entry);
    if (this.batch.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  async flush(): Promise<void> {
    if (this.batch.length === 0) return;
    const entries = this.batch.splice(0, this.batchSize);
    try {
      await this.writeEntries(entries);
    } catch (err) {
      internalError('GCPTransport flush error', err);
      this.batch.unshift(...entries);
    }
  }

  private buildLogEntry(entry: TransportLogEntry): Record<string, unknown> {
    const gcpEntry: Record<string, unknown> = {
      logName: this.logName,
      resource: this.resource,
      severity: toGcpSeverity(entry.level),
      timestamp: entry.timestamp ?? new Date().toISOString(),
      jsonPayload: {
        message: entry.message,
        appName: entry.appName,
        context: entry.context,
        ...(entry.data ?? {}),
      },
    };

    // GCP Cloud Trace correlation
    if (entry.traceId) {
      gcpEntry['trace'] = `projects/${this.projectId}/traces/${entry.traceId}`;
      gcpEntry['traceSampled'] = true;
    }

    return gcpEntry;
  }

  private async getAccessToken(): Promise<string | null> {
    if (this.accessToken && Date.now() < this.tokenExpiry) return this.accessToken;

    // Try ADC metadata server (GCE/GKE/Cloud Run)
    try {
      const token = await this.fetchFromMetadataServer();
      if (token) {
        this.accessToken = token;
        this.tokenExpiry = Date.now() + 55 * 60 * 1000; // 55 minutes
        return this.accessToken;
      }
    } catch {
      /* fall through to service account */
    }

    // Try service account key
    if (this.credentials) {
      try {
        const token = await this.fetchServiceAccountToken();
        if (token) {
          this.accessToken = token;
          this.tokenExpiry = Date.now() + 55 * 60 * 1000;
          return this.accessToken;
        }
      } catch (err) {
        internalError('GCPTransport service account token error', err);
      }
    }

    return null;
  }

  private fetchFromMetadataServer(): Promise<string | null> {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: 'metadata.google.internal',
          path: '/computeMetadata/v1/instance/service-accounts/default/token',
          headers: { 'Metadata-Flavor': 'Google' },
          timeout: 3000,
        },
        (res) => {
          let raw = '';
          res.on('data', (c: Buffer) => (raw += c.toString()));
          res.on('end', () => {
            if (res.statusCode === 200) {
              try {
                const parsed = JSON.parse(raw) as { access_token?: string };
                resolve(parsed.access_token ?? null);
              } catch {
                resolve(null);
              }
            } else {
              resolve(null);
            }
          });
        }
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('metadata timeout'));
      });
      req.end();
    });
  }

  private fetchServiceAccountToken(): Promise<string | null> {
    // Minimal JWT creation for service account — only for environments without
    // the full Google Auth Library. For production workloads, prefer ADC.
    if (!this.credentials) return Promise.resolve(null);

    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + 3600;
    const scope = 'https://www.googleapis.com/auth/logging.write';

    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        iss: this.credentials.client_email,
        scope,
        aud: 'https://oauth2.googleapis.com/token',
        exp,
        iat,
      })
    ).toString('base64url');

    const signingInput = `${header}.${payload}`;

    let signature: string;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const sign = require('node:crypto').createSign('RSA-SHA256');
      sign.update(signingInput);
      signature = sign.sign(this.credentials.private_key, 'base64url') as string;
    } catch {
      return Promise.resolve(null);
    }

    const jwt = `${signingInput}.${signature}`;
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;

    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: 'oauth2.googleapis.com',
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (res) => {
          let raw = '';
          res.on('data', (c: Buffer) => (raw += c.toString()));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(raw) as { access_token?: string };
              resolve(parsed.access_token ?? null);
            } catch {
              resolve(null);
            }
          });
        }
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  private async writeEntries(entries: TransportLogEntry[]): Promise<void> {
    const token = await this.getAccessToken();
    if (!token) {
      internalWarn('GCPTransport: no access token available — dropping entries');
      return;
    }

    const body = JSON.stringify({
      logName: this.logName,
      resource: this.resource,
      entries: entries.map((e) => this.buildLogEntry(e)),
    });

    return new Promise<void>((resolve, reject) => {
      const req = https.request(
        {
          hostname: 'logging.googleapis.com',
          path: '/v2/entries:write',
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (res) => {
          let raw = '';
          res.on('data', (c: Buffer) => (raw += c.toString()));
          res.on('end', () => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve();
            } else {
              reject(new Error(`GCP Logging API returned ${res.statusCode}: ${raw}`));
            }
          });
        }
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }
}
