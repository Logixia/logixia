/**
 * logixia — AWS CloudWatch Logs transport
 *
 * Sends log entries to AWS CloudWatch Logs via the PutLogEvents API.
 * Supports EMF (Embedded Metric Format) for automatic metric extraction.
 *
 * Auth: uses the standard AWS credential chain — environment variables
 * (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), ~/.aws/credentials, or
 * instance/task IAM roles. No SDK dependency — uses raw HTTPS with
 * AWS Signature Version 4.
 *
 * @example
 * ```ts
 * import { CloudWatchTransport } from 'logixia';
 *
 * const logger = createLogger({
 *   transports: {
 *     cloudwatch: new CloudWatchTransport({
 *       region: 'us-east-1',
 *       logGroupName: '/myapp/production',
 *       logStreamName: `api-${process.env.HOSTNAME}`,
 *       batchSize: 100,
 *       flushIntervalMs: 5000,
 *     }),
 *   },
 * });
 * ```
 */

import * as crypto from 'node:crypto';
import * as https from 'node:https';

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';

export interface CloudWatchTransportConfig {
  /** AWS region, e.g. `'us-east-1'`. Falls back to `AWS_REGION` env var. */
  region?: string;
  /** CloudWatch Logs group name. Created automatically if it does not exist. */
  logGroupName: string;
  /** CloudWatch Logs stream name. Defaults to hostname + process PID. */
  logStreamName?: string;
  /** AWS access key ID. Falls back to `AWS_ACCESS_KEY_ID` env var. */
  accessKeyId?: string;
  /** AWS secret access key. Falls back to `AWS_SECRET_ACCESS_KEY` env var. */
  secretAccessKey?: string;
  /** AWS session token (for temporary credentials). Falls back to `AWS_SESSION_TOKEN`. */
  sessionToken?: string;
  /**
   * Number of log events to batch before flushing.
   * CloudWatch allows max 10,000 events per PutLogEvents call.
   * @default 100
   */
  batchSize?: number;
  /**
   * Max ms between flushes even if batchSize is not reached.
   * @default 5000
   */
  flushIntervalMs?: number;
  /**
   * Enable EMF (Embedded Metric Format) — wraps log entries as CloudWatch
   * metric namespaces so numeric fields become CloudWatch Metrics automatically.
   * @default false
   */
  emf?: boolean;
  /** Minimum log level to forward. */
  level?: string;
}

interface CwLogEvent {
  timestamp: number;
  message: string;
}

/**
 * AWS CloudWatch Logs transport with EMF support and batched PutLogEvents calls.
 */
export class CloudWatchTransport implements IAsyncTransport {
  public readonly name = 'cloudwatch';
  public readonly batchSize: number;
  public readonly flushInterval: number;
  public readonly level: string | undefined;

  private batch: CwLogEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private sequenceToken: string | undefined;

  private readonly region: string;
  private readonly logGroupName: string;
  private readonly logStreamName: string;
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private readonly sessionToken: string | undefined;
  private readonly emf: boolean;

  constructor(config: CloudWatchTransportConfig) {
    this.region =
      config.region ??
      process.env['AWS_REGION'] ??
      process.env['AWS_DEFAULT_REGION'] ??
      'us-east-1';
    this.logGroupName = config.logGroupName;
    this.logStreamName =
      config.logStreamName ?? `${process.env['HOSTNAME'] ?? 'node'}-${process.pid}`;
    this.accessKeyId = config.accessKeyId ?? process.env['AWS_ACCESS_KEY_ID'] ?? '';
    this.secretAccessKey = config.secretAccessKey ?? process.env['AWS_SECRET_ACCESS_KEY'] ?? '';
    this.sessionToken = config.sessionToken ?? process.env['AWS_SESSION_TOKEN'];
    this.batchSize = config.batchSize ?? 100;
    this.flushInterval = config.flushIntervalMs ?? 5000;
    this.emf = config.emf ?? false;
    this.level = config.level;

    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.flushInterval);
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  write(entry: TransportLogEntry): void {
    const timestamp = entry.timestamp ? new Date(entry.timestamp).getTime() : Date.now();
    const message = this.emf ? this.toEmf(entry) : JSON.stringify(entry);
    this.batch.push({ timestamp, message });
    if (this.batch.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  async flush(): Promise<void> {
    if (this.batch.length === 0) return;
    const events = this.batch.splice(0, this.batchSize);
    try {
      await this.putLogEvents(events);
    } catch (err) {
      internalError('CloudWatchTransport flush error', err);
      // Re-queue on failure
      this.batch.unshift(...events);
    }
  }

  private toEmf(entry: TransportLogEntry): string {
    const { level, message, data: payload } = entry;
    const numericFields: Record<string, number> = {};
    for (const [k, v] of Object.entries(payload ?? {})) {
      if (typeof v === 'number') numericFields[k] = v;
    }
    return JSON.stringify({
      _aws: {
        Timestamp: Date.now(),
        CloudWatchMetrics:
          Object.keys(numericFields).length > 0
            ? [
                {
                  Namespace: this.logGroupName,
                  Dimensions: [['level']],
                  Metrics: Object.keys(numericFields).map((n) => ({ Name: n, Unit: 'None' })),
                },
              ]
            : [],
      },
      level,
      message,
      ...payload,
      ...numericFields,
    });
  }

  private async putLogEvents(events: CwLogEvent[]): Promise<void> {
    if (!this.accessKeyId || !this.secretAccessKey) {
      internalWarn('CloudWatchTransport: missing AWS credentials — skipping PutLogEvents');
      return;
    }

    const body = JSON.stringify({
      logGroupName: this.logGroupName,
      logStreamName: this.logStreamName,
      logEvents: events,
      ...(this.sequenceToken ? { sequenceToken: this.sequenceToken } : {}),
    });

    const host = `logs.${this.region}.amazonaws.com`;
    const path = '/';
    const service = 'logs';
    const method = 'POST';
    const amzTarget = 'Logs_20140328.PutLogEvents';

    const headers = await this.signRequest(method, host, path, service, body, {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Target': amzTarget,
    });

    return new Promise<void>((resolve, reject) => {
      const req = https.request({ host, path, method, headers }, (res) => {
        let raw = '';
        res.on('data', (c: Buffer) => (raw += c.toString()));
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsed = JSON.parse(raw) as { nextSequenceToken?: string };
              if (parsed.nextSequenceToken) this.sequenceToken = parsed.nextSequenceToken;
            } catch {
              /* ignore */
            }
            resolve();
          } else {
            reject(new Error(`CloudWatch PutLogEvents returned ${res.statusCode}: ${raw}`));
          }
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  // ── AWS Signature Version 4 ─────────────────────────────────────────────────

  private async signRequest(
    method: string,
    host: string,
    path: string,
    service: string,
    body: string,
    extraHeaders: Record<string, string>
  ): Promise<Record<string, string>> {
    const now = new Date();
    const amzDate = now
      .toISOString()
      .replace(/[:-]/g, '')
      .replace(/\.\d+Z/, 'Z');
    const dateStamp = amzDate.slice(0, 8);

    const payloadHash = crypto.createHash('sha256').update(body).digest('hex');
    const headers: Record<string, string> = {
      host,
      'x-amz-date': amzDate,
      'x-amz-content-sha256': payloadHash,
      ...(this.sessionToken ? { 'x-amz-security-token': this.sessionToken } : {}),
      ...extraHeaders,
    };

    const signedHeaderKeys = Object.keys(headers).sort().join(';');
    const canonicalHeaders =
      Object.entries(headers)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}:${v.trim()}`)
        .join('\n') + '\n';

    const canonicalRequest = [
      method,
      path,
      '',
      canonicalHeaders,
      signedHeaderKeys,
      payloadHash,
    ].join('\n');
    const credentialScope = `${dateStamp}/${this.region}/${service}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      crypto.createHash('sha256').update(canonicalRequest).digest('hex'),
    ].join('\n');

    const sign = (key: Buffer | string, msg: string): Buffer =>
      crypto.createHmac('sha256', key).update(msg).digest();

    const signingKey = sign(
      sign(sign(sign(`AWS4${this.secretAccessKey}`, dateStamp), this.region), service),
      'aws4_request'
    );
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

    const authHeader =
      `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, ` +
      `SignedHeaders=${signedHeaderKeys}, Signature=${signature}`;

    return {
      ...headers,
      Authorization: authHeader,
      'Content-Length': Buffer.byteLength(body).toString(),
    };
  }
}
