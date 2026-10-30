/**
 * logixia — AWS CloudWatch Logs transport
 *
 * Sends log entries to AWS CloudWatch Logs via the PutLogEvents API.
 * Supports EMF (Embedded Metric Format) for automatic metric extraction.
 *
 * Auth, in order: explicit config, environment variables, the shared
 * credentials file (AWS_PROFILE, AWS_SHARED_CREDENTIALS_FILE), ECS container
 * credentials, then EC2 instance metadata (IMDSv2). SSO, assume-role profiles
 * and credential_process are not supported. No SDK dependency — raw HTTPS with
 * AWS Signature Version 4.
 *
 * The log group and stream are created on first use if they do not exist.
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

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalWarn } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';
import { AwsCredentialProvider } from './aws-credentials';
import { signV4 } from './aws-sigv4';
import {
  BatchBuffer,
  DEFAULT_MAX_BUFFER_SIZE,
  DEFAULT_REQUEST_TIMEOUT_MS,
  HttpError,
  httpRequest,
  isPermanentHttpError,
} from './batch-buffer';
import { mergeCoreFields } from './entry-fields';
import { protectSecrets, urlSecrets } from './secret-config';

export interface CloudWatchTransportConfig {
  /** AWS region, e.g. `'us-east-1'`. Falls back to `AWS_REGION` env var. */
  region?: string;
  /** CloudWatch Logs group name. Created automatically if it does not exist. */
  logGroupName: string;
  /** CloudWatch Logs stream name. Defaults to hostname + process PID. */
  logStreamName?: string;
  /** Override the Logs endpoint, e.g. for LocalStack. Default: `https://logs.<region>.amazonaws.com`. */
  endpoint?: string;
  /** AWS access key ID. Falls back to the credential chain described above. */
  accessKeyId?: string;
  /** AWS secret access key. Used together with `accessKeyId`. */
  secretAccessKey?: string;
  /** AWS session token for temporary credentials. Used together with `accessKeyId`. */
  sessionToken?: string;
  /**
   * Number of log events to batch before flushing.
   * CloudWatch allows max 10,000 events per PutLogEvents call; larger values are capped.
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
  /** CloudWatch Metrics namespace used by EMF. @default 'Logixia' */
  emfNamespace?: string;
  /**
   * Payload fields published as EMF metrics. When set, only these numeric
   * fields become metrics; when unset every numeric payload field does (up to
   * the EMF limit of 100 per entry).
   */
  emfMetrics?: string[];
  /** Abort a request that has not finished after this many ms. @default 10000 */
  requestTimeoutMs?: number;
  /** Max buffered events; the oldest are dropped past this. @default 10000 */
  maxBufferSize?: number;
  /** Minimum log level to forward. */
  level?: string;
}

const MAX_EVENTS_PER_PUT = 10_000;
const EMF_MAX_METRICS = 100;

/** Error types worth retrying even though CloudWatch reports them as HTTP 400. */
const RETRYABLE_TYPES = new Set([
  'ThrottlingException',
  'ThrottledException',
  'LimitExceededException',
  'ServiceUnavailableException',
  'ExpiredTokenException',
  'ResourceNotFoundException',
]);

function awsErrorType(err: unknown): string | undefined {
  if (!(err instanceof HttpError)) return undefined;
  try {
    const type = (JSON.parse(err.body) as { __type?: string }).__type;
    return type?.split('#').pop();
  } catch {
    return undefined;
  }
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

  private readonly buffer: BatchBuffer<CwLogEvent>;
  private readonly requestTimeoutMs: number;
  private flushTimer: NodeJS.Timeout | null = null;
  private readonly credentials: AwsCredentialProvider;
  private readonly endpoint: URL;
  private streamReady = false;

  private readonly region: string;
  private readonly logGroupName: string;
  private readonly logStreamName: string;
  private readonly emf: boolean;
  private readonly emfNamespace: string;
  private readonly emfMetrics: ReadonlySet<string> | undefined;

  constructor(config: CloudWatchTransportConfig) {
    this.region =
      config.region ??
      process.env['AWS_REGION'] ??
      process.env['AWS_DEFAULT_REGION'] ??
      'us-east-1';
    this.logGroupName = config.logGroupName;
    this.logStreamName =
      config.logStreamName ?? `${process.env['HOSTNAME'] ?? 'node'}-${process.pid}`;
    this.credentials = new AwsCredentialProvider(config);
    this.endpoint = new URL(config.endpoint ?? `https://logs.${this.region}.amazonaws.com`);
    this.batchSize = Math.min(config.batchSize ?? 100, MAX_EVENTS_PER_PUT);
    this.emfNamespace = config.emfNamespace ?? 'Logixia';
    this.flushInterval = config.flushIntervalMs ?? 5000;
    this.emf = config.emf ?? false;
    this.emfMetrics = config.emfMetrics ? new Set(config.emfMetrics) : undefined;
    this.level = config.level;
    this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.buffer = new BatchBuffer<CwLogEvent>({
      name: 'CloudWatchTransport',
      batchSize: this.batchSize,
      maxBufferSize: config.maxBufferSize ?? DEFAULT_MAX_BUFFER_SIZE,
      send: (events) => this.putLogEvents(events),
      secrets: () => [...this.credentials.secretValues(), ...urlSecrets(this.endpoint)],
      shouldRetry: (err) =>
        !isPermanentHttpError(err) || RETRYABLE_TYPES.has(awsErrorType(err) ?? ''),
    });

    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.flushInterval);
    if (this.flushTimer.unref) this.flushTimer.unref();
    protectSecrets(this, ['credentials', 'endpoint']);
  }

  write(entry: TransportLogEntry): void {
    const timestamp = entry.timestamp ? new Date(entry.timestamp).getTime() : Date.now();
    const message = this.emf ? this.toEmf(entry) : stringifyForLog(entry);
    this.buffer.push({ timestamp, message });
    this.buffer.flushIfFull();
  }

  flush(): Promise<void> {
    return this.buffer.flush();
  }

  /**
   * Flush remaining events and stop the interval timer on shutdown. Without this
   * the manager's close() skips the transport (close was undefined) and any
   * buffered events were lost on deploy. Waits for any in-flight send first.
   */
  async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.buffer.close();
  }

  private toEmf(entry: TransportLogEntry): string {
    const { level, message, data: payload, timestamp } = entry;
    const fields = mergeCoreFields({ _aws: undefined, level, message }, payload);
    const metricNames: string[] = [];
    for (const [k, v] of Object.entries(fields)) {
      if (k === '_aws' || k === 'level' || k === 'message' || typeof v !== 'number') continue;
      if (this.emfMetrics && !this.emfMetrics.has(k)) continue;
      if (metricNames.length < EMF_MAX_METRICS) metricNames.push(k);
    }
    fields['_aws'] = {
      Timestamp: timestamp ? new Date(timestamp).getTime() : Date.now(),
      CloudWatchMetrics:
        metricNames.length > 0
          ? [
              {
                Namespace: this.emfNamespace,
                Dimensions: [['level']],
                Metrics: metricNames.map((n) => ({ Name: n, Unit: 'None' })),
              },
            ]
          : [],
    };
    return stringifyForLog(fields);
  }

  private async putLogEvents(events: CwLogEvent[]): Promise<void> {
    await this.ensureStream();
    const logEvents = [...events].sort((a, b) => a.timestamp - b.timestamp);
    try {
      await this.call('PutLogEvents', {
        logGroupName: this.logGroupName,
        logStreamName: this.logStreamName,
        logEvents,
      });
    } catch (err) {
      const type = awsErrorType(err);
      if (type === 'DataAlreadyAcceptedException') return;
      if (type === 'ResourceNotFoundException') this.streamReady = false;
      if (type === 'ExpiredTokenException') this.credentials.invalidate();
      throw err;
    }
  }

  private async ensureStream(): Promise<void> {
    if (this.streamReady) return;
    try {
      await this.call('CreateLogGroup', { logGroupName: this.logGroupName });
    } catch (err) {
      if (awsErrorType(err) === 'ExpiredTokenException') this.credentials.invalidate();
      if (!(err instanceof HttpError)) throw err;
      if (awsErrorType(err) !== 'ResourceAlreadyExistsException') {
        internalWarn(`CloudWatchTransport: CreateLogGroup failed, continuing (${err.message})`);
      }
    }
    try {
      await this.call('CreateLogStream', {
        logGroupName: this.logGroupName,
        logStreamName: this.logStreamName,
      });
    } catch (err) {
      if (awsErrorType(err) !== 'ResourceAlreadyExistsException') throw err;
    }
    this.streamReady = true;
  }

  private async call(action: string, payload: Record<string, unknown>): Promise<void> {
    const credentials = await this.credentials.get();
    const body = stringifyForLog(payload);
    const { host } = this.endpoint;
    const headers = signV4({
      method: 'POST',
      path: '/',
      headers: {
        host,
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': `Logs_20140328.${action}`,
      },
      body,
      region: this.region,
      service: 'logs',
      credentials,
    });
    await httpRequest({
      url: this.endpoint,
      headers,
      body,
      timeoutMs: this.requestTimeoutMs,
      label: `CloudWatch ${action}`,
      secrets: () => [
        ...this.credentials.secretValues(),
        headers['authorization'],
        headers['x-amz-security-token'],
        ...urlSecrets(this.endpoint),
      ],
    });
  }
}
