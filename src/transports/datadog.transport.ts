import { promisify } from 'node:util';
import { gzip } from 'node:zlib';

import type { DataDogTransportConfig, TransportLogEntry } from '../types/transport.types';
import { internalError } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';
import type { AnalyticsMetric } from './analytics.transport';
import { AnalyticsTransport, PartialBatchError } from './analytics.transport';
import { protectSecrets } from './secret-config';

const gzipAsync = promisify(gzip);

const MAX_LOGS_PER_REQUEST = 1000;
const MAX_LOGS_PAYLOAD_BYTES = 5_000_000;
const MAX_LOG_BYTES = 1_000_000;
const MAX_TRUNCATED_MESSAGE_CHARS = 150_000;

const TRUNCATED_LOG_KEYS = [
  'ddsource',
  'ddtags',
  'hostname',
  'service',
  'status',
  'timestamp',
  'level',
  'context',
  'traceId',
  'appName',
  'environment',
  'env',
  'version',
  'logger',
  'dd.trace_id',
  'dd.span_id',
];

const STATUS_MAP: Record<string, string> = {
  fatal: 'critical',
  critical: 'critical',
  error: 'error',
  warn: 'warn',
  warning: 'warn',
  info: 'info',
  debug: 'debug',
  trace: 'debug',
  verbose: 'debug',
};

const MAX_UINT64 = (1n << 64n) - 1n;
const DASHED_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]+$/i;
const DIGITS = /^\d+$/;

/**
 * Datadog correlates on a decimal 64-bit id. Accepts:
 * - a dashed UUID (logixia's default trace id): dashes stripped, then 32-hex;
 * - 32 hex chars (W3C trace id) or 16 hex chars containing a-f: low 64 bits as decimal;
 * - an all-digit string: already decimal (dd-trace's native format), passed through.
 * An all-digit string is ambiguous when it is 16 or 32 long: 32 is read as hex (a
 * decimal id has at most 20 digits), 16 is read as decimal.
 * Anything else yields the raw string for trace ids (`passthrough`) and nothing for span ids.
 */
function toDatadogId(id: unknown, passthrough: boolean): string | undefined {
  if (typeof id !== 'string' || id === '') return undefined;
  const fallback = passthrough ? id : undefined;
  const compact = DASHED_UUID.test(id) ? id.replaceAll('-', '') : id;
  const isHexId = HEX.test(compact) && (compact.length === 32 || compact.length === 16);
  if (DIGITS.test(compact) && compact.length !== 32) {
    const value = BigInt(compact);
    return value <= MAX_UINT64 ? value.toString() : fallback;
  }
  if (isHexId) return BigInt(`0x${compact.slice(-16)}`).toString();
  return fallback;
}

/** Datadog tags: no commas or whitespace, lowercase, at most 200 chars. */
function tag(key: string, value: string): string {
  return `${key}:${value}`
    .replaceAll(/[\s,]+/g, '_')
    .toLowerCase()
    .slice(0, 200);
}

/**
 * Sends log entries and metrics to Datadog via the Logs (v2) and Metrics HTTP APIs.
 *
 * The API key is transmitted via the `DD-API-KEY` request header — never in the URL.
 *
 * @example
 * transports: { datadog: { apiKey: process.env.DD_API_KEY, service: 'api', env: 'production' } }
 */
export class DataDogTransport extends AnalyticsTransport {
  private datadogConfig: DataDogTransportConfig;
  private baseUrl: string;
  private logsUrl: string;
  private metricsUrl: string;

  constructor(config: DataDogTransportConfig) {
    super('datadog', config);
    this.datadogConfig = config;

    // Set URLs based on site configuration
    const site = config.site || 'datadoghq.com';
    this.baseUrl = `https://api.${site}`;
    this.logsUrl = `https://http-intake.logs.${site}`;
    this.metricsUrl = `https://api.${site}`;
    protectSecrets(this, ['datadogConfig']);
  }

  protected async initialize(): Promise<void> {
    try {
      // Validate required configuration
      if (!this.datadogConfig.apiKey) {
        throw new Error('DataDog API key is required');
      }
      this.isReady = true;
    } catch (error) {
      internalError('DataDog transport initialization failed', error);
      throw error;
    }
  }

  protected async sendEntry(entry: TransportLogEntry): Promise<void> {
    await this.sendBatch([entry]);
  }

  /**
   * Logs go first, chunk by chunk; metrics follow once every log chunk is out.
   * A failure part-way throws PartialBatchError naming only the entries that were
   * not delivered, so a retry never re-posts a chunk Datadog already accepted.
   */
  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    if (this.datadogConfig.enableLogs !== false) {
      await this.sendLogBatch(entries);
    }

    if (this.datadogConfig.enableMetrics) {
      try {
        await this.sendMetricBatch(entries);
      } catch (error) {
        if (this.datadogConfig.enableLogs === false) throw error;
        // Logs are already delivered; retrying would duplicate them.
        throw new PartialBatchError((error as Error).message, [], { cause: error });
      }
    }
  }

  protected async cleanup(): Promise<void> {
    // DataDog doesn't require explicit cleanup
  }

  private async sendLogBatch(entries: TransportLogEntry[]): Promise<void> {
    const items = entries.map((entry) => ({ entry, json: this.serializeLog(entry) }));

    // API key is sent via DD-API-KEY header inside makeLogsRequest — never put it in the URL
    // so it cannot be leaked through error messages, access logs, or network traces.
    const chunks = this.chunkLogs(items);
    for (let i = 0; i < chunks.length; i += 1) {
      const chunk = chunks[i]!;
      try {
        await this.makeLogsRequest('/api/v2/logs', `[${chunk.map((item) => item.json).join(',')}]`);
      } catch (error) {
        if (i === 0) throw error;
        const unsent = chunks.slice(i).flatMap((c) => c.map((item) => item.entry));
        throw new PartialBatchError((error as Error).message, unsent, { cause: error });
      }
    }
  }

  /** Splits into requests of at most 1000 entries and about 5MB of JSON. */
  private chunkLogs(items: { entry: TransportLogEntry; json: string }[]) {
    const chunks: { entry: TransportLogEntry; json: string }[][] = [];
    let current: { entry: TransportLogEntry; json: string }[] = [];
    let currentBytes = 2;
    for (const item of items) {
      const bytes = Buffer.byteLength(item.json) + 1;
      if (
        current.length > 0 &&
        (current.length >= MAX_LOGS_PER_REQUEST || currentBytes + bytes > MAX_LOGS_PAYLOAD_BYTES)
      ) {
        chunks.push(current);
        current = [];
        currentBytes = 2;
      }
      current.push(item);
      currentBytes += bytes;
    }
    if (current.length > 0) chunks.push(current);
    return chunks;
  }

  /** Serializes once. A log over 1MB keeps its identity and correlation fields but loses its attributes and most of its message. */
  private serializeLog(entry: TransportLogEntry): string {
    const log = this.transformToDataDogLog(entry);
    const json = stringifyForLog(log);
    if (Buffer.byteLength(json) <= MAX_LOG_BYTES) return json;
    const kept: Record<string, unknown> = {};
    for (const key of TRUNCATED_LOG_KEYS) {
      if (log[key] !== undefined) kept[key] = log[key];
    }
    kept['message'] = String(log['message']).slice(0, MAX_TRUNCATED_MESSAGE_CHARS);
    kept['truncated'] = true;
    return stringifyForLog(kept);
  }

  private async sendMetric(entry: TransportLogEntry): Promise<void> {
    await this.sendMetricBatch([entry]);
  }

  private async sendMetricBatch(entries: TransportLogEntry[]): Promise<void> {
    const metrics = entries.map((entry) => this.transformToDataDogMetric(entry));

    const payload = {
      series: metrics,
    };

    await this.makeMetricsRequest('/api/v1/series', payload);
  }

  private transformToDataDogLog(entry: TransportLogEntry): Record<string, unknown> {
    const transformed = this.transformEntry(entry);
    const service = this.datadogConfig.service || 'logixia';
    const env = this.datadogConfig.env || 'production';
    const version = this.datadogConfig.version;
    const tags = [
      tag('env', env),
      tag('service', service),
      ...(version ? [tag('version', version)] : []),
    ];
    const spanId = toDatadogId(entry.data?.['spanId'] ?? entry.data?.['span_id'], false);
    const traceId = toDatadogId(entry.traceId, true);

    return {
      ...transformed,
      ddsource: 'nodejs',
      ddtags: tags.join(','),
      hostname: this.getHostname(),
      service,
      status: this.mapLogLevel(entry.level),
      message: entry.message,
      env,
      version,
      logger: { name: 'logixia', thread_name: 'main' },
      ...(traceId && { 'dd.trace_id': traceId }),
      ...(traceId && spanId && { 'dd.span_id': spanId }),
    };
  }

  protected override reservedKeys(): readonly string[] {
    return [
      'status',
      'ddtags',
      'ddsource',
      'hostname',
      'service',
      'version',
      'env',
      'logger',
      // Datadog reserved attributes (host is the hostname alias, source the ddsource alias).
      'host',
      'source',
      'dd.trace_id',
      'dd.span_id',
    ];
  }

  private transformToDataDogMetric(entry: TransportLogEntry): Record<string, unknown> {
    return {
      // TODO(v2): rename to logixia.logs.* — kept as logitron.logs.* so existing
      // Datadog dashboards and monitors keep resolving. Maintainers decide when to break them.
      metric: `logitron.logs.${entry.level}`,
      points: [[Math.floor(entry.timestamp.getTime() / 1000), 1]],
      type: 'count',
      host: this.getHostname(),
      tags: [
        tag('level', entry.level),
        tag('service', this.datadogConfig.service || 'logixia'),
        tag('env', this.datadogConfig.env || 'production'),
        ...(entry.context ? [tag('context', entry.context)] : []),
        ...(entry.appName ? [tag('app', entry.appName)] : []),
      ],
    };
  }

  private mapLogLevel(level: string): string {
    return STATUS_MAP[level.toLowerCase()] || 'info';
  }

  private async makeLogsRequest(endpoint: string, json: string): Promise<void> {
    const url = `${this.logsUrl}${endpoint}`;

    try {
      const compress = this.datadogConfig.compress === true;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
          ...(compress && { 'Content-Encoding': 'gzip' }),
        },
        body: compress ? await gzipAsync(json) : json,
      });

      if (!response.ok) {
        throw new Error(`DataDog Logs API error: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      throw new Error(`Failed to send logs to DataDog: ${(error as Error).message}`, {
        cause: error,
      });
    }
  }

  private async makeMetricsRequest(endpoint: string, data: unknown): Promise<void> {
    const url = `${this.metricsUrl}${endpoint}`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
        },
        body: stringifyForLog(data),
      });

      if (!response.ok) {
        throw new Error(`DataDog Metrics API error: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      throw new Error(`Failed to send metrics to DataDog: ${(error as Error).message}`, {
        cause: error,
      });
    }
  }

  private getHostname(): string {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      return require('node:os').hostname() as string;
    } catch {
      return 'unknown';
    }
  }

  // Public methods for additional DataDog functionality
  public async sendCustomMetric(metric: AnalyticsMetric): Promise<void> {
    const payload = {
      series: [
        {
          metric: metric.name,
          points: [[Math.floor((metric.timestamp || new Date()).getTime() / 1000), metric.value]],
          type: 'gauge',
          host: this.getHostname(),
          tags: Object.entries(metric.tags || {}).map(([key, value]) => `${key}:${value}`),
        },
      ],
    };

    await this.makeMetricsRequest('/api/v1/series', payload);
  }

  public async sendEvent(title: string, text: string, tags: string[] = []): Promise<void> {
    const payload = {
      title,
      text,
      date_happened: Math.floor(Date.now() / 1000),
      priority: 'normal',
      tags: [
        `service:${this.datadogConfig.service || 'logixia'}`,
        `env:${this.datadogConfig.env || 'production'}`,
        ...tags,
      ],
      source_type_name: 'logixia',
    };

    const url = `${this.baseUrl}/api/v1/events`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
        },
        body: stringifyForLog(payload),
      });

      if (!response.ok) {
        throw new Error(`DataDog Events API error: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      throw new Error(`Failed to send event to DataDog: ${(error as Error).message}`, {
        cause: error,
      });
    }
  }
}
