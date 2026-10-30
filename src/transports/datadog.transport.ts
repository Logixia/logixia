import { gzipSync } from 'node:zlib';

import type { DataDogTransportConfig, TransportLogEntry } from '../types/transport.types';
import { internalError } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';
import type { AnalyticsMetric } from './analytics.transport';
import { AnalyticsTransport } from './analytics.transport';

const MAX_LOGS_PER_REQUEST = 1000;
const MAX_LOGS_PAYLOAD_BYTES = 5_000_000;
const MAX_LOG_BYTES = 1_000_000;
const MAX_TRUNCATED_MESSAGE_CHARS = 150_000;

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

/** Datadog correlates on the low 64 bits of an id, written as a decimal string. */
function toDatadogId(id: unknown, wide: boolean): string | undefined {
  if (typeof id !== 'string' || id === '') return undefined;
  const hex = /^[0-9a-f]+$/i;
  if (!hex.test(id) || (wide ? id.length > 32 : id.length > 16)) return wide ? id : undefined;
  return BigInt(`0x${id.slice(-16)}`).toString();
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
    const promises: Promise<void>[] = [];

    // Send log if enabled
    if (this.datadogConfig.enableLogs !== false) {
      promises.push(this.sendLog(entry));
    }

    // Send metric if enabled
    if (this.datadogConfig.enableMetrics) {
      promises.push(this.sendMetric(entry));
    }

    // Trace correlation rides on the log's dd.trace_id, so a trace-only send is
    // needed only when logs are off; otherwise the entry would be posted twice.
    if (
      this.datadogConfig.enableTraces &&
      this.datadogConfig.enableLogs === false &&
      entry.traceId
    ) {
      promises.push(this.sendTrace(entry));
    }

    await Promise.all(promises);
  }

  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    const promises: Promise<void>[] = [];

    // Batch logs
    if (this.datadogConfig.enableLogs !== false) {
      promises.push(this.sendLogBatch(entries));
    }

    // Batch metrics
    if (this.datadogConfig.enableMetrics) {
      promises.push(this.sendMetricBatch(entries));
    }

    // Batch traces
    if (this.datadogConfig.enableTraces && this.datadogConfig.enableLogs === false) {
      const entriesWithTraces = entries.filter((e) => e.traceId);
      if (entriesWithTraces.length > 0) {
        promises.push(this.sendTraceBatch(entriesWithTraces));
      }
    }

    await Promise.all(promises);
  }

  protected async cleanup(): Promise<void> {
    // DataDog doesn't require explicit cleanup
  }

  private async sendLog(entry: TransportLogEntry): Promise<void> {
    await this.sendLogBatch([entry]);
  }

  private async sendLogBatch(entries: TransportLogEntry[]): Promise<void> {
    const logs = entries.map((entry) => this.fitLog(this.transformToDataDogLog(entry)));

    // API key is sent via DD-API-KEY header inside makeLogsRequest — never put it in the URL
    // so it cannot be leaked through error messages, access logs, or network traces.
    for (const chunk of this.chunkLogs(logs)) {
      await this.makeLogsRequest('/api/v2/logs', chunk);
    }
  }

  /** Splits into requests of at most 1000 entries and about 5MB of JSON. */
  private chunkLogs(logs: Record<string, unknown>[]): Record<string, unknown>[][] {
    const chunks: Record<string, unknown>[][] = [];
    let current: Record<string, unknown>[] = [];
    let currentBytes = 2;
    for (const log of logs) {
      const bytes = Buffer.byteLength(stringifyForLog(log)) + 1;
      if (
        current.length > 0 &&
        (current.length >= MAX_LOGS_PER_REQUEST || currentBytes + bytes > MAX_LOGS_PAYLOAD_BYTES)
      ) {
        chunks.push(current);
        current = [];
        currentBytes = 2;
      }
      current.push(log);
      currentBytes += bytes;
    }
    if (current.length > 0) chunks.push(current);
    return chunks;
  }

  /** A log over 1MB is cut down to its core fields and a truncated message. */
  private fitLog(log: Record<string, unknown>): Record<string, unknown> {
    if (Buffer.byteLength(stringifyForLog(log)) <= MAX_LOG_BYTES) return log;
    const { message, ddsource, ddtags, hostname, service, status, timestamp } = log;
    return {
      ddsource,
      ddtags,
      hostname,
      service,
      status,
      timestamp,
      message: String(message).slice(0, MAX_TRUNCATED_MESSAGE_CHARS),
      truncated: true,
    };
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

  private async sendTrace(entry: TransportLogEntry): Promise<void> {
    // DataDog traces are typically sent via the trace agent
    // For simplicity, we'll log this as a structured log with trace information
    await this.sendLog(entry);
  }

  private async sendTraceBatch(entries: TransportLogEntry[]): Promise<void> {
    // For batch traces, send as structured logs with trace information
    await this.sendLogBatch(entries);
  }

  private transformToDataDogLog(entry: TransportLogEntry): Record<string, unknown> {
    const transformed = this.transformEntry(entry);
    const service = this.datadogConfig.service || 'logixia';
    const env = this.datadogConfig.env || 'production';
    const version = this.datadogConfig.version;
    const tags = [`env:${env}`, `service:${service}`, ...(version ? [`version:${version}`] : [])];
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
        `level:${entry.level}`,
        `service:${this.datadogConfig.service || 'logixia'}`,
        `env:${this.datadogConfig.env || 'production'}`,
        ...(entry.context ? [`context:${entry.context}`] : []),
        ...(entry.appName ? [`app:${entry.appName}`] : []),
      ],
    };
  }

  private transformToDataDogTrace(entry: TransportLogEntry): Record<string, unknown> {
    return {
      trace_id: entry.traceId,
      span_id: this.generateSpanId(),
      parent_id: null,
      name: 'log.entry',
      service: this.datadogConfig.service || 'logixia',
      resource: entry.message,
      type: 'log',
      start: entry.timestamp.getTime() * 1000000, // nanoseconds
      duration: 1000000, // 1ms in nanoseconds
      meta: {
        'log.level': entry.level,
        'log.message': entry.message,
        ...(entry.context && { 'log.context': entry.context }),
        ...(entry.data &&
          Object.keys(entry.data).reduce(
            (acc, key) => {
              acc[`log.${key}`] = String(entry.data![key]);
              return acc;
            },
            {} as Record<string, string>
          )),
      },
      metrics: {
        _sampling_priority_v1: 1,
      },
    };
  }

  private mapLogLevel(level: string): string {
    return STATUS_MAP[level.toLowerCase()] || 'info';
  }

  private async makeLogsRequest(endpoint: string, data: unknown): Promise<void> {
    const url = `${this.logsUrl}${endpoint}`;

    try {
      const json = stringifyForLog(data);
      const compress = this.datadogConfig.compress === true;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
          ...(compress && { 'Content-Encoding': 'gzip' }),
        },
        body: compress ? gzipSync(json) : json,
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

  private generateSpanId(): string {
    // eslint-disable-next-line sonarjs/pseudo-random -- non-security span ID generation
    return Math.floor(Math.random() * 0xffffffffffff).toString(16);
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
