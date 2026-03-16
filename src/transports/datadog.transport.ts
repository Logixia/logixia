import type { DataDogTransportConfig, TransportLogEntry } from '../types/transport.types';
import { internalError } from '../utils/internal-log';
import type { AnalyticsMetric } from './analytics.transport';
import { AnalyticsTransport } from './analytics.transport';

/**
 * Sends log entries and metrics to Datadog via the Logs and Metrics HTTP APIs.
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

      // Test connection
      await this.testConnection();
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

    // Send trace if enabled and trace ID exists
    if (this.datadogConfig.enableTraces && entry.traceId) {
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
    if (this.datadogConfig.enableTraces) {
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
    const logs = entries.map((entry) => this.transformToDataDogLog(entry));

    const payload = {
      logs: logs,
    };

    // API key is sent via DD-API-KEY header inside makeLogsRequest — never put it in the URL
    // so it cannot be leaked through error messages, access logs, or network traces.
    await this.makeLogsRequest('/v1/input', payload);
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

    return {
      timestamp: entry.timestamp.toISOString(),
      level: this.mapLogLevel(entry.level),
      message: entry.message,
      service: this.datadogConfig.service || 'logitron',
      version: this.datadogConfig.version,
      env: this.datadogConfig.env || 'production',
      logger: {
        name: 'logitron',
        thread_name: 'main',
      },
      ...transformed,
      // Add DataDog specific fields
      'dd.trace_id': entry.traceId,
      'dd.span_id': this.generateSpanId(),
      host: this.getHostname(),
      source: 'nodejs',
    };
  }

  private transformToDataDogMetric(entry: TransportLogEntry): Record<string, unknown> {
    return {
      metric: `logitron.logs.${entry.level}`,
      points: [[Math.floor(entry.timestamp.getTime() / 1000), 1]],
      type: 'count',
      host: this.getHostname(),
      tags: [
        `level:${entry.level}`,
        `service:${this.datadogConfig.service || 'logitron'}`,
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
      service: this.datadogConfig.service || 'logitron',
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
    const levelMap: Record<string, string> = {
      error: 'error',
      warn: 'warn',
      warning: 'warn',
      info: 'info',
      debug: 'debug',
      trace: 'trace',
      verbose: 'debug',
    };

    return levelMap[level.toLowerCase()] || 'info';
  }

  private async makeLogsRequest(endpoint: string, data: unknown): Promise<void> {
    const url = `${this.logsUrl}${endpoint}`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
        },
        body: JSON.stringify(data),
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
        body: JSON.stringify(data),
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

  private async testConnection(): Promise<void> {
    // Test with a simple metric
    const testMetric = {
      series: [
        {
          metric: 'logitron.test',
          points: [[Math.floor(Date.now() / 1000), 1]],
          type: 'count',
          host: this.getHostname(),
          tags: ['test:true'],
        },
      ],
    };

    await this.makeMetricsRequest('/api/v1/series', testMetric);
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
        `service:${this.datadogConfig.service || 'logitron'}`,
        `env:${this.datadogConfig.env || 'production'}`,
        ...tags,
      ],
      source_type_name: 'logitron',
    };

    const url = `${this.baseUrl}/api/v1/events`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
        },
        body: JSON.stringify(payload),
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
