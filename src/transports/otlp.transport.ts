/**
 * OTLP Logs transport — emit logixia logs as OpenTelemetry LogRecords.
 *
 * logixia already READS the active OTel span (the bridge injects traceId/spanId
 * into payloads). This transport closes the loop by EMITTING logs OUT in the
 * OTLP/HTTP JSON format to a collector, making logixia an OTel-Logs-native
 * source — logs land in any OTLP backend (Grafana Loki, OpenObserve, Better
 * Stack, Axiom, Datadog, SigNoz…) already correlated with traces.
 *
 * Dependency-free: builds the OTLP/HTTP JSON payload directly (no
 * @opentelemetry/* packages required — that JS API is still alpha), conforming
 * to the OTel logs data model: SeverityNumber (1–24), resource attributes
 * (service.name/version, deployment.environment), and TraceId/SpanId on each
 * record for correlation.
 *
 * @example
 * ```ts
 * transports: {
 *   custom: [ new OtlpLogTransport({
 *     url: 'http://localhost:4318/v1/logs',
 *     serviceName: 'api',
 *     headers: { 'x-api-key': process.env.OTLP_KEY! },
 *   }) ],
 * }
 * ```
 */

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';

export interface OtlpLogTransportConfig {
  /** OTLP/HTTP logs endpoint, e.g. `http://localhost:4318/v1/logs`. */
  url: string;
  /** Extra HTTP headers (auth, tenant, etc.). */
  headers?: Record<string, string>;
  /** `service.name` resource attribute. Default: 'logixia'. */
  serviceName?: string;
  /** `service.version` resource attribute. */
  serviceVersion?: string;
  /** `deployment.environment` resource attribute. */
  environment?: string;
  /** Extra resource attributes merged into the OTLP resource. */
  resourceAttributes?: Record<string, string | number | boolean>;
  /** Entries per batch / per POST. Default: 100. */
  batchSize?: number;
  /** Auto-flush interval (ms). Default: 5000. */
  flushIntervalMs?: number;
  level?: string;
}

/**
 * Map a logixia level name to an OTel SeverityNumber (1–24) and text.
 * Per the OTel logs SDK spec: TRACE=1, DEBUG=5, INFO=9, WARN=13, ERROR=17,
 * FATAL=21. Custom/unknown levels fall back to INFO (9).
 */
export function toOtelSeverity(level: string): { number: number; text: string } {
  switch (level.toLowerCase()) {
    case 'trace':
      return { number: 1, text: 'TRACE' };
    case 'verbose':
      return { number: 5, text: 'DEBUG' }; // verbose maps to DEBUG range
    case 'debug':
      return { number: 5, text: 'DEBUG' };
    case 'info':
      return { number: 9, text: 'INFO' };
    case 'warn':
    case 'warning':
      return { number: 13, text: 'WARN' };
    case 'error':
      return { number: 17, text: 'ERROR' };
    case 'fatal':
      return { number: 21, text: 'FATAL' };
    default:
      return { number: 9, text: 'INFO' };
  }
}

/** Coerce a JS value into an OTLP AnyValue. */
function toAnyValue(value: unknown): Record<string, unknown> {
  if (typeof value === 'string') return { stringValue: value };
  if (typeof value === 'boolean') return { boolValue: value };
  if (typeof value === 'number') {
    return Number.isInteger(value) ? { intValue: value } : { doubleValue: value };
  }
  if (typeof value === 'bigint') return { stringValue: value.toString() };
  if (value === null || value === undefined) return { stringValue: '' };
  // Objects/arrays → JSON string (kvlistValue would be richer but stringValue is
  // universally accepted and avoids deep recursion / circular issues here).
  try {
    return { stringValue: JSON.stringify(value) };
  } catch {
    return { stringValue: String(value) };
  }
}

/** Build the OTLP KeyValue attribute list from a flat record. */
function toAttributes(rec: Record<string, unknown>): Array<{ key: string; value: unknown }> {
  return Object.entries(rec).map(([key, value]) => ({ key, value: toAnyValue(value) }));
}

export class OtlpLogTransport implements IAsyncTransport {
  public readonly name = 'otlp';
  public readonly level: string | undefined;

  private readonly url: string;
  private readonly headers: Record<string, string>;
  private readonly batchSize: number;
  private readonly flushIntervalMs: number;
  private readonly resourceAttrs: Array<{ key: string; value: unknown }>;

  private batch: TransportLogEntry[] = [];
  private flushTimer: NodeJS.Timeout | null = null;

  constructor(config: OtlpLogTransportConfig) {
    this.url = config.url;
    this.headers = config.headers ?? {};
    this.batchSize = config.batchSize ?? 100;
    this.flushIntervalMs = config.flushIntervalMs ?? 5000;
    this.level = config.level;

    const resource: Record<string, unknown> = {
      'service.name': config.serviceName ?? 'logixia',
      ...(config.serviceVersion ? { 'service.version': config.serviceVersion } : {}),
      ...(config.environment ? { 'deployment.environment': config.environment } : {}),
      ...(config.resourceAttributes ?? {}),
    };
    this.resourceAttrs = toAttributes(resource);

    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.flushIntervalMs);
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  write(entry: TransportLogEntry): void {
    this.batch.push(entry);
    if (this.batch.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  /** Convert one entry into an OTLP LogRecord. */
  private toLogRecord(entry: TransportLogEntry): Record<string, unknown> {
    const sev = toOtelSeverity(entry.level);
    const tsNanos = String(entry.timestamp.getTime() * 1_000_000);

    const attrs: Record<string, unknown> = { ...(entry.data ?? {}) };
    if (entry.context !== undefined) attrs['context'] = entry.context;
    if (entry.appName !== undefined) attrs['app.name'] = entry.appName;
    if (entry.environment !== undefined) attrs['deployment.environment'] = entry.environment;

    const record: Record<string, unknown> = {
      timeUnixNano: tsNanos,
      observedTimeUnixNano: tsNanos,
      severityNumber: sev.number,
      severityText: sev.text,
      body: { stringValue: entry.message },
      attributes: toAttributes(attrs),
    };

    // Trace correlation: OTel expects 32-hex traceId / 16-hex spanId. Pass the
    // traceId through (collectors tolerate non-hex correlation ids via the
    // attribute too, but the dedicated field enables native trace-log linking).
    if (entry.traceId) {
      record['traceId'] = entry.traceId;
    }

    return record;
  }

  private buildPayload(entries: TransportLogEntry[]): string {
    return JSON.stringify({
      resourceLogs: [
        {
          resource: { attributes: this.resourceAttrs },
          scopeLogs: [
            {
              scope: { name: 'logixia' },
              logRecords: entries.map((e) => this.toLogRecord(e)),
            },
          ],
        },
      ],
    });
  }

  async flush(): Promise<void> {
    // Drain the WHOLE batch; splice() detaches synchronously so concurrent
    // writes are never sent twice, and looping empties everything on shutdown.
    while (this.batch.length > 0) {
      const entries = this.batch.splice(0, this.batchSize);
      try {
        await this.send(entries);
      } catch (err) {
        internalError('OtlpLogTransport flush error', err);
        this.batch.unshift(...entries);
        return;
      }
    }
  }

  private async send(entries: TransportLogEntry[]): Promise<void> {
    if (typeof fetch !== 'function') {
      internalWarn('OtlpLogTransport: global fetch unavailable — cannot export logs');
      return;
    }
    const res = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this.headers },
      body: this.buildPayload(entries),
    });
    if (!res.ok) {
      throw new Error(`OTLP export failed: HTTP ${res.status}`);
    }
  }

  async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    for (let attempt = 0; attempt < 3 && this.batch.length > 0; attempt += 1) {
      await this.flush();
    }
    if (this.batch.length > 0) {
      internalError(`OtlpLogTransport closing with ${this.batch.length} undelivered record(s)`);
    }
  }
}
