/**
 * logixia — Metrics extraction → Prometheus
 *
 * Automatically extracts metrics from structured log fields and exposes them
 * in the Prometheus text exposition format (version 0.0.4).
 * No external dependency — the format is fully self-contained.
 *
 * Supported metric types:
 *   - `counter`   — incremented on each matching log entry
 *   - `histogram` — observes a numeric payload field per entry
 *   - `gauge`     — tracks the most recent numeric value of a payload field
 *
 * Usage:
 * ```ts
 * import { createMetricsPlugin } from 'logixia';
 *
 * const metrics = createMetricsPlugin({
 *   http_request_duration: {
 *     type: 'histogram',
 *     field: 'duration',
 *     labels: ['method', 'statusCode'],
 *     help: 'HTTP request duration in milliseconds',
 *   },
 *   error_count: {
 *     type: 'counter',
 *     levelFilter: 'error',
 *     labels: ['context'],
 *     help: 'Total error log entries',
 *   },
 *   active_connections: {
 *     type: 'gauge',
 *     field: 'connections',
 *     help: 'Current active connection count',
 *   },
 * });
 *
 * logger.use(metrics);                         // start collecting
 * app.get('/metrics', metrics.expressHandler()); // expose for Prometheus scrape
 * ```
 *
 * All metric names are automatically prefixed with `logixia_`.
 * Output follows https://prometheus.io/docs/instrumenting/exposition_formats/
 */

import type { IncomingMessage, ServerResponse } from 'node:http';

import type { LogixiaPlugin } from './plugin';
import type { LogEntry } from './types/index';

// ── Metric config types ───────────────────────────────────────────────────────

/**
 * Increment a counter on each matching log entry.
 *
 * @example Count every error entry, labelled by context:
 * ```ts
 * error_count: { type: 'counter', levelFilter: 'error', labels: ['context'] }
 * ```
 *
 * @example Count entries where payload.event === 'checkout':
 * ```ts
 * checkout_events: { type: 'counter', field: 'event', value: 'checkout' }
 * ```
 */
export interface CounterConfig {
  type: 'counter';
  /** Only increment when `entry.level` equals this value. Omit to count all entries. */
  levelFilter?: string;
  /**
   * Only increment when `entry.payload[field] === value`.
   * If omitted, every entry (matching `levelFilter`) is counted.
   */
  field?: string;
  value?: unknown;
  /** `entry.payload` fields used as Prometheus label dimensions. `'level'` is also valid. */
  labels?: string[];
  help?: string;
}

/**
 * Observe a numeric payload field and bucket it into a Prometheus histogram.
 *
 * @example Duration histogram labelled by HTTP method and status code:
 * ```ts
 * http_request_duration: {
 *   type: 'histogram',
 *   field: 'duration',
 *   labels: ['method', 'statusCode'],
 *   buckets: [10, 25, 50, 100, 250, 500, 1000],
 * }
 * ```
 */
export interface HistogramConfig {
  type: 'histogram';
  /** The `entry.payload` field containing the numeric value to observe. */
  field: string;
  /** `entry.payload` fields used as Prometheus label dimensions. */
  labels?: string[];
  help?: string;
  /**
   * Bucket upper bounds (inclusive). Sorted automatically.
   * Default: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
   */
  buckets?: number[];
}

/**
 * Track the most recent numeric value of a payload field as a gauge.
 *
 * @example Track live connection count:
 * ```ts
 * active_connections: { type: 'gauge', field: 'connections' }
 * ```
 */
export interface GaugeConfig {
  type: 'gauge';
  /** The `entry.payload` field containing the numeric value. */
  field: string;
  /** `entry.payload` fields used as Prometheus label dimensions. */
  labels?: string[];
  help?: string;
}

export type MetricConfig = CounterConfig | HistogramConfig | GaugeConfig;
export type MetricsMap = Record<string, MetricConfig>;

// ── Internal metric state ─────────────────────────────────────────────────────

interface CounterState {
  type: 'counter';
  values: Map<string, number>;
}

interface HistogramState {
  type: 'histogram';
  buckets: number[];
  /** Parallel arrays; index = bucket index; last entry = +Inf cumulative count */
  counts: Map<string, number[]>;
  sums: Map<string, number>;
  observations: Map<string, number>;
}

interface GaugeState {
  type: 'gauge';
  values: Map<string, number>;
}

type MetricState = CounterState | HistogramState | GaugeState;

// ── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_BUCKETS: readonly number[] = [
  1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000,
];

// ── Label helpers ─────────────────────────────────────────────────────────────

function buildLabelKey(config: MetricConfig, entry: LogEntry): string {
  const labelNames = config.labels ?? [];
  if (labelNames.length === 0) return '{}';
  const pairs: Record<string, string> = {};
  const payload = entry.payload ?? {};
  for (const name of labelNames) {
    const raw = name === 'level' ? entry.level : payload[name];
    pairs[name] = raw !== undefined && raw !== null ? String(raw) : '';
  }
  return JSON.stringify(pairs);
}

function renderLabels(labelKey: string): string {
  if (labelKey === '{}') return '';
  const obj = JSON.parse(labelKey) as Record<string, string>;
  const parts = Object.entries(obj).map(([k, v]) => `${k}="${escapeLabel(v)}"`);
  return `{${parts.join(',')}}`;
}

function escapeLabel(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

// ── MetricsPlugin ─────────────────────────────────────────────────────────────

/**
 * A logixia plugin that extracts Prometheus-compatible metrics from log entries.
 *
 * Implements `LogixiaPlugin` — pass directly to `logger.use()`:
 * ```ts
 * const metrics = new MetricsPlugin({ ... });
 * logger.use(metrics);
 * ```
 *
 * Or use the `createMetricsPlugin()` factory (preferred):
 * ```ts
 * const metrics = createMetricsPlugin({ ... });
 * logger.use(metrics);
 * ```
 */
export class MetricsPlugin implements LogixiaPlugin {
  public readonly name = 'logixia-metrics';

  private readonly map: MetricsMap;
  private readonly metricState = new Map<string, MetricState>();

  constructor(map: MetricsMap) {
    this.map = map;
    this.initAllState();
  }

  // ── LogixiaPlugin lifecycle ────────────────────────────────────────────────

  onInit(): void {
    // State is initialised in the constructor; nothing extra needed here.
  }

  onLog(entry: LogEntry): LogEntry {
    const payload = entry.payload ?? {};

    for (const [rawName, config] of Object.entries(this.map)) {
      const state = this.metricState.get(rawName);
      if (!state) continue;

      const labelKey = buildLabelKey(config, entry);

      if (config.type === 'counter' && state.type === 'counter') {
        // Level filter
        if (config.levelFilter && entry.level !== config.levelFilter) continue;
        // Field/value filter
        if (config.field !== undefined && payload[config.field] !== config.value) continue;
        state.values.set(labelKey, (state.values.get(labelKey) ?? 0) + 1);
      } else if (config.type === 'histogram' && state.type === 'histogram') {
        const raw = payload[config.field];
        if (raw === undefined || raw === null) continue;
        const val = Number(raw);
        if (Number.isNaN(val)) continue;

        // Initialise per-label arrays on first observation
        if (!state.counts.has(labelKey)) {
          state.counts.set(
            labelKey,
            Array.from<number>({ length: state.buckets.length + 1 }).fill(0)
          );
          state.sums.set(labelKey, 0);
          state.observations.set(labelKey, 0);
        }

        const bucketArr = state.counts.get(labelKey)!;
        for (let i = 0; i < state.buckets.length; i++) {
          if (val <= state.buckets[i]!) bucketArr[i]!++;
        }
        // The +Inf bucket (last slot) always increments
        bucketArr[state.buckets.length]!++;
        state.sums.set(labelKey, (state.sums.get(labelKey) ?? 0) + val);
        state.observations.set(labelKey, (state.observations.get(labelKey) ?? 0) + 1);
      } else if (config.type === 'gauge' && state.type === 'gauge') {
        const raw = payload[config.field];
        if (raw === undefined || raw === null) continue;
        const val = Number(raw);
        if (Number.isNaN(val)) continue;
        state.values.set(labelKey, val);
      }
    }

    // Always pass the entry through unchanged
    return entry;
  }

  // ── Output ─────────────────────────────────────────────────────────────────

  /**
   * Render all registered metrics in the Prometheus text exposition format
   * (version 0.0.4).
   *
   * All metric names are prefixed with `logixia_`.
   *
   * @example
   * ```
   * # HELP logixia_error_count Total error log entries
   * # TYPE logixia_error_count counter
   * logixia_error_count{context="OrderService"} 7
   * ```
   */
  render(): string {
    const lines: string[] = [];

    for (const [rawName, config] of Object.entries(this.map)) {
      const metricName = `logixia_${rawName}`;
      const state = this.metricState.get(rawName);
      if (!state) continue;

      const helpText = config.help ?? rawName.replace(/_/g, ' ');
      lines.push(`# HELP ${metricName} ${helpText}`);
      lines.push(`# TYPE ${metricName} ${config.type}`);

      if (state.type === 'counter') {
        if (state.values.size === 0) {
          lines.push(`${metricName} 0`);
        } else {
          for (const [labelKey, count] of state.values) {
            lines.push(`${metricName}${renderLabels(labelKey)} ${count}`);
          }
        }
      } else if (state.type === 'histogram') {
        for (const [labelKey, bucketCounts] of state.counts) {
          const labelSuffix = renderLabels(labelKey);
          const baseObj = labelKey === '{}' ? {} : (JSON.parse(labelKey) as Record<string, string>);

          // One line per finite bucket
          for (let i = 0; i < state.buckets.length; i++) {
            const leKey = JSON.stringify({ ...baseObj, le: String(state.buckets[i]) });
            lines.push(`${metricName}_bucket${renderLabels(leKey)} ${bucketCounts[i] ?? 0}`);
          }
          // +Inf bucket
          const infKey = JSON.stringify({ ...baseObj, le: '+Inf' });
          lines.push(
            `${metricName}_bucket${renderLabels(infKey)} ${bucketCounts[state.buckets.length] ?? 0}`
          );
          lines.push(`${metricName}_sum${labelSuffix} ${state.sums.get(labelKey) ?? 0}`);
          lines.push(`${metricName}_count${labelSuffix} ${state.observations.get(labelKey) ?? 0}`);
        }
      } else if (state.type === 'gauge') {
        if (state.values.size === 0) {
          lines.push(`${metricName} 0`);
        } else {
          for (const [labelKey, val] of state.values) {
            lines.push(`${metricName}${renderLabels(labelKey)} ${val}`);
          }
        }
      }
    }

    return `${lines.join('\n')}\n`;
  }

  /**
   * Reset all metric counters and observations back to zero.
   * Useful between test runs or on a scheduled reset interval.
   */
  reset(): void {
    this.metricState.clear();
    this.initAllState();
  }

  /**
   * Express route handler — call `app.get('/metrics', metrics.expressHandler())`.
   *
   * @example
   * ```ts
   * import express from 'express';
   * const app = express();
   * app.get('/metrics', metrics.expressHandler());
   * ```
   */
  expressHandler(): (
    req: unknown,
    res: { set(k: string, v: string): unknown; end(body: string): void }
  ) => void {
    return (_req, res) => {
      res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.end(this.render());
    };
  }

  /**
   * Raw Node.js `http` server handler.
   * Responds to `GET /metrics` with the Prometheus text payload.
   *
   * @example Start a dedicated metrics server on the standard port:
   * ```ts
   * import http from 'node:http';
   * const server = http.createServer(metrics.httpHandler());
   * server.listen(9464); // Prometheus default port for custom exporters
   * ```
   */
  httpHandler(): (req: IncomingMessage, res: ServerResponse) => void {
    return (req, res) => {
      const isMetricsPath = req.url === '/metrics' || req.url === '/metrics/';
      if (!isMetricsPath) {
        res.writeHead(404).end('Not found');
        return;
      }
      const body = this.render();
      res.writeHead(200, {
        'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
      });
      res.end(body);
    };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private initAllState(): void {
    for (const [rawName, config] of Object.entries(this.map)) {
      this.initSingleState(rawName, config);
    }
  }

  private initSingleState(rawName: string, config: MetricConfig): void {
    if (config.type === 'counter') {
      this.metricState.set(rawName, { type: 'counter', values: new Map() });
    } else if (config.type === 'histogram') {
      const buckets = [...(config.buckets ?? DEFAULT_BUCKETS)].sort((a, b) => a - b);
      this.metricState.set(rawName, {
        type: 'histogram',
        buckets,
        counts: new Map(),
        sums: new Map(),
        observations: new Map(),
      });
    } else {
      this.metricState.set(rawName, { type: 'gauge', values: new Map() });
    }
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create a `MetricsPlugin` from a metrics map and return it ready for
 * `logger.use()`.
 *
 * @example
 * ```ts
 * import { createMetricsPlugin } from 'logixia';
 *
 * const metrics = createMetricsPlugin({
 *   http_request_duration: {
 *     type: 'histogram',
 *     field: 'duration',
 *     labels: ['method', 'statusCode'],
 *     help: 'HTTP request duration in milliseconds',
 *   },
 *   error_count: {
 *     type: 'counter',
 *     levelFilter: 'error',
 *     labels: ['context'],
 *     help: 'Total error log entries',
 *   },
 * });
 *
 * logger.use(metrics);
 * app.get('/metrics', metrics.expressHandler());
 * ```
 */
export function createMetricsPlugin(map: MetricsMap): MetricsPlugin {
  return new MetricsPlugin(map);
}
