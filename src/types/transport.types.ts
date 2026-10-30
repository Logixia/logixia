// ── Transport retry / failover ─────────────────────────────────────────────────

/**
 * Per-transport retry & failover configuration.
 */
export interface TransportRetryConfig {
  maxRetries?: number;
  backoff?: 'fixed' | 'linear' | 'exponential';
  delay?: number;
  maxDelay?: number;
  fallback?: ITransport;
  onExhausted?: (error: Error, entry: TransportLogEntry) => void;
}

export interface ITransport {
  name: string;
  level?: string | undefined;
  /**
   * Optional predicate evaluated before writing. Return false to skip this
   * entry for this transport. Runs after the level check.
   */
  filter?: (entry: TransportLogEntry) => boolean;
  /**
   * Write a log entry. May return a Promise (async / cloud transports) or
   * void (sync / in-memory batch transports that flush on their own schedule).
   */
  write(entry: TransportLogEntry): void | Promise<void>;
  close?(): Promise<void>;
  retry?: TransportRetryConfig;
}

export interface TransportLogEntry {
  timestamp: Date;
  level: string;
  message: string;
  data?: Record<string, unknown>;
  context?: string;
  traceId?: string;
  appName?: string;
  environment?: string;
}

export interface FileTransportConfig {
  filename: string;
  dirname?: string;
  /** Rotate once the file would pass this size: bytes, or a string like '50MB' or '1GB'. */
  maxSize?: string | number;
  /** How many rotated files to keep; older ones are deleted. Unset keeps them all. */
  maxFiles?: number;
  /** Rotate when the date changes, e.g. 'YYYY-MM-DD' (daily) or 'YYYY-MM-DD-HH' (hourly). */
  datePattern?: string;
  /** Gzip rotated files. */
  zippedArchive?: boolean;
  /** Permission bits for log files, rotated and gzipped ones included. Default 0o600. */
  fileMode?: number;
  /** Permission bits for directories the transport creates. Default 0o700. */
  dirMode?: number;
  format?: 'json' | 'text' | 'csv';
  level?: string;
  batchSize?: number;
  flushInterval?: number;
  rotation?: RotationConfig;
  /**
   * Cap on entries held in memory that are not on disk yet, the batch being
   * written included. Default 10000; entries past it are handled per `queuePolicy`
   * and counted in the drop warning.
   */
  maxQueue?: number;
  /**
   * What to do when `maxQueue` is reached. `drop-oldest` discards the oldest
   * waiting entry, `drop-newest` discards the incoming one, `block` makes
   * `write()` wait for room. Default `drop-oldest`.
   */
  queuePolicy?: 'drop-oldest' | 'drop-newest' | 'block';
  filter?: (entry: TransportLogEntry) => boolean;
}

export interface DatabaseTransportConfig {
  type: 'mongodb' | 'postgresql' | 'mysql' | 'sqlite';
  connectionString?: string;
  host?: string;
  port?: number;
  database: string;
  table?: string;
  collection?: string;
  username?: string;
  password?: string;
  ssl?: boolean;
  level?: string;
  batchSize?: number;
  flushInterval?: number;
  filter?: (entry: TransportLogEntry) => boolean;
  /**
   * Most entries buffered in memory while the database is unreachable; past it
   * the oldest are dropped. Default 10000, never below `batchSize`.
   */
  maxBufferSize?: number;
}

export interface ConsoleTransportConfig {
  level?: string;
  colorize?: boolean;
  timestamp?: boolean;
  format?: 'json' | 'text';
  /**
   * Custom level → color name map injected from `levelOptions.colors`.
   * Allows the ConsoleTransport to colorize custom levels (e.g. kafka, mongo)
   * using the same colors the user configured on the logger.
   */
  levelColors?: Record<string, string>;
  filter?: (entry: TransportLogEntry) => boolean;
}

export interface AnalyticsTransportConfig {
  level?: string;
  apiKey: string;
  projectId?: string;
  endpoint?: string;
  batchSize?: number;
  flushInterval?: number;
  enableUserTracking?: boolean;
  enableEventTracking?: boolean;
  /**
   * Most entries held in memory while the provider is unreachable. Past it the
   * oldest entries are dropped and counted. Default 10000.
   */
  maxBufferSize?: number;
  customProperties?: Record<string, unknown>;
  filter?: (entry: TransportLogEntry) => boolean;
}

export interface MixpanelTransportConfig extends AnalyticsTransportConfig {
  token: string;
  distinct_id?: string;
  enableSuperProperties?: boolean;
  superProperties?: Record<string, unknown>;
}

export interface DataDogTransportConfig extends AnalyticsTransportConfig {
  apiKey: string;
  site?:
    | 'datadoghq.com'
    | 'datadoghq.eu'
    | 'us3.datadoghq.com'
    | 'us5.datadoghq.com'
    | 'ap1.datadoghq.com'
    | 'ddog-gov.com';
  /** Gzip log request bodies (`Content-Encoding: gzip`). Default false. */
  compress?: boolean;
  service?: string;
  version?: string;
  env?: string;
  enableMetrics?: boolean;
  enableLogs?: boolean;
  enableTraces?: boolean;
}

export interface GoogleAnalyticsTransportConfig extends AnalyticsTransportConfig {
  measurementId: string;
  apiSecret: string;
  clientId?: string;
  enableEcommerce?: boolean;
  enableEnhancedMeasurement?: boolean;
}

export interface SegmentTransportConfig extends AnalyticsTransportConfig {
  writeKey: string;
  dataPlaneUrl?: string;
  /** Payload field read as the Segment userId. Default 'userId'; only string values are used. */
  userIdField?: string;
  enableBatching?: boolean;
  maxBatchSize?: number;
  flushAt?: number;
  flushInterval?: number;
}

export interface RotationConfig {
  interval?: '1h' | '6h' | '12h' | '1d' | '1w' | '1m' | '1y';
  maxSize?: string | number;
  maxFiles?: number;
  compress?: boolean;
  /** Checked before each write; return true to rotate now. */
  shouldRotate?: (currentFile: string, stats: FileStats) => boolean;
}

export interface FileStats {
  size: number;
  created: Date;
  modified: Date;
}

export interface TransportConfig {
  console?: ConsoleTransportConfig;
  file?: FileTransportConfig | FileTransportConfig[];
  database?: DatabaseTransportConfig | DatabaseTransportConfig[];
  analytics?: AnalyticsConfig;
  custom?: ITransport[];
}

export interface AnalyticsConfig {
  mixpanel?: MixpanelTransportConfig | MixpanelTransportConfig[];
  datadog?: DataDogTransportConfig | DataDogTransportConfig[];
  googleAnalytics?: GoogleAnalyticsTransportConfig | GoogleAnalyticsTransportConfig[];
  segment?: SegmentTransportConfig | SegmentTransportConfig[];
}

export interface IAsyncTransport extends ITransport {
  flush(): Promise<void>;
  isReady?(): Promise<boolean>;
}

export interface TransportEvents {
  log: (entry: TransportLogEntry) => void;
  error: (error: Error, transport: string) => void;
  rotate: (oldFile: string, newFile: string) => void;
  flush: (transport: string, count: number) => void;
}

export interface IBatchTransport extends ITransport {
  readonly batchSize?: number;
  readonly flushInterval?: number;
  addToBatch(entry: TransportLogEntry): void;
  flush(): Promise<void>;
}

export type TransportType = 'console' | 'file' | 'database' | 'analytics' | 'custom';

export interface TransportMetrics {
  name: string;
  type: TransportType;
  logsWritten: number;
  errors: number;
  lastWrite: Date;
  averageWriteTime: number;
}
