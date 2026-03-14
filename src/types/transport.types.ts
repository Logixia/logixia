// ── Transport retry / failover ─────────────────────────────────────────────────

/**
 * Per-transport retry & failover configuration.
 *
 * @example
 * ```ts
 * retry: { maxRetries: 3, backoff: 'exponential', delay: 500 }
 * fallback: myLocalFileTransport
 * ```
 */
export interface TransportRetryConfig {
  /** Maximum number of retry attempts after the first failure. Default: 0 (no retry). */
  maxRetries?: number;
  /** Backoff strategy between retries. Default: 'exponential'. */
  backoff?: 'fixed' | 'linear' | 'exponential';
  /** Base delay (ms) between retries. Default: 500. */
  delay?: number;
  /** Maximum delay cap (ms) when using exponential backoff. Default: 30_000. */
  maxDelay?: number;
  /**
   * Fallback transport to write to when all retries are exhausted.
   * Typically a local FileTransport acting as a dead-letter queue.
   */
  fallback?: ITransport;
  /** Called when all retries are exhausted (after fallback, if any). */
  onExhausted?: (error: Error, entry: TransportLogEntry) => void;
}

export interface ITransport {
  name: string;
  level?: string | undefined;
  write(entry: TransportLogEntry): Promise<void>;
  close?(): Promise<void>;
  /** Optional per-transport retry configuration. */
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

// File Transport Configuration
export interface FileTransportConfig {
  filename: string;
  dirname?: string;
  maxSize?: string | number; // '10MB', '1GB' or bytes
  maxFiles?: number;
  datePattern?: string; // 'YYYY-MM-DD', 'YYYY-MM-DD-HH'
  zippedArchive?: boolean;
  format?: 'json' | 'text' | 'csv';
  level?: string;
  batchSize?: number;
  flushInterval?: number;
  rotation?: RotationConfig;
}

// Database Transport Configuration
export interface DatabaseTransportConfig {
  type: 'mongodb' | 'postgresql' | 'mysql' | 'sqlite';
  connectionString?: string;
  host?: string;
  port?: number;
  database: string;
  table?: string; // For SQL databases
  collection?: string; // For MongoDB
  username?: string;
  password?: string;
  ssl?: boolean;
  level?: string;
  batchSize?: number;
  flushInterval?: number; // milliseconds
}

// Console Transport Configuration
export interface ConsoleTransportConfig {
  level?: string;
  colorize?: boolean;
  timestamp?: boolean;
  format?: 'json' | 'text';
}

// Analytics Transport Configuration
export interface AnalyticsTransportConfig {
  level?: string;
  apiKey: string;
  projectId?: string;
  endpoint?: string;
  batchSize?: number;
  flushInterval?: number;
  enableUserTracking?: boolean;
  enableEventTracking?: boolean;
  customProperties?: Record<string, unknown>;
}

// Mixpanel Transport Configuration
export interface MixpanelTransportConfig extends AnalyticsTransportConfig {
  token: string;
  distinct_id?: string;
  enableSuperProperties?: boolean;
  superProperties?: Record<string, unknown>;
}

// DataDog Transport Configuration
export interface DataDogTransportConfig extends AnalyticsTransportConfig {
  apiKey: string;
  site?: 'datadoghq.com' | 'datadoghq.eu' | 'us3.datadoghq.com' | 'us5.datadoghq.com';
  service?: string;
  version?: string;
  env?: string;
  enableMetrics?: boolean;
  enableLogs?: boolean;
  enableTraces?: boolean;
}

// Google Analytics Transport Configuration
export interface GoogleAnalyticsTransportConfig extends AnalyticsTransportConfig {
  measurementId: string;
  apiSecret: string;
  clientId?: string;
  enableEcommerce?: boolean;
  enableEnhancedMeasurement?: boolean;
}

// Segment Transport Configuration
export interface SegmentTransportConfig extends AnalyticsTransportConfig {
  writeKey: string;
  dataPlaneUrl?: string;
  enableBatching?: boolean;
  maxBatchSize?: number;
  flushAt?: number;
  flushInterval?: number;
}

// Rotation Configuration
export interface RotationConfig {
  // Time-based rotation
  interval?: '1h' | '6h' | '12h' | '1d' | '1w' | '1m' | '1y';

  // Size-based rotation
  maxSize?: string | number; // '10MB', '100MB', '1GB'

  // File management
  maxFiles?: number;
  compress?: boolean;

  // Custom rotation function
  shouldRotate?: (currentFile: string, stats: FileStats) => boolean;
}

export interface FileStats {
  size: number;
  created: Date;
  modified: Date;
}

// Transport Factory Configuration
export interface TransportConfig {
  console?: ConsoleTransportConfig;
  file?: FileTransportConfig | FileTransportConfig[];
  database?: DatabaseTransportConfig | DatabaseTransportConfig[];
  analytics?: AnalyticsConfig;
  custom?: ITransport[];
}

// Analytics Configuration
export interface AnalyticsConfig {
  mixpanel?: MixpanelTransportConfig | MixpanelTransportConfig[];
  datadog?: DataDogTransportConfig | DataDogTransportConfig[];
  googleAnalytics?: GoogleAnalyticsTransportConfig | GoogleAnalyticsTransportConfig[];
  segment?: SegmentTransportConfig | SegmentTransportConfig[];
}

// Async Transport for database operations
export interface IAsyncTransport extends ITransport {
  flush(): Promise<void>;
  isReady(): Promise<boolean>;
}

// Transport Events
export interface TransportEvents {
  log: (entry: TransportLogEntry) => void;
  error: (error: Error, transport: string) => void;
  rotate: (oldFile: string, newFile: string) => void;
  flush: (transport: string, count: number) => void;
}

// Batch Transport for high-performance scenarios
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
