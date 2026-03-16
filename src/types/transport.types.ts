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
  maxSize?: string | number;
  maxFiles?: number;
  datePattern?: string;
  zippedArchive?: boolean;
  format?: 'json' | 'text' | 'csv';
  level?: string;
  batchSize?: number;
  flushInterval?: number;
  rotation?: RotationConfig;
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
}

export interface ConsoleTransportConfig {
  level?: string;
  colorize?: boolean;
  timestamp?: boolean;
  format?: 'json' | 'text';
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
  customProperties?: Record<string, unknown>;
}

export interface MixpanelTransportConfig extends AnalyticsTransportConfig {
  token: string;
  distinct_id?: string;
  enableSuperProperties?: boolean;
  superProperties?: Record<string, unknown>;
}

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
