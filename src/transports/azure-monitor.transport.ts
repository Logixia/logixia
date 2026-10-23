/**
 * logixia — Azure Monitor / Application Insights transport
 *
 * Sends log entries to Azure Monitor via the Data Collection Rules (DCR) API
 * using the Logs Ingestion API (the modern replacement for the legacy HTTP
 * Data Collector API).
 *
 * Maps logixia levels to Application Insights severity levels:
 *   verbose → 0, debug → 1, info → 1, warn → 2, error → 3, critical → 4
 *
 * @example
 * ```ts
 * import { AzureMonitorTransport } from 'logixia';
 *
 * const logger = createLogger({
 *   transports: {
 *     azure: new AzureMonitorTransport({
 *       // Logs Ingestion API endpoint (from your DCR)
 *       endpoint: 'https://<dce>.ingest.monitor.azure.com',
 *       ruleId: 'dcr-xxxxxxxxxxxxxxxx',
 *       streamName: 'Custom-LogixiaLogs',
 *       // Client credentials (or managed identity via no-credential mode)
 *       tenantId: process.env.AZURE_TENANT_ID,
 *       clientId: process.env.AZURE_CLIENT_ID,
 *       clientSecret: process.env.AZURE_CLIENT_SECRET,
 *     }),
 *   },
 * });
 * ```
 */

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';
import {
  BatchBuffer,
  DEFAULT_MAX_BUFFER_SIZE,
  DEFAULT_REQUEST_TIMEOUT_MS,
  httpRequest,
} from './batch-buffer';

/**
 * Azure AD tenant IDs are either a GUID or a verified domain (e.g. `contoso.onmicrosoft.com`).
 * This pattern is deliberately permissive on structure but strict on character
 * set — it rejects the breakout characters (`/`, `@`, `:`, `?`, `#`, whitespace)
 * that would let a hostile config smuggle a different host, path, or query into
 * the OAuth token URL.
 */
const AZURE_TENANT_RE = /^[a-z0-9][a-z0-9.-]{1,253}$/i;

export interface AzureMonitorTransportConfig {
  /** DCE (Data Collection Endpoint) URL, e.g. `https://<name>.ingest.monitor.azure.com`. */
  endpoint: string;
  /** Data Collection Rule immutable ID (from Azure portal). */
  ruleId: string;
  /** Stream name defined in the DCR, e.g. `'Custom-LogixiaLogs_CL'`. */
  streamName: string;
  /** Azure AD tenant ID for OAuth2 client-credentials flow. */
  tenantId?: string;
  /** Azure AD app (service principal) client ID. */
  clientId?: string;
  /** Azure AD app client secret. */
  clientSecret?: string;
  /** Number of entries to batch. @default 200 */
  batchSize?: number;
  /** Flush interval in ms. @default 5000 */
  flushIntervalMs?: number;
  /** Abort a request that has not finished after this many ms. @default 10000 */
  requestTimeoutMs?: number;
  /** Max buffered entries; the oldest are dropped past this. @default 10000 */
  maxBufferSize?: number;
  level?: string;
}

const SEVERITY_MAP: Record<string, number> = {
  verbose: 0,
  trace: 0,
  debug: 1,
  info: 1,
  log: 1,
  warn: 2,
  warning: 2,
  error: 3,
  critical: 4,
  fatal: 4,
};

/**
 * Azure Monitor Logs Ingestion transport.
 */
export class AzureMonitorTransport implements IAsyncTransport {
  public readonly name = 'azure-monitor';
  public readonly batchSize: number;
  public readonly flushInterval: number;
  public readonly level: string | undefined;

  private readonly buffer: BatchBuffer<TransportLogEntry>;
  private readonly requestTimeoutMs: number;
  private flushTimer: NodeJS.Timeout | null = null;
  private accessToken: string | null = null;
  private tokenExpiry = 0;

  private readonly endpoint: string;
  private readonly ruleId: string;
  private readonly streamName: string;
  private readonly tenantId: string | undefined;
  private readonly clientId: string | undefined;
  private readonly clientSecret: string | undefined;

  constructor(config: AzureMonitorTransportConfig) {
    this.endpoint = config.endpoint.replace(/\/$/, '');
    this.ruleId = config.ruleId;
    this.streamName = config.streamName;
    this.tenantId = config.tenantId ?? process.env['AZURE_TENANT_ID'];
    this.clientId = config.clientId ?? process.env['AZURE_CLIENT_ID'];
    this.clientSecret = config.clientSecret ?? process.env['AZURE_CLIENT_SECRET'];
    this.batchSize = config.batchSize ?? 200;
    this.flushInterval = config.flushIntervalMs ?? 5000;
    this.level = config.level;
    this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.buffer = new BatchBuffer<TransportLogEntry>({
      name: 'AzureMonitorTransport',
      batchSize: this.batchSize,
      maxBufferSize: config.maxBufferSize ?? DEFAULT_MAX_BUFFER_SIZE,
      send: (entries) => this.sendEntries(entries),
    });

    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.flushInterval);
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  write(entry: TransportLogEntry): void {
    this.buffer.push(entry);
    this.buffer.flushIfFull();
  }

  flush(): Promise<void> {
    return this.buffer.flush();
  }

  /**
   * Flush remaining entries and stop the interval timer on shutdown. Without
   * this the manager's close() skipped the transport (close was undefined) and
   * buffered entries were lost on deploy. Waits for any in-flight send first.
   */
  async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.buffer.close();
  }

  private toAzureRecord(entry: TransportLogEntry): Record<string, unknown> {
    return {
      TimeGenerated: entry.timestamp ?? new Date().toISOString(),
      SeverityLevel: SEVERITY_MAP[entry.level.toLowerCase()] ?? 1,
      Message: entry.message,
      AppName: entry.appName,
      Context: entry.context ?? '',
      TraceId: entry.traceId ?? '',
      Properties: stringifyForLog(entry.data ?? {}),
    };
  }

  private async getAccessToken(): Promise<string | null> {
    if (this.accessToken && Date.now() < this.tokenExpiry) return this.accessToken;

    if (!this.tenantId || !this.clientId || !this.clientSecret) {
      internalWarn(
        'AzureMonitorTransport: missing credentials — set tenantId, clientId, clientSecret'
      );
      return null;
    }

    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: 'https://monitor.azure.com/.default',
    }).toString();

    const tenantId = this.tenantId;
    if (!AZURE_TENANT_RE.test(tenantId)) {
      internalWarn(
        `AzureMonitorTransport: refusing to request token — tenantId "${tenantId}" is not a valid GUID or domain`
      );
      return null;
    }

    const reqUrl = new URL(
      `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`
    );
    try {
      const res = await httpRequest({
        url: reqUrl,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        timeoutMs: this.requestTimeoutMs,
        label: 'Azure token request',
      });
      const parsed = JSON.parse(res.body) as { access_token?: string; expires_in?: number };
      if (!parsed.access_token) return null;
      this.accessToken = parsed.access_token;
      this.tokenExpiry = Date.now() + (parsed.expires_in ?? 3600) * 1000 - 60_000;
      return this.accessToken;
    } catch (err) {
      internalError('AzureMonitorTransport token request failed', err);
      return null;
    }
  }

  private async sendEntries(entries: TransportLogEntry[]): Promise<void> {
    const token = await this.getAccessToken();
    if (!token) throw new Error('AzureMonitorTransport: no access token available');

    const records = entries.map((e) => this.toAzureRecord(e));
    const body = stringifyForLog(records);
    let reqUrl: URL;
    try {
      // Build from the user-configured DCE endpoint; encodeURIComponent-ing the
      // ruleId/streamName stops a hostile config from smuggling extra path
      // segments or query params into the request.
      reqUrl = new URL(
        `dataCollectionRules/${encodeURIComponent(this.ruleId)}/streams/${encodeURIComponent(this.streamName)}?api-version=2023-01-01`,
        this.endpoint.endsWith('/') ? this.endpoint : `${this.endpoint}/`
      );
    } catch (error) {
      internalError(`AzureMonitorTransport: invalid endpoint "${this.endpoint}"`, error);
      return;
    }
    if (reqUrl.protocol !== 'https:') {
      internalError(`AzureMonitorTransport: endpoint must use https (got ${reqUrl.protocol})`);
      return;
    }

    await httpRequest({
      url: reqUrl,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body,
      timeoutMs: this.requestTimeoutMs,
      label: 'Azure Monitor API',
    });
  }
}
