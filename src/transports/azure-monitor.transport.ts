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

import * as https from 'node:https';
import * as url from 'node:url';

import type { IAsyncTransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';

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

  private batch: TransportLogEntry[] = [];
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

    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.flushInterval);
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  write(entry: TransportLogEntry): void {
    this.batch.push(entry);
    if (this.batch.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  async flush(): Promise<void> {
    if (this.batch.length === 0) return;
    const entries = this.batch.splice(0, this.batchSize);
    try {
      await this.sendEntries(entries);
    } catch (err) {
      internalError('AzureMonitorTransport flush error', err);
      this.batch.unshift(...entries);
    }
  }

  private toAzureRecord(entry: TransportLogEntry): Record<string, unknown> {
    return {
      TimeGenerated: entry.timestamp ?? new Date().toISOString(),
      SeverityLevel: SEVERITY_MAP[entry.level.toLowerCase()] ?? 1,
      Message: entry.message,
      AppName: entry.appName,
      Context: entry.context ?? '',
      TraceId: entry.traceId ?? '',
      Properties: JSON.stringify(entry.data ?? {}),
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

    return new Promise<string | null>((resolve, reject) => {
      const reqUrl = url.parse(
        `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`
      );
      const req = https.request(
        {
          hostname: reqUrl.hostname,
          path: reqUrl.path,
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (res) => {
          let raw = '';
          res.on('data', (c: Buffer) => (raw += c.toString()));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(raw) as { access_token?: string; expires_in?: number };
              if (parsed.access_token) {
                this.accessToken = parsed.access_token;
                this.tokenExpiry = Date.now() + (parsed.expires_in ?? 3600) * 1000 - 60_000;
                resolve(this.accessToken);
              } else {
                resolve(null);
              }
            } catch {
              resolve(null);
            }
          });
        }
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  private async sendEntries(entries: TransportLogEntry[]): Promise<void> {
    const token = await this.getAccessToken();
    if (!token) return;

    const records = entries.map((e) => this.toAzureRecord(e));
    const body = JSON.stringify(records);
    const reqUrl = url.parse(
      `${this.endpoint}/dataCollectionRules/${this.ruleId}/streams/${this.streamName}?api-version=2023-01-01`
    );

    return new Promise<void>((resolve, reject) => {
      const req = https.request(
        {
          hostname: reqUrl.hostname,
          path: reqUrl.path,
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (res) => {
          let raw = '';
          res.on('data', (c: Buffer) => (raw += c.toString()));
          res.on('end', () => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve();
            } else {
              reject(new Error(`Azure Monitor API returned ${res.statusCode}: ${raw}`));
            }
          });
        }
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }
}
