import {
  TransportLogEntry,
  GoogleAnalyticsTransportConfig,
} from "../types/transport.types";
import { AnalyticsTransport, AnalyticsEvent } from "./analytics.transport";

export class GoogleAnalyticsTransport extends AnalyticsTransport {
  private gaConfig: GoogleAnalyticsTransportConfig;
  private baseUrl: string = "https://www.google-analytics.com/mp/collect";
  private debugUrl: string =
    "https://www.google-analytics.com/debug/mp/collect";

  constructor(config: GoogleAnalyticsTransportConfig) {
    super("google-analytics", config);
    this.gaConfig = config;
  }

  protected async initialize(): Promise<void> {
    try {
      // Validate required configuration
      if (!this.gaConfig.measurementId) {
        throw new Error("Google Analytics Measurement ID is required");
      }
      if (!this.gaConfig.apiSecret) {
        throw new Error("Google Analytics API Secret is required");
      }

      // Test connection
      await this.testConnection();
      this.isReady = true;
    } catch (error) {
      console.error("Google Analytics transport initialization failed:", error);
      throw error;
    }
  }

  protected async sendEntry(entry: TransportLogEntry): Promise<void> {
    const event = this.transformToGAEvent(entry);
    await this.sendEvent(event);
  }

  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    const events = entries.map((entry) => this.transformToGAEvent(entry));
    await this.sendEvents(events);
  }

  protected async cleanup(): Promise<void> {
    // Google Analytics doesn't require explicit cleanup
  }

  private transformToGAEvent(entry: TransportLogEntry): any {
    const transformed = this.transformEntry(entry);

    // Map log levels to GA event categories
    const eventCategory = this.mapLogLevelToCategory(entry.level);

    return {
      name: "log_event",
      params: {
        event_category: eventCategory,
        event_label: entry.message,
        log_level: entry.level,
        log_message: entry.message,
        timestamp: entry.timestamp.toISOString(),
        ...(entry.context && { context: entry.context }),
        ...(entry.traceId && { trace_id: entry.traceId }),
        ...(entry.appName && { app_name: entry.appName }),
        ...(entry.environment && { environment: entry.environment }),
        ...this.flattenData(transformed),
        // Add custom dimensions
        custom_dimension_1: entry.level,
        custom_dimension_2: entry.context || "default",
        custom_dimension_3: entry.environment || "production",
      },
    };
  }

  private mapLogLevelToCategory(level: string): string {
    const categoryMap: Record<string, string> = {
      error: "Error",
      warn: "Warning",
      warning: "Warning",
      info: "Information",
      debug: "Debug",
      trace: "Trace",
      verbose: "Verbose",
    };

    return categoryMap[level.toLowerCase()] || "Information";
  }

  private flattenData(
    data: Record<string, any>,
    prefix: string = "",
  ): Record<string, any> {
    const flattened: Record<string, any> = {};

    for (const [key, value] of Object.entries(data)) {
      const newKey = prefix ? `${prefix}_${key}` : key;

      if (
        value &&
        typeof value === "object" &&
        !Array.isArray(value) &&
        !(value instanceof Date)
      ) {
        Object.assign(flattened, this.flattenData(value, newKey));
      } else {
        // GA4 has parameter value limits
        const stringValue = String(value);
        flattened[newKey] =
          stringValue.length > 100
            ? stringValue.substring(0, 100)
            : stringValue;
      }
    }

    return flattened;
  }

  private async sendEvent(event: any): Promise<void> {
    const payload = {
      client_id: this.gaConfig.clientId || this.generateClientId(),
      events: [event],
    };

    await this.makeRequest(payload);
  }

  private async sendEvents(events: any[]): Promise<void> {
    // GA4 allows up to 25 events per request
    const chunks = this.chunkArray(events, 25);

    for (const chunk of chunks) {
      const payload = {
        client_id: this.gaConfig.clientId || this.generateClientId(),
        events: chunk,
      };

      await this.makeRequest(payload);
    }
  }

  private async makeRequest(
    payload: any,
    debug: boolean = false,
  ): Promise<void> {
    const url = debug ? this.debugUrl : this.baseUrl;
    const params = new URLSearchParams({
      measurement_id: this.gaConfig.measurementId,
      api_secret: this.gaConfig.apiSecret,
    });

    try {
      const response = await fetch(`${url}?${params}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Google Analytics API error: ${response.status} ${response.statusText} - ${errorText}`,
        );
      }

      if (debug) {
        const result = await response.json();
        console.log("GA4 Debug Response:", result);
      }
    } catch (error) {
      throw new Error(
        `Failed to send data to Google Analytics: ${(error as Error).message}`,
      );
    }
  }

  private async testConnection(): Promise<void> {
    // Send a test event to validate the connection
    const testEvent = {
      name: "logitron_test",
      params: {
        event_category: "Test",
        event_label: "Connection Test",
        test: true,
        timestamp: new Date().toISOString(),
      },
    };

    const payload = {
      client_id: this.gaConfig.clientId || this.generateClientId(),
      events: [testEvent],
    };

    // Use debug endpoint for testing
    await this.makeRequest(payload, true);
  }

  private generateClientId(): string {
    // Generate a UUID-like client ID
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
      /[xy]/g,
      function (c) {
        const r = (Math.random() * 16) | 0;
        const v = c === "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      },
    );
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  // Public methods for additional GA4 functionality
  public async trackPageView(
    pagePath: string,
    pageTitle?: string,
  ): Promise<void> {
    const event = {
      name: "page_view",
      params: {
        page_location: pagePath,
        page_title: pageTitle || pagePath,
        engagement_time_msec: 1,
      },
    };

    await this.sendEvent(event);
  }

  public async trackCustomEvent(
    eventName: string,
    parameters: Record<string, any> = {},
  ): Promise<void> {
    // Ensure event name follows GA4 conventions
    const sanitizedEventName = eventName
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, "_");

    const event = {
      name: sanitizedEventName,
      params: {
        ...this.flattenData(parameters),
        timestamp: new Date().toISOString(),
      },
    };

    await this.sendEvent(event);
  }

  public async trackConversion(
    conversionName: string,
    value?: number,
    currency?: string,
  ): Promise<void> {
    const event = {
      name: conversionName,
      params: {
        ...(value !== undefined && { value }),
        ...(currency && { currency }),
        timestamp: new Date().toISOString(),
      },
    };

    await this.sendEvent(event);
  }

  public async trackError(
    errorMessage: string,
    errorCode?: string,
    fatal: boolean = false,
  ): Promise<void> {
    const event = {
      name: "exception",
      params: {
        description: errorMessage,
        fatal,
        ...(errorCode && { error_code: errorCode }),
        timestamp: new Date().toISOString(),
      },
    };

    await this.sendEvent(event);
  }

  public async setUserProperties(
    properties: Record<string, any>,
  ): Promise<void> {
    // GA4 user properties are set with events
    const event = {
      name: "user_properties_update",
      params: {
        ...this.flattenData(properties),
        timestamp: new Date().toISOString(),
      },
    };

    await this.sendEvent(event);
  }

  // Enhanced measurement events
  public async trackFileDownload(
    fileName: string,
    fileExtension: string,
  ): Promise<void> {
    if (!this.gaConfig.enableEnhancedMeasurement) {
      return;
    }

    const event = {
      name: "file_download",
      params: {
        file_name: fileName,
        file_extension: fileExtension,
        link_url: fileName,
        timestamp: new Date().toISOString(),
      },
    };

    await this.sendEvent(event);
  }

  public async trackVideoEngagement(
    videoTitle: string,
    videoUrl: string,
    progress: number,
  ): Promise<void> {
    if (!this.gaConfig.enableEnhancedMeasurement) {
      return;
    }

    const event = {
      name: "video_progress",
      params: {
        video_title: videoTitle,
        video_url: videoUrl,
        video_progress: progress,
        timestamp: new Date().toISOString(),
      },
    };

    await this.sendEvent(event);
  }
}
