import {
  TransportLogEntry,
  SegmentTransportConfig,
} from "../types/transport.types";
import {
  AnalyticsTransport,
  AnalyticsEvent,
  AnalyticsUser,
} from "./analytics.transport";

export class SegmentTransport extends AnalyticsTransport {
  private segmentConfig: SegmentTransportConfig;
  private baseUrl: string;

  constructor(config: SegmentTransportConfig) {
    super("segment", config);
    this.segmentConfig = {
      enableBatching: true,
      maxBatchSize: 100,
      flushAt: 20,
      flushInterval: 10000,
      ...config,
    };

    this.baseUrl = config.dataPlaneUrl || "https://api.segment.io";
  }

  protected async initialize(): Promise<void> {
    try {
      // Validate required configuration
      if (!this.segmentConfig.writeKey) {
        throw new Error("Segment Write Key is required");
      }

      // Test connection
      await this.testConnection();
      this.isReady = true;
    } catch (error) {
      console.error("Segment transport initialization failed:", error);
      throw error;
    }
  }

  protected async sendEntry(entry: TransportLogEntry): Promise<void> {
    const segmentEvent = this.transformToSegmentEvent(entry);
    await this.track(segmentEvent);
  }

  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    if (!this.segmentConfig.enableBatching) {
      // Send individually if batching is disabled
      for (const entry of entries) {
        await this.sendEntry(entry);
      }
      return;
    }

    const segmentEvents = entries.map((entry) =>
      this.transformToSegmentEvent(entry),
    );
    await this.batchTrack(segmentEvents);
  }

  protected async cleanup(): Promise<void> {
    // Segment doesn't require explicit cleanup
  }

  private transformToSegmentEvent(entry: TransportLogEntry): any {
    const transformed = this.transformEntry(entry);

    return {
      type: "track",
      event: `Log ${entry.level.charAt(0).toUpperCase() + entry.level.slice(1)}`,
      userId: this.extractUserId(entry),
      anonymousId: this.generateAnonymousId(),
      timestamp: entry.timestamp.toISOString(),
      properties: {
        level: entry.level,
        message: entry.message,
        logger: "logixia",
        ...transformed,
        ...(entry.context && { context: entry.context }),
        ...(entry.traceId && { traceId: entry.traceId }),
        ...(entry.appName && { appName: entry.appName }),
        ...(entry.environment && { environment: entry.environment }),
      },
      context: {
        library: {
          name: "logixia",
          version: "1.0.0",
        },
        app: {
          name: entry.appName || "unknown",
          version: "1.0.0",
          environment: entry.environment || "production",
        },
        ...(entry.traceId && {
          trace: {
            trace_id: entry.traceId,
          },
        }),
      },
      integrations: {
        // Disable integrations that might interfere
        All: false,
        "Segment.io": true,
      },
    };
  }

  private async track(event: any): Promise<void> {
    await this.makeRequest("/v1/track", event);
  }

  private async batchTrack(events: any[]): Promise<void> {
    // Split into chunks based on maxBatchSize
    const chunks = this.chunkArray(
      events,
      this.segmentConfig.maxBatchSize || 100,
    );

    for (const chunk of chunks) {
      const payload = {
        batch: chunk,
      };

      await this.makeRequest("/v1/batch", payload);
    }
  }

  private async makeRequest(endpoint: string, data: any): Promise<void> {
    const url = `${this.baseUrl}${endpoint}`;

    // Encode write key for basic auth
    const auth = Buffer.from(`${this.segmentConfig.writeKey}:`).toString(
      "base64",
    );

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Basic ${auth}`,
          "User-Agent": "logixia/1.0.0",
        },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Segment API error: ${response.status} ${response.statusText} - ${errorText}`,
        );
      }
    } catch (error) {
      throw new Error(
        `Failed to send data to Segment: ${(error as Error).message}`,
      );
    }
  }

  private async testConnection(): Promise<void> {
    // Send a test track event
    const testEvent = {
      type: "track",
      event: "Logixia Test",
      userId: "test-user",
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      properties: {
        test: true,
        source: "logixia",
      },
      context: {
        library: {
          name: "logixia",
          version: "1.0.0",
        },
      },
    };

    await this.makeRequest("/v1/track", testEvent);
  }

  private extractUserId(entry: TransportLogEntry): string | undefined {
    // Try to extract user ID from entry data
    if (entry.data) {
      return entry.data.userId || entry.data.user_id || entry.data.id;
    }
    return undefined;
  }

  private generateAnonymousId(): string {
    // Generate a UUID-like anonymous ID
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

  // Public methods for Segment-specific functionality
  public async identify(user: AnalyticsUser): Promise<void> {
    const payload = {
      type: "identify",
      userId: user.id,
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      traits: {
        ...user.properties,
        ...user.traits,
      },
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
      },
    };

    await this.makeRequest("/v1/identify", payload);
  }

  public async page(
    name: string,
    properties: Record<string, any> = {},
  ): Promise<void> {
    const payload = {
      type: "page",
      name,
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      properties: {
        ...properties,
        url: properties.url || `/${name.toLowerCase().replace(/\s+/g, "-")}`,
        title: properties.title || name,
      },
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
        page: {
          url: properties.url || `/${name.toLowerCase().replace(/\s+/g, "-")}`,
          title: properties.title || name,
        },
      },
    };

    await this.makeRequest("/v1/page", payload);
  }

  public async screen(
    name: string,
    properties: Record<string, any> = {},
  ): Promise<void> {
    const payload = {
      type: "screen",
      name,
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      properties: {
        ...properties,
      },
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
        screen: {
          name,
        },
      },
    };

    await this.makeRequest("/v1/screen", payload);
  }

  public async group(
    groupId: string,
    traits: Record<string, any> = {},
    userId?: string,
  ): Promise<void> {
    const payload = {
      type: "group",
      groupId,
      userId,
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      traits,
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
      },
    };

    await this.makeRequest("/v1/group", payload);
  }

  public async alias(userId: string, previousId: string): Promise<void> {
    const payload = {
      type: "alias",
      userId,
      previousId,
      timestamp: new Date().toISOString(),
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
      },
    };

    await this.makeRequest("/v1/alias", payload);
  }

  public async trackCustomEvent(
    eventName: string,
    properties: Record<string, any> = {},
    userId?: string,
  ): Promise<void> {
    const payload = {
      type: "track",
      event: eventName,
      userId,
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      properties,
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
      },
    };

    await this.makeRequest("/v1/track", payload);
  }

  // E-commerce tracking methods
  public async trackPurchase(
    orderId: string,
    products: any[],
    revenue: number,
    currency: string = "USD",
  ): Promise<void> {
    const payload = {
      type: "track",
      event: "Order Completed",
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      properties: {
        orderId,
        revenue,
        currency,
        products,
      },
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
      },
    };

    await this.makeRequest("/v1/track", payload);
  }

  public async trackProductViewed(product: any): Promise<void> {
    const payload = {
      type: "track",
      event: "Product Viewed",
      anonymousId: this.generateAnonymousId(),
      timestamp: new Date().toISOString(),
      properties: product,
      context: {
        library: {
          name: "logitron",
          version: "1.0.0",
        },
      },
    };

    await this.makeRequest("/v1/track", payload);
  }
}
