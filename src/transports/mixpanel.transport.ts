import {
  TransportLogEntry,
  MixpanelTransportConfig,
} from "../types/transport.types";
import {
  AnalyticsTransport,
  AnalyticsEvent,
  AnalyticsUser,
} from "./analytics.transport";

export class MixpanelTransport extends AnalyticsTransport {
  private mixpanelConfig: MixpanelTransportConfig;
  private baseUrl: string = "https://api.mixpanel.com";

  constructor(config: MixpanelTransportConfig) {
    super("mixpanel", config);
    this.mixpanelConfig = config;
  }

  protected async initialize(): Promise<void> {
    try {
      // Validate required configuration
      if (!this.mixpanelConfig.token) {
        throw new Error("Mixpanel token is required");
      }

      // Test connection with a simple request
      await this.testConnection();
      this.isReady = true;
    } catch (error) {
      console.error("Mixpanel transport initialization failed:", error);
      throw error;
    }
  }

  protected async sendEntry(entry: TransportLogEntry): Promise<void> {
    const event = this.transformToMixpanelEvent(entry);
    await this.trackEvent(event);
  }

  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    const events = entries.map((entry) => this.transformToMixpanelEvent(entry));
    await this.trackEvents(events);
  }

  protected async cleanup(): Promise<void> {
    // Mixpanel doesn't require explicit cleanup
  }

  private transformToMixpanelEvent(entry: TransportLogEntry): AnalyticsEvent {
    const transformed = this.transformEntry(entry);

    return {
      name: `log_${entry.level}`,
      properties: {
        ...transformed,
        distinct_id: this.mixpanelConfig.distinct_id || "anonymous",
        time: entry.timestamp.getTime(),
        $insert_id: this.generateInsertId(entry),
        // Add super properties if enabled
        ...(this.mixpanelConfig.enableSuperProperties
          ? this.mixpanelConfig.superProperties
          : {}),
      },
      timestamp: entry.timestamp,
    };
  }

  private async trackEvent(event: AnalyticsEvent): Promise<void> {
    const payload = {
      event: event.name,
      properties: {
        token: this.mixpanelConfig.token,
        ...event.properties,
      },
    };

    await this.makeRequest("/track", [payload]);
  }

  private async trackEvents(events: AnalyticsEvent[]): Promise<void> {
    const payload = events.map((event) => ({
      event: event.name,
      properties: {
        token: this.mixpanelConfig.token,
        ...event.properties,
      },
    }));

    await this.makeRequest("/track", payload);
  }

  private async makeRequest(endpoint: string, data: any): Promise<void> {
    const url = `${this.mixpanelConfig.endpoint || this.baseUrl}${endpoint}`;

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/plain",
        },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        throw new Error(
          `Mixpanel API error: ${response.status} ${response.statusText}`,
        );
      }

      const result = await response.text();
      if (result !== "1") {
        throw new Error(`Mixpanel API returned error: ${result}`);
      }
    } catch (error) {
      throw new Error(
        `Failed to send data to Mixpanel: ${(error as Error).message}`,
      );
    }
  }

  private async testConnection(): Promise<void> {
    // Send a test event to validate the connection
    const testEvent = {
      event: "logitron_test",
      properties: {
        token: this.mixpanelConfig.token,
        distinct_id: "test_user",
        test: true,
        time: Date.now(),
      },
    };

    await this.makeRequest("/track", [testEvent]);
  }

  private generateInsertId(entry: TransportLogEntry): string {
    // Generate a unique insert ID to prevent duplicate events
    const timestamp = entry.timestamp.getTime();
    const hash = this.simpleHash(entry.message + (entry.traceId || ""));
    return `${timestamp}_${hash}`;
  }

  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  // Public methods for additional Mixpanel functionality
  public async identifyUser(user: AnalyticsUser): Promise<void> {
    if (!this.mixpanelConfig.enableUserTracking) {
      return;
    }

    const payload = {
      $token: this.mixpanelConfig.token,
      $distinct_id: user.id,
      $set: user.properties || {},
    };

    await this.makeRequest("/engage", [payload]);
  }

  public async setUserProperties(
    userId: string,
    properties: Record<string, any>,
  ): Promise<void> {
    if (!this.mixpanelConfig.enableUserTracking) {
      return;
    }

    const payload = {
      $token: this.mixpanelConfig.token,
      $distinct_id: userId,
      $set: properties,
    };

    await this.makeRequest("/engage", [payload]);
  }

  public async trackCustomEvent(
    eventName: string,
    properties: Record<string, any> = {},
  ): Promise<void> {
    if (!this.mixpanelConfig.enableEventTracking) {
      return;
    }

    const payload = {
      event: eventName,
      properties: {
        token: this.mixpanelConfig.token,
        distinct_id: this.mixpanelConfig.distinct_id || "anonymous",
        time: Date.now(),
        ...properties,
        ...(this.mixpanelConfig.enableSuperProperties
          ? this.mixpanelConfig.superProperties
          : {}),
      },
    };

    await this.makeRequest("/track", [payload]);
  }
}
