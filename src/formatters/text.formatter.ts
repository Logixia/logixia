/**
 * Text formatter for Logixia
 */

import { ILogFormatter, LogEntry, LogLevel } from "../types";

export class TextFormatter implements ILogFormatter {
  private colorize: boolean;
  private includeTimestamp: boolean;
  private includeAppName: boolean;
  private includeTraceId: boolean;
  private includeContext: boolean;
  private timestampFormat: "iso" | "locale" | "short";
  private colors: Record<string, string>;

  constructor(
    options: {
      colorize?: boolean;
      includeTimestamp?: boolean;
      includeAppName?: boolean;
      includeTraceId?: boolean;
      includeContext?: boolean;
      timestampFormat?: "iso" | "locale" | "short";
      colors?: Record<string, string>;
    } = {},
  ) {
    this.colorize = options.colorize ?? true;
    this.includeTimestamp = options.includeTimestamp ?? true;
    this.includeAppName = options.includeAppName ?? true;
    this.includeTraceId = options.includeTraceId ?? true;
    this.includeContext = options.includeContext ?? true;
    this.timestampFormat = options.timestampFormat ?? "locale";
    this.colors = {
      error: "\x1b[31m", // Red
      warn: "\x1b[33m", // Yellow
      info: "\x1b[32m", // Green
      debug: "\x1b[34m", // Blue
      trace: "\x1b[35m", // Magenta
      verbose: "\x1b[36m", // Cyan
      reset: "\x1b[0m", // Reset
      bold: "\x1b[1m", // Bold
      dim: "\x1b[2m", // Dim
      ...options.colors,
    };
  }

  format(entry: LogEntry): string {
    const parts: string[] = [];

    // Add timestamp
    if (this.includeTimestamp) {
      const timestamp = this.formatTimestamp(entry.timestamp);
      parts.push(
        this.colorize
          ? `${this.colors.dim}${timestamp}${this.colors.reset}`
          : timestamp,
      );
    }

    // Add log level
    const levelName = entry.level.toLowerCase();
    const levelColor = this.colors[levelName] || this.colors.reset;
    const formattedLevel = this.colorize
      ? `${levelColor}${this.colors.bold}${levelName.toUpperCase().padEnd(5)}${this.colors.reset}`
      : levelName.toUpperCase().padEnd(5);
    parts.push(`[${formattedLevel}]`);

    // Add app name
    if (this.includeAppName) {
      const appName = this.colorize
        ? `${this.colors.bold}${entry.appName}${this.colors.reset}`
        : entry.appName;
      parts.push(`[${appName}]`);
    }

    // Add trace ID
    if (this.includeTraceId && entry.traceId) {
      const traceId = this.colorize
        ? `${this.colors.dim}${entry.traceId}${this.colors.reset}`
        : entry.traceId;
      parts.push(`[${traceId}]`);
    }

    // Add context
    if (this.includeContext && entry.context) {
      const context = this.colorize
        ? `${this.colors.cyan}${entry.context}${this.colors.reset}`
        : entry.context;
      parts.push(`[${context}]`);
    }

    // Add message
    const message =
      this.colorize && entry.level === LogLevel.ERROR
        ? `${this.colors.error}${entry.message}${this.colors.reset}`
        : entry.message;
    parts.push(message);

    // Add payload
    if (entry.payload && Object.keys(entry.payload).length > 0) {
      const payload = this.formatPayload(entry.payload);
      if (payload) {
        parts.push(
          this.colorize
            ? `${this.colors.dim}${payload}${this.colors.reset}`
            : payload,
        );
      }
    }

    return parts.join(" ");
  }

  private formatTimestamp(timestamp: string): string {
    const date = new Date(timestamp);

    switch (this.timestampFormat) {
      case "iso":
        return date.toISOString();
      case "short":
        return date.toLocaleTimeString();
      case "locale":
      default:
        return date.toLocaleString();
    }
  }

  private formatPayload(payload: Record<string, any>): string {
    try {
      // Handle simple objects
      if (Object.keys(payload).length === 1) {
        const entry = Object.entries(payload)[0];
        if (entry) {
          const [key, value] = entry;
          if (
            typeof value === "string" ||
            typeof value === "number" ||
            typeof value === "boolean"
          ) {
            return `${key}=${value}`;
          }
        }
      }

      // Handle multiple properties or complex objects
      const formatted = Object.entries(payload)
        .map(([key, value]) => {
          if (value === null || value === undefined) {
            return `${key}=${value}`;
          }
          if (typeof value === "string") {
            return `${key}="${value}"`;
          }
          if (typeof value === "number" || typeof value === "boolean") {
            return `${key}=${value}`;
          }
          if (value instanceof Date) {
            return `${key}=${value.toISOString()}`;
          }
          if (typeof value === "object") {
            return `${key}=${JSON.stringify(value)}`;
          }
          return `${key}=${String(value)}`;
        })
        .join(" ");

      return formatted;
    } catch {
      return JSON.stringify(payload);
    }
  }

  /**
   * Create a formatter with preset configurations
   */
  static createSimple(): TextFormatter {
    return new TextFormatter({
      colorize: true,
      includeTimestamp: true,
      includeAppName: false,
      includeTraceId: false,
      includeContext: true,
      timestampFormat: "short",
    });
  }

  static createDetailed(): TextFormatter {
    return new TextFormatter({
      colorize: true,
      includeTimestamp: true,
      includeAppName: true,
      includeTraceId: true,
      includeContext: true,
      timestampFormat: "locale",
    });
  }

  static createMinimal(): TextFormatter {
    return new TextFormatter({
      colorize: false,
      includeTimestamp: false,
      includeAppName: false,
      includeTraceId: false,
      includeContext: false,
    });
  }
}
