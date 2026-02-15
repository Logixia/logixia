/**
 * JSON formatter for Logixia
 */

import { ILogFormatter, LogEntry, LogLevel } from "../types";
import { serializeError } from "../utils/error.utils";

export class JsonFormatter implements ILogFormatter {
  private includeTimestamp: boolean;
  private includeLevel: boolean;
  private includeAppName: boolean;
  private includeTraceId: boolean;
  private includeContext: boolean;
  private prettyPrint: boolean;

  constructor(
    options: {
      includeTimestamp?: boolean;
      includeLevel?: boolean;
      includeAppName?: boolean;
      includeTraceId?: boolean;
      includeContext?: boolean;
      prettyPrint?: boolean;
    } = {},
  ) {
    this.includeTimestamp = options.includeTimestamp ?? true;
    this.includeLevel = options.includeLevel ?? true;
    this.includeAppName = options.includeAppName ?? true;
    this.includeTraceId = options.includeTraceId ?? true;
    this.includeContext = options.includeContext ?? true;
    this.prettyPrint = options.prettyPrint ?? false;
  }

  format(entry: LogEntry): string {
    const formatted: Record<string, any> = {};

    // Add timestamp
    if (this.includeTimestamp) {
      formatted.timestamp = entry.timestamp;
    }

    // Add log level
    if (this.includeLevel) {
      formatted.level = entry.level.toLowerCase();
      formatted.levelValue = entry.level;
    }

    // Add app name
    if (this.includeAppName) {
      formatted.appName = entry.appName;
    }

    // Add trace ID
    if (this.includeTraceId && entry.traceId) {
      formatted.traceId = entry.traceId;
    }

    // Add context
    if (this.includeContext && entry.context) {
      formatted.context = entry.context;
    }

    // Add message
    formatted.message = entry.message;

    // Add payload
    if (entry.payload && Object.keys(entry.payload).length > 0) {
      formatted.payload = this.serializePayload(entry.payload);
    }

    // Add error if present
    if (entry.error) {
      formatted.error = serializeError(entry.error);
    }

    // Add metadata
    formatted.meta = {
      pid: process.pid,
      hostname: process.env.HOSTNAME || "unknown",
      version: process.version,
    };

    return this.prettyPrint
      ? JSON.stringify(formatted, null, 2)
      : JSON.stringify(formatted);
  }

  private serializePayload(payload: Record<string, any>): Record<string, any> {
    const serialized: Record<string, any> = {};

    for (const [key, value] of Object.entries(payload)) {
      try {
        if (value instanceof Error) {
          serialized[key] = serializeError(value);
        } else if (value instanceof Date) {
          serialized[key] = value.toISOString();
        } else if (typeof value === "function") {
          serialized[key] = "[Function]";
        } else if (typeof value === "symbol") {
          serialized[key] = value.toString();
        } else if (value === undefined) {
          serialized[key] = null;
        } else {
          serialized[key] = value;
        }
      } catch {
        serialized[key] = "[Unserializable]";
      }
    }

    return serialized;
  }
}
