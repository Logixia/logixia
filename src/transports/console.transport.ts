import {
  ITransport,
  TransportLogEntry,
  ConsoleTransportConfig,
} from "../types/transport.types";

export class ConsoleTransport implements ITransport {
  public readonly name = "console";

  constructor(private config: ConsoleTransportConfig = {}) {}

  async write(entry: TransportLogEntry): Promise<void> {
    const formattedEntry = this.formatEntry(entry);

    // Use appropriate console method based on log level
    switch (entry.level.toLowerCase()) {
      case "error":
        console.error(formattedEntry);
        break;
      case "warn":
      case "warning":
        console.warn(formattedEntry);
        break;
      case "debug":
        console.debug(formattedEntry);
        break;
      case "info":
      default:
        console.log(formattedEntry);
        break;
    }
  }

  private formatEntry(entry: TransportLogEntry): string {
    if (this.config.format === "json") {
      return JSON.stringify(
        {
          timestamp:
            this.config.timestamp !== false
              ? entry.timestamp.toISOString()
              : undefined,
          level: entry.level,
          message: entry.message,
          ...(entry.data || {}),
          context: entry.context,
          traceId: entry.traceId,
          appName: entry.appName,
          environment: entry.environment,
        },
        null,
        2,
      );
    }

    // Text format
    const parts: string[] = [];

    // Timestamp
    if (this.config.timestamp !== false) {
      const timestamp = entry.timestamp.toISOString();
      parts.push(this.colorize(timestamp, "gray"));
    }

    // Level
    const level = entry.level.toUpperCase().padEnd(5);
    const coloredLevel = this.colorize(level, this.getLevelColor(entry.level));
    parts.push(coloredLevel);

    // Context
    if (entry.context) {
      const context = `[${entry.context}]`;
      parts.push(this.colorize(context, "cyan"));
    }

    // Trace ID
    if (entry.traceId) {
      const traceId = `(${entry.traceId})`;
      parts.push(this.colorize(traceId, "magenta"));
    }

    // Message
    parts.push(entry.message);

    // Data
    if (entry.data && Object.keys(entry.data).length > 0) {
      const data = JSON.stringify(entry.data);
      parts.push(this.colorize(data, "blue"));
    }

    return parts.join(" ");
  }

  private getLevelColor(level: string): string {
    const colors: Record<string, string> = {
      error: "red",
      warn: "yellow",
      warning: "yellow",
      info: "green",
      debug: "blue",
      trace: "magenta",
      verbose: "cyan",
    };

    return colors[level.toLowerCase()] || "white";
  }

  private colorize(text: string, color: string): string {
    if (this.config.colorize === false) {
      return text;
    }

    const colors: Record<string, string> = {
      red: "\x1b[31m",
      green: "\x1b[32m",
      yellow: "\x1b[33m",
      blue: "\x1b[34m",
      magenta: "\x1b[35m",
      cyan: "\x1b[36m",
      white: "\x1b[37m",
      gray: "\x1b[90m",
      reset: "\x1b[0m",
    };

    const colorCode = colors[color] || colors.white;
    return `${colorCode}${text}${colors.reset}`;
  }

  async close(): Promise<void> {
    // Console transport doesn't need cleanup
  }
}
