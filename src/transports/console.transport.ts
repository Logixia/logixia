import { ITransport, TransportLogEntry, ConsoleTransportConfig } from '../types/transport.types';

/**
 * ConsoleTransport
 * 
 * Logs entries to the console with optional formatting and colors.
 */
export class ConsoleTransport implements ITransport {
  public readonly name = 'console';
  
  constructor(private config: ConsoleTransportConfig = {}) {}

  /**
   * Write a log entry to the console
   */
  async write(entry: TransportLogEntry): Promise<void> {
    const formattedEntry = this.formatEntry(entry);
    const level = entry.level.toLowerCase();

    switch (level) {
      case 'error':
        console.error(formattedEntry);
        break;
      case 'warn':
      case 'warning':
        console.warn(formattedEntry);
        break;
      case 'debug':
        console.debug(formattedEntry);
        break;
      case 'info':
      default:
        console.log(formattedEntry);
        break;
    }
  }

  /**
   * Format a log entry for output
   */
  private formatEntry(entry: TransportLogEntry): string {
    if (this.config.format === 'json') {
      return JSON.stringify({
        timestamp: this.config.timestamp !== false ? entry.timestamp.toISOString() : undefined,
        level: entry.level,
        message: entry.message,
        ...(entry.data || {}),
        context: entry.context,
        traceId: entry.traceId,
        appName: entry.appName,
        environment: entry.environment
      }, null, 2);
    }

    return this.formatTextEntry(entry);
  }

  /**
   * Format a text entry with colors and structured output
   */
  private formatTextEntry(entry: TransportLogEntry): string {
    const parts: string[] = [];

    // Timestamp
    if (this.config.timestamp !== false) {
      parts.push(this.colorize(entry.timestamp.toISOString(), 'gray'));
    }

    // Level
    const level = entry.level.toUpperCase().padEnd(5);
    parts.push(this.colorize(level, this.getLevelColor(entry.level)));

    // Context
    if (entry.context) {
      parts.push(this.colorize(`[${entry.context}]`, 'cyan'));
    }

    // Trace ID
    if (entry.traceId) {
      parts.push(this.colorize(`(${entry.traceId})`, 'magenta'));
    }

    // Message
    parts.push(entry.message);

    // Data
    if (entry.data && Object.keys(entry.data).length > 0) {
      parts.push(this.colorize(JSON.stringify(entry.data), 'blue'));
    }

    return parts.join(' ');
  }

  /**
   * Map log level to console color
   */
  private getLevelColor(level: string): string {
    const colors: Record<string, string> = {
      error: 'red',
      warn: 'yellow',
      warning: 'yellow',
      info: 'green',
      debug: 'blue',
      trace: 'magenta',
      verbose: 'cyan'
    };
    return colors[level.toLowerCase()] || 'white';
  }

  /**
   * Colorize text for console output
   */
  private colorize(text: string, color: string): string {
    if (this.config.colorize === false) return text;

    const colors: Record<string, string> = {
      red: '\x1b[31m',
      green: '\x1b[32m',
      yellow: '\x1b[33m',
      blue: '\x1b[34m',
      magenta: '\x1b[35m',
      cyan: '\x1b[36m',
      white: '\x1b[37m',
      gray: '\x1b[90m',
      reset: '\x1b[0m'
    };

    const colorCode = colors[color] || colors.white;
    return `${colorCode}${text}${colors.reset}`;
  }

  /**
   * Close transport (noop for console)
   */
  async close(): Promise<void> {
    // No cleanup required
  }
}
