import type {
  ConsoleTransportConfig,
  ITransport,
  TransportLogEntry,
} from '../types/transport.types';
import { safeToString } from '../utils/coerce.utils';

/**
 * Writes log entries to stdout (info/debug/verbose) and stderr (error/warn).
 *
 * Supports pretty-printed colorized output and compact JSON mode.
 *
 * @example
 * transports: { console: { format: 'json' } }
 */
export class ConsoleTransport implements ITransport {
  public readonly name = 'console';

  // Pre-built ANSI color map — avoids object recreation inside formatEntry()
  private static readonly COLORS: ReadonlyMap<string, string> = new Map([
    ['black', '\x1b[30m'],
    ['red', '\x1b[31m'],
    ['green', '\x1b[32m'],
    ['yellow', '\x1b[33m'],
    ['blue', '\x1b[34m'],
    ['magenta', '\x1b[35m'],
    ['cyan', '\x1b[36m'],
    ['white', '\x1b[37m'],
    ['gray', '\x1b[90m'],
    ['grey', '\x1b[90m'],
    ['brightred', '\x1b[91m'],
    ['brightgreen', '\x1b[92m'],
    ['brightyellow', '\x1b[93m'],
    ['brightblue', '\x1b[94m'],
    ['brightmagenta', '\x1b[95m'],
    ['brightcyan', '\x1b[96m'],
    ['brightwhite', '\x1b[97m'],
    ['reset', '\x1b[0m'],
  ]);

  // CWE-117 guard: strip ASCII control characters from user-supplied text so
  // attacker-controlled log payloads cannot inject ANSI escapes, overwrite
  // lines, or forge log entries on the operator's terminal. Keeps \t (0x09)
  // since tabs are harmless, and strips everything else in the C0 + DEL + C1
  // ranges. Applied only to text mode — JSON mode already escapes via
  // JSON.stringify.
  // eslint-disable-next-line no-control-regex
  private static readonly CONTROL_CHARS_RE = /[\x00-\x08\x0B-\x1F\x7F-\x9F]/g;

  private static sanitize(value: unknown): string {
    // Coerce to string first: upstream code (NestJS internals, user payloads)
    // can pass objects / Errors here, and .replace() would throw otherwise.
    return safeToString(value).replace(ConsoleTransport.CONTROL_CHARS_RE, '');
  }

  constructor(private config: ConsoleTransportConfig = {}) {}

  write(entry: TransportLogEntry): Promise<void> {
    const formatted = this.formatEntry(entry) + '\n';
    // Use process.stderr for errors, stdout for everything else —
    // avoids the extra indirection that console.log/error add.
    const out = entry.level.toLowerCase() === 'error' ? process.stderr : process.stdout;
    out.write(formatted);
    return Promise.resolve();
  }

  private formatEntry(entry: TransportLogEntry): string {
    if (this.config.format === 'json') {
      return JSON.stringify(
        {
          timestamp: this.config.timestamp !== false ? entry.timestamp.toISOString() : undefined,
          level: entry.level,
          message: entry.message,
          ...(entry.data || {}),
          context: entry.context,
          traceId: entry.traceId,
          appName: entry.appName,
          environment: entry.environment,
        },
        null,
        2
      );
    }

    // Text format
    const parts: string[] = [];

    // Timestamp
    if (this.config.timestamp !== false) {
      const timestamp = entry.timestamp.toISOString();
      parts.push(this.colorize(timestamp, 'gray'));
    }

    // Level
    const level = entry.level.toUpperCase().padEnd(5);
    const coloredLevel = this.colorize(level, this.getLevelColor(entry.level));
    parts.push(coloredLevel);

    // Context
    if (entry.context) {
      const context = `[${ConsoleTransport.sanitize(entry.context)}]`;
      parts.push(this.colorize(context, 'cyan'));
    }

    // Trace ID
    if (entry.traceId) {
      const traceId = `(${ConsoleTransport.sanitize(entry.traceId)})`;
      parts.push(this.colorize(traceId, 'magenta'));
    }

    // Message
    parts.push(ConsoleTransport.sanitize(entry.message));

    // Data — JSON.stringify already escapes control chars as \u001b, so the
    // JSON representation is safe to print without further sanitization.
    if (entry.data && Object.keys(entry.data).length > 0) {
      const data = JSON.stringify(entry.data);
      parts.push(this.colorize(data, 'blue'));
    }

    return parts.join(' ');
  }

  private getLevelColor(level: string): string {
    const lower = level.toLowerCase();

    // User-configured colors take priority (covers custom levels like kafka, mongo, etc.)
    if (this.config.levelColors?.[lower]) {
      return this.config.levelColors[lower]!;
    }

    // Built-in defaults
    const defaults: Record<string, string> = {
      error: 'red',
      warn: 'yellow',
      warning: 'yellow',
      info: 'green',
      debug: 'blue',
      trace: 'magenta',
      verbose: 'cyan',
    };

    return defaults[lower] || 'gray';
  }

  private colorize(text: string, color: string): string {
    if (this.config.colorize === false) return text;
    // Use the static pre-built map — no per-call object allocation
    const reset = ConsoleTransport.COLORS.get('reset')!;
    const code = ConsoleTransport.COLORS.get(color) ?? ConsoleTransport.COLORS.get('white')!;
    return `${code}${text}${reset}`;
  }

  close(): Promise<void> {
    return Promise.resolve();
  }
}
