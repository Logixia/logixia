/**
 * logixia — TypeScript typed log fields
 *
 * Solves the type-safety gap: standard `Record<string, unknown>` metadata gives
 * zero IDE autocomplete and lets typos slip silently into production logs.
 *
 * Two complementary utilities:
 *
 * 1. `createTypedLogger<TFields>()` — wraps any IBaseLogger so that the second
 *    argument of every log method is constrained to `TFields` (a typed object).
 *    Compile-time safety, zero runtime overhead.
 *
 * 2. `defineLogSchema<TFields>(schema)` — declares expected fields with optional
 *    validators. In development (NODE_ENV !== 'production') every log call is
 *    validated against the schema and a warning is emitted for missing required
 *    fields or type mismatches.
 *
 * @example
 * ```ts
 * import { createTypedLogger, defineLogSchema } from 'logixia';
 *
 * interface OrderFields {
 *   orderId: string;
 *   userId: string;
 *   amount?: number;
 *   currency?: string;
 * }
 *
 * const schema = defineLogSchema<OrderFields>({
 *   orderId: { type: 'string', required: true },
 *   userId:  { type: 'string', required: true },
 *   amount:  { type: 'number' },
 *   currency: { type: 'string' },
 * });
 *
 * const orderLogger = createTypedLogger<OrderFields>(baseLogger, schema);
 * await orderLogger.info('Order created', { orderId: 'ord_123', userId: 'usr_456', amount: 99.99 });
 * //                                       ^^^^ fully typed autocomplete ^^^^
 * ```
 */

import { internalWarn } from './internal-log';

// ── Schema types ─────────────────────────────────────────────────────────────

export type LogFieldType = 'string' | 'number' | 'boolean' | 'object' | 'array';

export interface LogFieldDef {
  type: LogFieldType;
  /** Emit a warning when this field is missing from the log call. Default: false */
  required?: boolean;
  /** Custom validator — return a string to emit it as a warning message. */
  validate?: (value: unknown) => string | undefined;
}

export type LogSchema<TFields extends Record<string, unknown>> = {
  [K in keyof TFields]: LogFieldDef;
};

export interface CompiledSchema<TFields extends Record<string, unknown>> {
  readonly fields: LogSchema<TFields>;
  /**
   * Validate a payload against the schema.
   * Returns an array of warning strings (empty = pass).
   * Only runs in non-production environments.
   */
  validate(payload: Partial<TFields>): string[];
}

// ── defineLogSchema ──────────────────────────────────────────────────────────

/**
 * Define a typed schema for a category of log entries.
 *
 * Call this once at module initialisation and pass it to `createTypedLogger`.
 * In development, every log call is validated against the schema.
 */
export function defineLogSchema<TFields extends Record<string, unknown>>(
  fields: LogSchema<TFields>
): CompiledSchema<TFields> {
  return {
    fields,
    validate(payload: Partial<TFields>): string[] {
      if (process.env['NODE_ENV'] === 'production') return [];

      const warnings: string[] = [];

      for (const [key, def] of Object.entries(fields) as [keyof TFields & string, LogFieldDef][]) {
        const value = payload[key];

        if (def.required && (value === undefined || value === null)) {
          warnings.push(`Required field "${key}" is missing`);
          continue;
        }

        if (value !== undefined && value !== null) {
          const actualType = Array.isArray(value) ? 'array' : typeof value;
          if (actualType !== def.type) {
            warnings.push(`Field "${key}" expected type "${def.type}" but got "${actualType}"`);
          }

          if (def.validate) {
            const msg = def.validate(value);
            if (msg) warnings.push(`Field "${key}": ${msg}`);
          }
        }
      }

      return warnings;
    },
  };
}

// ── TypedLogger ──────────────────────────────────────────────────────────────

/** IBaseLogger-compatible subset used by TypedLogger */
export interface LoggerLike {
  error(message: string | Error, data?: Record<string, unknown>): Promise<void>;
  warn(message: string, data?: Record<string, unknown>): Promise<void>;
  info(message: string, data?: Record<string, unknown>): Promise<void>;
  debug(message: string, data?: Record<string, unknown>): Promise<void>;
  verbose?(message: string, data?: Record<string, unknown>): Promise<void>;
  trace?(message: string, data?: Record<string, unknown>): Promise<void>;
}

/**
 * A logger whose metadata is typed to `TFields`.
 *
 * The `error` overload still accepts a plain `Error` object as the first arg
 * (with optional `TFields` data) so the typed logger remains a drop-in replacement.
 */
export interface TypedLogger<TFields extends Record<string, unknown>> {
  error(error: Error, data?: Partial<TFields>): Promise<void>;
  error(message: string, data?: Partial<TFields>): Promise<void>;
  warn(message: string, data?: Partial<TFields>): Promise<void>;
  info(message: string, data?: Partial<TFields>): Promise<void>;
  debug(message: string, data?: Partial<TFields>): Promise<void>;
  verbose(message: string, data?: Partial<TFields>): Promise<void>;
  trace(message: string, data?: Partial<TFields>): Promise<void>;
  /** Access the underlying untyped logger if needed. */
  readonly raw: LoggerLike;
}

/**
 * Wrap any logixia logger with a type-safe field interface.
 *
 * @param logger  Any object that implements `IBaseLogger` (e.g. the result of `createLogger()`)
 * @param schema  Optional schema for dev-time validation. Created with `defineLogSchema()`.
 */
export function createTypedLogger<TFields extends Record<string, unknown>>(
  logger: LoggerLike,
  schema?: CompiledSchema<TFields>
): TypedLogger<TFields> {
  function withValidation(
    level: string,
    fn: (msg: string, data?: Record<string, unknown>) => Promise<void>,
    message: string,
    data?: Partial<TFields>
  ): Promise<void> {
    if (schema && data) {
      const warnings = schema.validate(data);
      for (const w of warnings) {
        internalWarn(`[logixia/schema] ${w} — level=${level} message="${message}"`);
      }
    }
    return fn(message, data as Record<string, unknown> | undefined);
  }

  return {
    raw: logger,
    error(messageOrError: string | Error, data?: Partial<TFields>): Promise<void> {
      return logger.error(messageOrError as string, data as Record<string, unknown> | undefined);
    },
    warn: (m, d) => withValidation('warn', logger.warn.bind(logger), m, d),
    info: (m, d) => withValidation('info', logger.info.bind(logger), m, d),
    debug: (m, d) => withValidation('debug', logger.debug.bind(logger), m, d),
    verbose: (m, d) =>
      withValidation('verbose', (logger.verbose ?? logger.debug).bind(logger), m, d),
    trace: (m, d) => withValidation('trace', (logger.trace ?? logger.debug).bind(logger), m, d),
  };
}
