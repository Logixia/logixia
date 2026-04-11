import type {
  InjectionToken,
  MiddlewareConsumer,
  ModuleMetadata,
  NestModule,
  OptionalFactoryDependency,
  Type,
} from '@nestjs/common';
import { Module, RequestMethod } from '@nestjs/common';
import type { RouteInfo } from '@nestjs/common/interfaces/middleware/middleware-configuration.interface';
import type { NextFunction, Request, Response } from 'express';

import type { LoggerConfig, TraceIdConfig } from '../types';
import { TraceContext } from '../utils/trace.utils';
import { KafkaTraceInterceptor } from './kafka-trace.interceptor';
import { LogixiaLoggerService } from './logitron-nestjs.service';
import { TraceMiddleware } from './trace.middleware';
import { WebSocketTraceInterceptor } from './websocket-trace.interceptor';

const DEFAULT_ROUTES: RouteInfo[] = [{ path: '*', method: RequestMethod.ALL }];

// Constants for provider tokens
export const LOGIXIA_LOGGER_CONFIG = 'LOGIXIA_LOGGER_CONFIG';
export const LOGIXIA_LOGGER_PREFIX = 'LOGIXIA_LOGGER_';

// Export the service and interceptors for external use
export { KafkaTraceInterceptor } from './kafka-trace.interceptor';
export { LogixiaLoggerService } from './logitron-nestjs.service';
export { WebSocketTraceInterceptor } from './websocket-trace.interceptor';

// Interface for module configuration
interface LogixiaModuleConfig {
  forRoutes?: RouteInfo[];
  exclude?: RouteInfo[];
}

// Interface for async configuration
export interface LogixiaAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  useExisting?: Type<LogixiaOptionsFactory>;
  useClass?: Type<LogixiaOptionsFactory>;
  useFactory?: (...args: unknown[]) => Promise<Partial<LoggerConfig>> | Partial<LoggerConfig>;
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
}

// Interface for options factory
export interface LogixiaOptionsFactory {
  createLogixiaOptions(): Promise<Partial<LoggerConfig>> | Partial<LoggerConfig>;
}

/**
 * Logixia Logger Module for NestJS dependency injection
 */
@Module({})
export class LogixiaLoggerModule implements NestModule {
  private config: LogixiaModuleConfig = {};
  private static loggerConfig: Partial<LoggerConfig> = {};

  /**
   * @internal Backing field for the global logger. Do not read or write
   * directly — use {@link getGlobalLogger} / {@link _setGlobalLogger} which
   * enforce single-init semantics.
   */
  // Retained for backwards compatibility with internal callers that read the
  // field directly (e.g. nestjs-extras). Treat as read-only — writes must go
  // through _setGlobalLogger / _resetGlobalLogger.
  // eslint-disable-next-line sonarjs/public-static-readonly -- intentional: we need to swap this in tests via _resetGlobalLogger, so `readonly` is too strict
  static _globalLogger: LogixiaLoggerService | null = null;

  /**
   * @internal Set the global logger exactly once.
   *
   * Called from the module's forRoot / forRootAsync factory. If the module is
   * initialised more than once in the same process (nested DI context, test
   * harness creating multiple apps, hot reload, etc.) a warning is written to
   * stderr and the first logger wins — silently overwriting would allow the
   * newer instance's transport config to replace the live one while the old
   * one is still being used by registered shutdown hooks, decorators, etc.
   *
   * Use {@link _resetGlobalLogger} in tests to reset between runs.
   */
  static _setGlobalLogger(service: LogixiaLoggerService): void {
    if (LogixiaLoggerModule._globalLogger !== null) {
      process.stderr.write(
        '[logixia] LogixiaLoggerModule.forRoot() was called more than once — ignoring the second init. ' +
          'If this is intentional (e.g. in tests), call LogixiaLoggerModule._resetGlobalLogger() first.\n'
      );
      return;
    }
    LogixiaLoggerModule._globalLogger = service;
  }

  /** @internal Clear the global logger. Tests only. */
  static _resetGlobalLogger(): void {
    LogixiaLoggerModule._globalLogger = null;
  }

  /**
   * Returns the global LogixiaLoggerService instance that was created when the
   * module booted. Useful for logging outside of NestJS DI — utility functions,
   * plain scripts, decorators — without injecting the service everywhere.
   *
   * Returns `null` if called before `LogixiaLoggerModule.forRoot[Async]()` has
   * been initialised (i.e. before the NestJS app has started).
   *
   * @example
   * ```ts
   * // some-util.ts
   * import { LogixiaLoggerModule } from 'logixia/nest';
   *
   * export function doSomething() {
   *   LogixiaLoggerModule.getGlobalLogger()?.info('doing something');
   * }
   * ```
   */
  static getGlobalLogger(): LogixiaLoggerService | null {
    return LogixiaLoggerModule._globalLogger;
  }

  configure(consumer: MiddlewareConsumer) {
    const { forRoutes = DEFAULT_ROUTES, exclude } = this.config;

    // Resolve the trace config ONCE at configure() time — it does not change
    // per request, so constructing a fresh TraceMiddleware on every invocation
    // (the old behaviour) was just allocation churn.
    let resolvedTraceConfig: TraceIdConfig | undefined;
    if (typeof LogixiaLoggerModule.loggerConfig.traceId === 'object') {
      resolvedTraceConfig = LogixiaLoggerModule.loggerConfig.traceId as TraceIdConfig;
    } else if (LogixiaLoggerModule.loggerConfig.traceId === true) {
      resolvedTraceConfig = {
        enabled: true,
        contextKey: 'traceId',
        generator: () => TraceContext.instance.generate(),
      };
    }

    const middleware = new TraceMiddleware(resolvedTraceConfig);
    const middlewareConfig = (req: Request, res: Response, next: NextFunction) =>
      middleware.use(req, res, next);

    if (exclude) {
      consumer
        .apply(middlewareConfig)
        .exclude(...exclude)
        .forRoutes(...forRoutes);
    } else {
      consumer.apply(middlewareConfig).forRoutes(...forRoutes);
    }
  }

  /**
   * Configure the module with synchronous options
   */
  static forRoot(config?: Partial<LoggerConfig>) {
    // Store config for middleware access
    LogixiaLoggerModule.loggerConfig = config || {};

    const traceConfig =
      typeof config?.traceId === 'object' ? config.traceId : { enabled: !!config?.traceId };

    return {
      module: LogixiaLoggerModule,
      providers: [
        {
          provide: LOGIXIA_LOGGER_CONFIG,
          useValue: config || {},
        },
        {
          provide: 'TRACE_CONFIG',
          useValue: traceConfig,
        },
        {
          provide: LogixiaLoggerService,
          useFactory: (loggerConfig: Partial<LoggerConfig>) => {
            const defaultConfig: LoggerConfig = {
              level: 'info',
              service: 'NestJSApp',
              environment: 'development',
              fields: {},
              formatters: ['text'],
              outputs: ['console'],
              levelOptions: {
                level: 'info', // INFO level
                levels: {
                  error: 0,
                  warn: 1,
                  info: 2,
                  debug: 3,
                  verbose: 4,
                },
                colors: {
                  error: 'red',
                  warn: 'yellow',
                  info: 'green',
                  debug: 'blue',
                  verbose: 'cyan',
                },
              },
              ...loggerConfig,
            };
            const service = new LogixiaLoggerService(defaultConfig);
            LogixiaLoggerModule._setGlobalLogger(service);
            return service;
          },
          inject: [LOGIXIA_LOGGER_CONFIG],
        },
        {
          provide: KafkaTraceInterceptor,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- NestJS DI injects typed config
          useFactory: (traceConfig: any) => new KafkaTraceInterceptor(traceConfig),
          inject: ['TRACE_CONFIG'],
        },
        {
          provide: WebSocketTraceInterceptor,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- NestJS DI injects typed config
          useFactory: (traceConfig: any) => new WebSocketTraceInterceptor(traceConfig),
          inject: ['TRACE_CONFIG'],
        },
      ],
      exports: [
        LogixiaLoggerService,
        LOGIXIA_LOGGER_CONFIG,
        KafkaTraceInterceptor,
        WebSocketTraceInterceptor,
      ],
      global: true,
    };
  }

  /**
   * Configure the module with asynchronous options
   */
  static forRootAsync(options: LogixiaAsyncOptions) {
    return {
      module: LogixiaLoggerModule,
      imports: options.imports || [],
      providers: [
        ...this.createAsyncProviders(options),
        {
          provide: 'TRACE_CONFIG',
          useFactory: (loggerConfig: Partial<LoggerConfig>) => {
            return typeof loggerConfig?.traceId === 'object'
              ? loggerConfig.traceId
              : { enabled: !!loggerConfig?.traceId };
          },
          inject: [LOGIXIA_LOGGER_CONFIG],
        },
        {
          provide: LogixiaLoggerService,
          useFactory: (loggerConfig: Partial<LoggerConfig>) => {
            const defaultConfig: LoggerConfig = {
              level: 'info',
              service: 'NestJSApp',
              environment: 'development',
              fields: {},
              formatters: ['text'],
              outputs: ['console'],
              levelOptions: {
                level: 'info', // INFO level
                levels: {
                  error: 0,
                  warn: 1,
                  info: 2,
                  debug: 3,
                  verbose: 4,
                },
                colors: {
                  error: 'red',
                  warn: 'yellow',
                  info: 'green',
                  debug: 'blue',
                  verbose: 'cyan',
                },
              },
              ...loggerConfig,
            };
            // Store config for middleware access
            LogixiaLoggerModule.loggerConfig = defaultConfig;
            const service = new LogixiaLoggerService(defaultConfig);
            LogixiaLoggerModule._setGlobalLogger(service);
            return service;
          },
          inject: [LOGIXIA_LOGGER_CONFIG],
        },
        {
          provide: KafkaTraceInterceptor,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- NestJS DI injects typed config
          useFactory: (traceConfig: any) => new KafkaTraceInterceptor(traceConfig),
          inject: ['TRACE_CONFIG'],
        },
        {
          provide: WebSocketTraceInterceptor,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- NestJS DI injects typed config
          useFactory: (traceConfig: any) => new WebSocketTraceInterceptor(traceConfig),
          inject: ['TRACE_CONFIG'],
        },
      ],
      exports: [
        LogixiaLoggerService,
        LOGIXIA_LOGGER_CONFIG,
        KafkaTraceInterceptor,
        WebSocketTraceInterceptor,
      ],
      global: true,
    };
  }

  /**
   * Create feature-specific logger instances
   */
  static forFeature(context: string) {
    const providerToken = `${LOGIXIA_LOGGER_PREFIX}${context.toUpperCase()}`;
    return {
      module: LogixiaLoggerModule,
      providers: [
        {
          provide: providerToken,
          useFactory: (baseLogger: LogixiaLoggerService) => {
            return baseLogger.child(context);
          },
          inject: [LogixiaLoggerService],
        },
      ],
      exports: [providerToken],
    };
  }

  private static createAsyncProviders(options: LogixiaAsyncOptions) {
    if (options.useExisting || options.useFactory) {
      return [this.createAsyncOptionsProvider(options)];
    }
    return [
      this.createAsyncOptionsProvider(options),
      {
        provide: options.useClass!,
        useClass: options.useClass!,
      },
    ];
  }

  private static createAsyncOptionsProvider(options: LogixiaAsyncOptions) {
    if (options.useFactory) {
      return {
        provide: LOGIXIA_LOGGER_CONFIG,
        useFactory: options.useFactory,
        inject: options.inject || [],
      };
    }
    return {
      provide: LOGIXIA_LOGGER_CONFIG,
      useFactory: async (optionsFactory: LogixiaOptionsFactory) =>
        await optionsFactory.createLogixiaOptions(),
      inject: [options.useExisting || options.useClass!],
    };
  }
}
