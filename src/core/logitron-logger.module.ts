import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
  ModuleMetadata,
  Type,
  InjectionToken,
  OptionalFactoryDependency,
} from "@nestjs/common";
import { RouteInfo } from "@nestjs/common/interfaces/middleware/middleware-configuration.interface";
import { LoggerConfig, TraceIdConfig } from "../types";
import { LogixiaLoggerService } from "./logitron-nestjs.service";
import { TraceMiddleware, traceMiddleware } from "./trace.middleware";
import { KafkaTraceInterceptor } from "./kafka-trace.interceptor";
import { WebSocketTraceInterceptor } from "./websocket-trace.interceptor";
import { NextFunction, Request, Response } from "express";

const DEFAULT_ROUTES: RouteInfo[] = [{ path: "*", method: RequestMethod.ALL }];

// Constants for provider tokens
export const LOGIXIA_LOGGER_CONFIG = "LOGIXIA_LOGGER_CONFIG";
export const LOGIXIA_LOGGER_PREFIX = "LOGIXIA_LOGGER_";

// Export the service and interceptors for external use
export { LogixiaLoggerService } from "./logitron-nestjs.service";
export { KafkaTraceInterceptor } from "./kafka-trace.interceptor";
export { WebSocketTraceInterceptor } from "./websocket-trace.interceptor";

// Interface for module configuration
interface LogixiaModuleConfig {
  forRoutes?: RouteInfo[];
  exclude?: RouteInfo[];
}

// Interface for async configuration
export interface LogixiaAsyncOptions extends Pick<ModuleMetadata, "imports"> {
  useExisting?: Type<LogixiaOptionsFactory>;
  useClass?: Type<LogixiaOptionsFactory>;
  useFactory?: (
    ...args: any[]
  ) => Promise<Partial<LoggerConfig>> | Partial<LoggerConfig>;
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
}

// Interface for options factory
export interface LogixiaOptionsFactory {
  createLogixiaOptions():
    | Promise<Partial<LoggerConfig>>
    | Partial<LoggerConfig>;
}

/**
 * Logixia Logger Module for NestJS dependency injection
 */
@Module({})
export class LogixiaLoggerModule implements NestModule {
  private config: LogixiaModuleConfig = {};
  private static loggerConfig: Partial<LoggerConfig> = {};

  configure(consumer: MiddlewareConsumer) {
    const { forRoutes = DEFAULT_ROUTES, exclude } = this.config;

    // Configure middleware with trace config
    const middlewareConfig = (
      req: Request,
      res: Response,
      next: NextFunction,
    ) => {
      let traceConfig: TraceIdConfig | undefined;

      if (typeof LogixiaLoggerModule.loggerConfig.traceId === "object") {
        traceConfig = LogixiaLoggerModule.loggerConfig.traceId as TraceIdConfig;
      } else if (LogixiaLoggerModule.loggerConfig.traceId === true) {
        // Default configuration when traceId is simply true
        traceConfig = {
          enabled: true,
          contextKey: "traceId",
          generator: () => {
            const timestamp = Date.now().toString(36);
            const random = Math.random().toString(36).substring(2, 8);
            return `${timestamp}-${random}`;
          },
        };
      } else {
        traceConfig = undefined;
      }

      const middleware = new TraceMiddleware(traceConfig);
      return middleware.use(req, res, next);
    };

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
      typeof config?.traceId === "object"
        ? config.traceId
        : { enabled: !!config?.traceId };

    return {
      module: LogixiaLoggerModule,
      providers: [
        {
          provide: LOGIXIA_LOGGER_CONFIG,
          useValue: config || {},
        },
        {
          provide: "TRACE_CONFIG",
          useValue: traceConfig,
        },
        {
          provide: LogixiaLoggerService,
          useFactory: (loggerConfig: Partial<LoggerConfig>) => {
            const defaultConfig: LoggerConfig = {
              level: "info",
              service: "NestJSApp",
              environment: "development",
              fields: {},
              formatters: ["text"],
              outputs: ["console"],
              levelOptions: {
                level: "info", // INFO level
                levels: {
                  error: 0,
                  warn: 1,
                  info: 2,
                  debug: 3,
                  verbose: 4,
                },
                colors: {
                  error: "red",
                  warn: "yellow",
                  info: "green",
                  debug: "blue",
                  verbose: "cyan",
                },
              },
              ...loggerConfig,
            };
            return new LogixiaLoggerService(defaultConfig);
          },
          inject: [LOGIXIA_LOGGER_CONFIG],
        },
        {
          provide: KafkaTraceInterceptor,
          useFactory: (traceConfig: any) =>
            new KafkaTraceInterceptor(traceConfig),
          inject: ["TRACE_CONFIG"],
        },
        {
          provide: WebSocketTraceInterceptor,
          useFactory: (traceConfig: any) =>
            new WebSocketTraceInterceptor(traceConfig),
          inject: ["TRACE_CONFIG"],
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
          provide: "TRACE_CONFIG",
          useFactory: (loggerConfig: Partial<LoggerConfig>) => {
            return typeof loggerConfig?.traceId === "object"
              ? loggerConfig.traceId
              : { enabled: !!loggerConfig?.traceId };
          },
          inject: [LOGIXIA_LOGGER_CONFIG],
        },
        {
          provide: LogixiaLoggerService,
          useFactory: (loggerConfig: Partial<LoggerConfig>) => {
            const defaultConfig: LoggerConfig = {
              level: "info",
              service: "NestJSApp",
              environment: "development",
              fields: {},
              formatters: ["text"],
              outputs: ["console"],
              levelOptions: {
                level: "info", // INFO level
                levels: {
                  error: 0,
                  warn: 1,
                  info: 2,
                  debug: 3,
                  verbose: 4,
                },
                colors: {
                  error: "red",
                  warn: "yellow",
                  info: "green",
                  debug: "blue",
                  verbose: "cyan",
                },
              },
              ...loggerConfig,
            };
            // Store config for middleware access
            LogixiaLoggerModule.loggerConfig = defaultConfig;
            return new LogixiaLoggerService(defaultConfig);
          },
          inject: [LOGIXIA_LOGGER_CONFIG],
        },
        {
          provide: KafkaTraceInterceptor,
          useFactory: (traceConfig: any) =>
            new KafkaTraceInterceptor(traceConfig),
          inject: ["TRACE_CONFIG"],
        },
        {
          provide: WebSocketTraceInterceptor,
          useFactory: (traceConfig: any) =>
            new WebSocketTraceInterceptor(traceConfig),
          inject: ["TRACE_CONFIG"],
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
