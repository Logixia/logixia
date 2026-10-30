---
title: API overview
description: 'Every logixia import path and what it exports: logger, context, redaction, metrics, NestJS, middleware, correlation, transports, browser, search and testing.'
order: 25
---

# API overview

logixia has twelve import paths, listed in `package.json` under `exports`. Each ships ESM, CommonJS and type declarations. This page groups what each one exports; follow the links for details.

| Import path           | Purpose                                                                            |
| --------------------- | ---------------------------------------------------------------------------------- |
| `logixia`             | Logger, context, redaction, sampling, metrics, OTel, OTLP, Slack, Discord, search. |
| `logixia/nest`        | NestJS module, service, filter, decorators, interceptors.                          |
| `logixia/middleware`  | Express middleware and Fastify plugin for request logging.                         |
| `logixia/correlation` | Correlation IDs for services and message queues.                                   |
| `logixia/transports`  | Transport classes and `TransportManager`.                                          |
| `logixia/worker`      | Worker-thread transport.                                                           |
| `logixia/cloudwatch`  | AWS CloudWatch Logs transport.                                                     |
| `logixia/gcp`         | Google Cloud Logging transport.                                                    |
| `logixia/azure`       | Azure Monitor transport.                                                           |
| `logixia/browser`     | Browser and edge logger.                                                           |
| `logixia/search`      | In-memory log search.                                                              |
| `logixia/testing`     | Mock logger for tests.                                                             |

## `logixia`

### Logger

| Export                                                       | Description                                                                                                             |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `createLogger(config, context?)`                             | Create a logger; custom levels become typed methods. See [Configuration](/guide/configuration).                         |
| `LogixiaLogger`                                              | The logger class. Has `flush()`, `healthCheck()` and namespace-level methods that the `createLogger` return type omits. |
| `logger`                                                     | A ready-made default logger.                                                                                            |
| `DEFAULT_CONFIG`, `DEFAULT_LOG_LEVELS`, `DEFAULT_LOG_COLORS` | Default configuration values.                                                                                           |
| `LogLevel`                                                   | Constant of built-in level names.                                                                                       |
| `JsonFormatter`, `TextFormatter`                             | Formatter classes.                                                                                                      |

### Context and tracing

See [Tracing](/guide/tracing) and [Child loggers and context](/guide/child-loggers-and-context).

`LogixiaContext`, `createExpressContextMiddleware`, `createFastifyContextHook`, `TraceContext`, `runWithTraceId`, `getCurrentTraceId`, `generateTraceId`, `extractTraceId`, `sanitizeIncomingId`, `createTraceMiddleware`, `DEFAULT_TRACE_HEADERS`, `MAX_INCOMING_ID_LENGTH`, `TRACE_CONTEXT_KEY`, `getTraceContextKey`, `traceStorage` and the deprecated `setTraceId`. Names starting with `_` (`_setActiveContextKey`, `_shutdownRegistrySize`) are internal.

### Redaction and serialization

See [Redaction](/guide/redaction).

`applyRedaction`, `redactObject`, `serializeError`, `isError`, `normalizeError`, `safeStringify`, `stringifyForLog`, `decycleValue`, `retrocycle`.

### Levels and lifecycle

See [Log levels](/guide/log-levels) and [Graceful shutdown](/guide/graceful-shutdown).

`registerLevelSignal`, `createLevelControlHandler`, `flushOnExit`, `registerForShutdown`, `deregisterFromShutdown`, `resetShutdownHandlers`.

### Observability

| Group         | Exports                                                                                     | Guide                                 |
| ------------- | ------------------------------------------------------------------------------------------- | ------------------------------------- |
| Metrics       | `createMetricsPlugin`, `MetricsPlugin`, `OVERFLOW_LABEL_VALUE`                              | [Metrics](/guide/metrics)             |
| OpenTelemetry | `initOtelBridge`, `disableOtelBridge`, `getActiveOtelContext`, `getOtelMetaFields`          | [OpenTelemetry](/guide/opentelemetry) |
| Wide events   | `withWideEvent`, `wideEventMiddleware`, `addEventFields`, `setEventField`, `getEventFields` | [Wide events](/guide/wide-events)     |
| Plugins       | `usePlugin`, `PluginRegistry`, `globalPluginRegistry`                                       | [Plugins](/guide/plugins)             |
| Typed fields  | `createTypedLogger`, `defineLogSchema`                                                      | [Typed logger](/guide/typed-logger)   |

### Transports available from the root

`OtlpLogTransport`, `toOtelSeverity`, `SlackTransport`, `DiscordTransport`. All other transports come from `logixia/transports` or their own entry. See [Transports](/guide/transports/).

### Errors

`LogixiaException`, `ErrorResponseBuilder`, `isLogixiaException`, `generateRequestId`. See [NestJS](/guide/nestjs).

### Search classes

The root also re-exports the search module: `SearchManager`, `BasicLogIndexer`, `BasicSearchEngine`, `CorrelationEngine`, `NLPSearchEngine`, `PatternRecognitionEngine`. Prefer importing them from `logixia/search`.

### Types

::: details Exported types
Logger and config: `LoggerConfig`, `LoggerConfigInterface`, `LogEntry`, `LogLevelString`, `LogColor`, `LogFieldKey`, `Environment`, `NamespaceLevels`, `GracefulShutdownConfig`, `SamplingConfig`, `AdaptiveSamplingConfig`, `SamplingStats`, `RedactConfig`, `TraceIdConfig`, `TraceIdExtractorConfig`, `ErrorSerializationOptions`, `SafeStringifyOptions`, `TimingEntry`, `ContextData`, `LogContext`.

Logger interfaces: `IBaseLogger`, `ILogger`, `ILoggerDefault`, `ILogFormatter`, `LoggerWithLevels`, `ExtractLevels`, `CustomLevelMethods`, `ReconfigurableLogger`, `LevelSignalOptions`.

HTTP: `HttpRequest`, `HttpResponse`, `HttpError`, `RequestContext`, `RequestMetrics`, `RequestTiming`.

Metrics, OTel and wide events: `MetricConfig`, `MetricsMap`, `CounterConfig`, `GaugeConfig`, `HistogramConfig`, `MetricsPluginOptions`, `OtelBridgeOptions`, `OtelSpanContext`, `WideEventFields`, `WideEventLogger`, `WideEventOptions`, `WideEventMiddlewareOptions`, `LogixiaPlugin`.

Typed logger: `TypedLogger`, `LoggerLike`, `LogSchema`, `LogFieldDef`, `LogFieldType`, `CompiledSchema`.

Errors: `ErrorDetail`, `BuildParams`, `LogixiaErrorResponse`, `LogixiaExceptionOptions`.

Transports: `OtlpLogTransportConfig`, `SlackTransportConfig`, `SlackMessage`, `DiscordTransportConfig`, `DiscordEmbed`.

Search: `SearchManagerConfig`, `SearchFilters`, `SearchOptions`, `SearchResult`, `SearchStats`, `SearchSuggestion`, `SearchPreset`, `SearchQuery`, `SearchHighlight`, `SearchMatch`, `TimeRange`, `RelativeTime`, `SortField`, `SuggestionType`, `ExportOptions`, `ParsedNLQuery`, `QueryEntity`, `QueryIntent`, `EntityType`, `LogPattern`, `LogCluster`, `AnomalyDetection`, `CorrelatedLogs`, `LogCorrelationSummary`, `TimelineEvent`, `RelatedLog`, `RelationshipType`, `SimilarLog`, `SemanticIndex`, `ILogIndexer`, `ILogSearchEngine`.
:::

::: warning Transport interface types
`ITransport`, `IAsyncTransport`, `IBatchTransport`, `TransportLogEntry`, `TransportConfig` and the per-transport config types (such as `FileTransportConfig`) are not exported by name. [Custom transport](/guide/transports/custom) shows how to obtain the types you need from `LoggerConfig`.
:::

## `logixia/nest`

`LogixiaLoggerModule`, `LogixiaLoggerService`, `LogixiaExceptionFilter`, `LOGIXIA_EXCEPTION_FILTER_OPTIONS`, `InjectLogger`, `LogMethod`, `TraceMiddleware`, `KafkaTraceInterceptor`, `WebSocketTraceInterceptor`, `createLoggerService`, and the constants `LOGIXIA_LOGGER_CONFIG`, `LOGIXIA_LOGGER_PREFIX`, `LOGIXIA_TRACE_CONFIG`. Types for the module and filter options are exported too. See [NestJS](/guide/nestjs).

## `logixia/middleware`

`createExpressMiddleware`, `createFastifyPlugin`, and the types `HttpLoggerOptions`, `IncomingRequest`, `OutgoingResponse`, `FastifyInstance`. See [HTTP logging](/guide/http-logging).

## `logixia/correlation`

`correlationMiddleware`, `correlationFastifyHook`, `correlationFetch`, `createCorrelationAxiosInterceptor`, `childFromRequest`, `withCorrelationId`, `getCurrentCorrelationId`, `generateCorrelationId`, `extractMessageCorrelationId`, `buildKafkaCorrelationHeaders`, plus the types `CorrelationContext`, `CorrelationMiddlewareOptions` and `ChildFromRequestOptions`. See [Tracing](/guide/tracing).

## `logixia/transports`

`ConsoleTransport`, `FileTransport`, `DatabaseTransport`, `AnalyticsTransport`, `MixpanelTransport`, `DataDogTransport`, `GoogleAnalyticsTransport`, `SegmentTransport`, `CloudWatchTransport`, `AzureMonitorTransport`, `GCPTransport`, `OtlpLogTransport`, `SlackTransport`, `DiscordTransport`, `WorkerTransport`, `TransportManager`, `toOtelSeverity`, and the types `OtlpLogTransportConfig`, `SlackTransportConfig`, `SlackMessage`, `DiscordTransportConfig`, `DiscordEmbed`. See [Transports](/guide/transports/).

## Single-transport entries

| Import path          | Exports                                                            |
| -------------------- | ------------------------------------------------------------------ |
| `logixia/worker`     | `WorkerTransport`, type `WorkerTransportConfig`                    |
| `logixia/cloudwatch` | `CloudWatchTransport`, type `CloudWatchTransportConfig`            |
| `logixia/gcp`        | `GCPTransport`, types `GCPTransportConfig`, `GCPMonitoredResource` |
| `logixia/azure`      | `AzureMonitorTransport`, type `AzureMonitorTransportConfig`        |

These entries let bundlers load one transport without pulling in the others.

## `logixia/browser`

`createBrowserLogger`, `BrowserLogger`, `browserLogger`, `BrowserConsoleTransport`, `BrowserRemoteTransport`, `createTypedLogger`, `defineLogSchema`, `initOtelBridge`, `disableOtelBridge`, `getActiveOtelContext`, `getOtelMetaFields`, plus the types `BrowserLoggerConfig`, `BrowserLogEntry`, `BrowserLogLevel` and `IBrowserTransport`. See [Browser and edge](/guide/browser-and-edge).

## `logixia/search`

`SearchManager`, `BasicLogIndexer`, `BasicSearchEngine`, `CorrelationEngine`, `NLPSearchEngine`, `PatternRecognitionEngine`, and the search types (`SearchFilters`, `SearchOptions`, `SearchResult`, `LogPattern`, `AnomalyDetection`, `CorrelatedLogs`, `ExportOptions` and more). See [Log search](/guide/log-search).

## `logixia/testing`

`createMockLogger` and the types `MockLoggerInstance`, `MockLogCall`, `LogMatcher`. See [Testing](/guide/testing).

## Command line

The package also installs a `logixia` binary. See [Command line tool](/guide/cli).
