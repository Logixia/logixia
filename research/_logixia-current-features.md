# logixia — current feature surface (as of audit)

logixia ALREADY HAS these features (do NOT recommend adding what it already has):
- Log levels (error/warn/info/debug/trace/verbose) + custom levels
- Structured logging, child loggers
- Adaptive log level (NODE_ENV/CI-based)
- Per-namespace log levels (with ENV overrides)
- Transports: Console, File (with rotation + gzip), Database (PG/MySQL/SQLite/Mongo), Analytics (Mixpanel/DataDog/Segment/GA)
- Cloud adapters: AWS CloudWatch, GCP Cloud Logging, Azure Monitor
- Request tracing: trace utils, Express/Fastify middleware, NestJS middleware, Kafka + WebSocket interceptors (AsyncLocalStorage based)
- NestJS integration: @LogMethod decorator, LogixiaExceptionFilter, DI module
- Correlation ID propagation: Express/Fastify, outbound fetch + axios, Kafka/SQS/RabbitMQ helpers
- Browser support (zero Node deps, remote transport with keepalive)
- Log redaction: path-based (** globs) + regex patterns + auto-detect PII (conservative/aggressive), message-string redaction
- Timer API (time/timeEnd)
- Field management (enable/disable fields)
- Per-transport level control + filter predicates
- Log search engine (full-text, NL query, trace correlation, similarity, presets, in-memory index)
- OpenTelemetry bridge (auto trace/span injection)
- Graceful shutdown (flushOnExit, SIGTERM/SIGINT, drain-on-close)
- Plugin/extension API (onInit/onLog/onError/onShutdown)
- Metrics -> Prometheus (counters/histograms/gauges, /metrics endpoint)
- Multi-transport retry + failover + fallback
- Sampling (rate, per-level, trace-consistent, token-bucket rate limit)
- CLI tool (tail, search, query, stats, analyze, explore, export)
- TypeScript-first, async-first (non-blocking)

TARGET RUNTIME: Node.js (Express/NestJS/Fastify primary), also browser/edge.
