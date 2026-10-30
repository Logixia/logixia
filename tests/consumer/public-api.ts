// Compiled by `npm run typecheck:consumer` the way an application sees the package:
// 'logixia' specifiers resolve through the package.json `exports` map to the built
// `dist/*.d.ts`, under strict + exactOptionalPropertyTypes with real framework types.
import express from 'express';
import Fastify from 'fastify';
import type {
  ILoggerDefault,
  ITransport as RootTransport,
  TransportLogEntry as RootEntry,
} from 'logixia';
import {
  createExpressContextMiddleware,
  createFastifyContextHook,
  createLogger,
  wideEventMiddleware,
} from 'logixia';
import {
  childFromRequest,
  correlationFastifyHook,
  correlationMiddleware,
} from 'logixia/correlation';
import { createExpressMiddleware, createFastifyPlugin } from 'logixia/middleware';
import { createMockLogger } from 'logixia/testing';
import type {
  ConsoleTransportConfig,
  FileTransportConfig,
  IAsyncTransport,
  IBatchTransport,
  ITransport,
  OtlpLogTransportConfig,
  TransportConfig,
  TransportLogEntry,
} from 'logixia/transports';

const logger = createLogger({ appName: 'consumer', environment: 'development' });

const app = express();
app.use(createExpressMiddleware(logger));
app.use(wideEventMiddleware(logger));
app.use(createExpressContextMiddleware());
app.use(correlationMiddleware());
app.use((req, _res, next) => {
  const requestLogger = childFromRequest(req, logger);
  void requestLogger.flush();
  next();
});

const fastify = Fastify();
fastify.addHook('onRequest', createFastifyContextHook());
fastify.addHook('onRequest', correlationFastifyHook());
void fastify.register(createFastifyPlugin(logger));
fastify.get('/', (request) => {
  void childFromRequest(request, logger).info('hi');
  return 'ok';
});

logger.setLevel('debug');
const level: string = logger.getLevel();
logger.setNamespaceLevels({ 'db.*': 'debug', '*': 'info' });
logger.patchNamespaceLevels({ http: 'warn' });
const namespaces: Record<string, string> = logger.getNamespaceLevels();
logger.enableField('traceId');
void logger.flush();
void logger.healthCheck();
logger.child('db').setNamespaceLevels({ db: 'info' });

const custom = createLogger({
  appName: 'consumer',
  levelOptions: { level: 'info', levels: { error: 0, info: 1, audit: 1 } },
});
custom.setNamespaceLevels({ '*': 'info' });
void custom.audit('ok');
custom.child('x').setNamespaceLevels({});

// A reserved name is not a level method: `flush` stays the runtime control.
const reserved = createLogger({
  appName: 'consumer',
  levelOptions: { level: 'info', levels: { info: 1, flush: 2 } },
});
const flushed: Promise<void> = reserved.flush();

// A hand-written ILoggerDefault with only the pre-existing members still compiles.
const handWritten: ILoggerDefault = {
  error: async () => undefined,
  warn: async () => undefined,
  info: async () => undefined,
  debug: async () => undefined,
  trace: async () => undefined,
  verbose: async () => undefined,
  logLevel: async () => undefined,
  time: () => undefined,
  timeEnd: async () => undefined,
  timeAsync: async (_label, fn) => fn(),
  setLevel: () => undefined,
  getLevel: () => 'info',
  setContext: () => undefined,
  getContext: () => undefined,
  enableField: () => undefined,
  disableField: () => undefined,
  isFieldEnabled: () => true,
  getFieldState: () => ({}),
  resetFieldState: () => undefined,
  enableTransportLevelPrompting: () => undefined,
  disableTransportLevelPrompting: () => undefined,
  setTransportLevels: () => undefined,
  getTransportLevels: () => undefined,
  clearTransportLevelPreferences: () => undefined,
  getAvailableTransports: () => [],
  child: () => logger,
  close: async () => undefined,
  use() {
    return this;
  },
  unuse() {
    return this;
  },
};

// The mock logger is assignable to the logger interfaces.
const mock = createMockLogger();
const asDefault: ILoggerDefault = mock.logger;

// Custom transports are implementable against the public transport types.
class MemoryTransport implements ITransport, IAsyncTransport, IBatchTransport {
  readonly name = 'memory';
  readonly entries: TransportLogEntry[] = [];
  write(entry: TransportLogEntry): void {
    this.entries.push(entry);
  }
  addToBatch(entry: TransportLogEntry): void {
    this.entries.push(entry);
  }
  async flush(): Promise<void> {}
}
const consoleConfig: ConsoleTransportConfig = { level: 'warn', format: 'json' };
const fileConfig: FileTransportConfig = { filename: 'app.log' };
const otlpConfig: OtlpLogTransportConfig = { url: 'http://localhost:4318/v1/logs' };
const transportConfig: TransportConfig = {
  console: consoleConfig,
  file: fileConfig,
  custom: [new MemoryTransport()],
};
const withTransports = createLogger({ appName: 'consumer', transports: transportConfig });
const rootEntry: RootEntry = {
  timestamp: new Date(),
  level: 'info',
  message: 'x',
};
const rootTransport: RootTransport = new MemoryTransport();

export {
  asDefault,
  flushed,
  handWritten,
  level,
  namespaces,
  otlpConfig,
  rootEntry,
  rootTransport,
  withTransports,
};
