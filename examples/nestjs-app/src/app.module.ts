import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from '../../../src/core/logitron-logger.module';
import { LogLevel } from '../../../src/types';
import type { TransportConfig } from '../../../src/types/transport.types';
import { UsersModule } from './users/users.module';
import { OrdersModule } from './orders/orders.module';
import { EventsModule } from './events/events.module';
import { KafkaModule } from './kafka/kafka.module';
import { HealthModule } from './health/health.module';

// ── Transport factory — reads env vars set by docker-compose ──────────────────
function buildTransports(): TransportConfig {
  const transports: TransportConfig = {
    // Console is always on
    console: { colorize: true, timestamp: true, format: 'text' },
  };

  // ── File transport ────────────────────────────────────────────────────────
  if (process.env['LOG_TO_FILE'] === 'true') {
    transports.file = {
      filename:      process.env['LOG_FILE_NAME'] ?? 'app.log',
      dirname:       process.env['LOG_FILE_DIR']  ?? './logs',
      format:        'json',
      rotation:      { interval: '1d', maxFiles: 7, compress: true },
      flushInterval: 3000,
    };
  }

  // ── PostgreSQL transport ──────────────────────────────────────────────────
  if (process.env['LOG_TO_POSTGRES'] === 'true') {
    transports.database = [
      {
        type:          'postgresql',
        host:          process.env['POSTGRES_HOST']     ?? 'localhost',
        port:          Number(process.env['POSTGRES_PORT'] ?? 5432),
        database:      process.env['POSTGRES_DB']       ?? 'logixia_logs',
        username:      process.env['POSTGRES_USER']     ?? 'logixia',
        password:      process.env['POSTGRES_PASSWORD'] ?? 'logixia_pass',
        table:         'logs',
        level:         'warn',       // only WARN+ goes to postgres
        batchSize:     50,
        flushInterval: 5000,
      },
    ];

    // ── MongoDB transport ───────────────────────────────────────────────────
    if (process.env['LOG_TO_MONGO'] === 'true') {
      const pgTransport = Array.isArray(transports.database)
        ? transports.database
        : [transports.database!];

      transports.database = [
        ...pgTransport,
        {
          type: 'mongodb',
          connectionString: `mongodb://${process.env['MONGO_USER'] ?? 'logixia'}:${process.env['MONGO_PASSWORD'] ?? 'logixia_pass'}@${process.env['MONGO_HOST'] ?? 'localhost'}:${process.env['MONGO_PORT'] ?? 27017}/${process.env['MONGO_DB'] ?? 'logixia_logs'}?authSource=admin`,
          database:         process.env['MONGO_DB'] ?? 'logixia_logs',
          collection:       'logs',
          level:            'info',   // INFO+ goes to mongo
          batchSize:        100,
          flushInterval:    5000,
        },
      ];
    }
  } else if (process.env['LOG_TO_MONGO'] === 'true') {
    // Mongo only (postgres disabled)
    transports.database = {
      type: 'mongodb',
      connectionString: `mongodb://${process.env['MONGO_USER'] ?? 'logixia'}:${process.env['MONGO_PASSWORD'] ?? 'logixia_pass'}@${process.env['MONGO_HOST'] ?? 'localhost'}:${process.env['MONGO_PORT'] ?? 27017}/${process.env['MONGO_DB'] ?? 'logixia_logs'}?authSource=admin`,
      database:   process.env['MONGO_DB'] ?? 'logixia_logs',
      collection: 'logs',
      level:      'info',
      batchSize:  100,
      flushInterval: 5000,
    };
  }

  return transports;
}

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName:     process.env['APP_NAME'] ?? 'thread-gate',
      environment: (process.env['NODE_ENV'] === 'production' ? 'production' : 'development'),
      traceId:     {
        enabled: true,
        extractor: {
          header: ['x-trace-id', 'x-request-id'],
          query: ['traceId'],
          body:  ['traceId'],
          params: ['traceId'],
        },
      },
      format:      { timestamp: true, colorize: true, json: false },

      levelOptions: {
        level: LogLevel.DEBUG,
        levels: {
          [LogLevel.ERROR]:   0,
          [LogLevel.WARN]:    1,
          [LogLevel.INFO]:    2,
          [LogLevel.DEBUG]:   3,
          [LogLevel.VERBOSE]: 4,
          kafka:              5,
        },
        colors: {
          [LogLevel.ERROR]:   'red',
          [LogLevel.WARN]:    'yellow',
          [LogLevel.INFO]:    'blue',
          [LogLevel.DEBUG]:   'green',
          [LogLevel.VERBOSE]: 'cyan',
          kafka:              'magenta',
          'kafka.error':      'red',
        },
      },

      // ── Multi-transport ─────────────────────────────────────────────────
      transports: buildTransports(),

      // ── Graceful shutdown — flush all transports before exit ────────────
      gracefulShutdown: { enabled: true, timeout: 8000 },
    }),

    UsersModule,
    OrdersModule,
    EventsModule,
    KafkaModule,
    HealthModule,
  ],
})
export class AppModule {}
