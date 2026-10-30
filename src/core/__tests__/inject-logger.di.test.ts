/**
 * Real NestJS DI test: `@InjectLogger()` must resolve against `forRoot` /
 * `forRootAsync` without `forFeature('service')`.
 */
import 'reflect-metadata';

import { Injectable, Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { LOGIXIA_LOGGER_SERVICE, LogixiaLoggerModule } from '../logitron-logger.module';
import { LogixiaLoggerService } from '../logitron-nestjs.service';
import { InjectLogger, LogixiaExceptionFilter } from '../nestjs-extras';

@Injectable()
class OrderService {
  constructor(@InjectLogger() readonly logger: LogixiaLoggerService) {}
}

const quiet = { levelOptions: { level: 'error' as const } };

afterEach(() => {
  LogixiaLoggerModule._resetGlobalLogger();
});

describe('@InjectLogger() with the root module', () => {
  it('resolves with forRoot and aliases the root service', async () => {
    @Module({
      imports: [LogixiaLoggerModule.forRoot(quiet)],
      providers: [OrderService, LogixiaExceptionFilter],
    })
    class AppModule {}
    const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
    const svc = app.get(OrderService);
    expect(svc.logger).toBeInstanceOf(LogixiaLoggerService);
    expect(svc.logger).toBe(app.get(LogixiaLoggerService));
    expect(app.get(LogixiaExceptionFilter)).toBeInstanceOf(LogixiaExceptionFilter);
    await app.close();
  });

  it('resolves with forRootAsync', async () => {
    @Module({
      imports: [LogixiaLoggerModule.forRootAsync({ useFactory: () => quiet })],
      providers: [OrderService],
    })
    class AppModule {}
    const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
    expect(app.get(OrderService).logger).toBe(app.get(LogixiaLoggerService));
    await app.close();
  });

  it('forFeature(service) keeps working alongside forRoot', async () => {
    @Module({
      imports: [LogixiaLoggerModule.forRoot(quiet), LogixiaLoggerModule.forFeature('service')],
      providers: [OrderService],
    })
    class AppModule {}
    const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
    expect(app.get(OrderService).logger).toBeDefined();
    expect(LOGIXIA_LOGGER_SERVICE).toBe('LOGIXIA_LOGGER_SERVICE');
    await app.close();
  });
});
