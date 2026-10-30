/**
 * Real NestJS DI test: `@InjectLogger()` resolves the root service from
 * `forRoot` / `forRootAsync`, and `@InjectLogger(context)` resolves the
 * `forFeature(context)` child logger. Neither may hand out the other's instance.
 */
import 'reflect-metadata';

import { Injectable, Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { LogixiaLoggerModule } from '../logitron-logger.module';
import { LogixiaLoggerService } from '../logitron-nestjs.service';
import { InjectLogger, LogixiaExceptionFilter } from '../nestjs-extras';

const contextOf = (svc: LogixiaLoggerService): string | undefined =>
  (svc as unknown as { context?: string }).context;

@Injectable()
class RootUser {
  constructor(@InjectLogger() readonly logger: LogixiaLoggerService) {}
}

@Injectable()
class OrdersUser {
  constructor(@InjectLogger('orders') readonly logger: LogixiaLoggerService) {}
}

@Injectable()
class ServiceUser {
  constructor(@InjectLogger('service') readonly logger: LogixiaLoggerService) {}
}

const quiet = { levelOptions: { level: 'error' as const } };

afterEach(() => {
  LogixiaLoggerModule._resetGlobalLogger();
});

describe('@InjectLogger()', () => {
  it('injects the root service with forRoot, and the exception filter resolves too', async () => {
    @Module({
      imports: [LogixiaLoggerModule.forRoot(quiet)],
      providers: [RootUser, LogixiaExceptionFilter],
    })
    class AppModule {}
    const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
    const root = app.get(LogixiaLoggerService);
    expect(app.get(RootUser).logger).toBe(root);
    expect(app.get(LogixiaExceptionFilter)).toBeInstanceOf(LogixiaExceptionFilter);
    await app.close();
  });

  it('injects the root service with forRootAsync', async () => {
    @Module({
      imports: [LogixiaLoggerModule.forRootAsync({ useFactory: () => quiet })],
      providers: [RootUser],
    })
    class AppModule {}
    const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
    expect(app.get(RootUser).logger).toBe(app.get(LogixiaLoggerService));
    await app.close();
  });

  it('with forRoot + forFeature, no-arg gets the root and a context gets its own child', async () => {
    @Module({
      imports: [
        LogixiaLoggerModule.forRoot(quiet),
        LogixiaLoggerModule.forFeature('orders'),
        LogixiaLoggerModule.forFeature('service'),
      ],
      providers: [RootUser, OrdersUser, ServiceUser],
    })
    class AppModule {}
    const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
    const root = app.get(LogixiaLoggerService);

    expect(app.get(RootUser).logger).toBe(root);
    expect(contextOf(root)).toBeUndefined();

    const orders = app.get(OrdersUser).logger;
    expect(orders).not.toBe(root);
    expect(contextOf(orders)).toBe('orders');

    const service = app.get(ServiceUser).logger;
    expect(service).not.toBe(root);
    expect(contextOf(service)).toBe('service');
    await app.close();
  });
});
