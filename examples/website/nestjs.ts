import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia/nest';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'nestjs-api',
      environment: 'production',
      traceId: true,
      transports: { console: {} },
    }),
  ],
})
export class AppModule {}
