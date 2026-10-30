/**
 * Code shown on the website landing page (website/.vitepress/theme/components/HomeHero.vue
 * and HomeBento.vue). Those components render highlighted HTML, so keep the snippets
 * below in sync with them; `npm run typecheck:examples` then catches API drift.
 */
import { Module } from '@nestjs/common';
import { createLogger } from 'logixia';
import { createBrowserLogger } from 'logixia/browser';
import { LogixiaLoggerModule } from 'logixia/nest';

// HomeHero.vue: terminal panel
export async function heroExample(): Promise<void> {
  const logger = createLogger({
    appName: 'api',
    traceId: true,
    redact: { paths: ['**.password', '**.token'] },
    transports: {
      console: { format: 'text' },
      file: { filename: 'app.log', maxSize: '50MB' },
      database: { type: 'postgresql', database: 'app' },
    },
  });

  await logger.info('Server started', { port: 3000 });
  await logger.warn('slow query', { ms: 812 });
  await logger.error('charge failed', { password: 'hunter2' });
}

// HomeBento.vue: NestJS tile
@Module({
  imports: [LogixiaLoggerModule.forRoot({ appName: 'api', traceId: true })],
})
export class AppModule {}

// HomeBento.vue: browser and edge tile
export const browserLogger = createBrowserLogger({ appName: 'web' });
