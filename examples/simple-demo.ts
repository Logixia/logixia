import { LogixiaLogger } from '../src/core/logixia-logger';

// Simple configuration with only console and file output
const logger = new LogixiaLogger({
  appName: 'SimpleDemo',
  environment: 'development',
  level: 'debug',
  transports: {
    console: {
      level: 'debug',
      colorize: true,
      timestamp: true,
      format: 'text',
    },
    file: {
      level: 'info',
      filename: './logs/simple-demo.log',
      format: 'json'
    }
  }
});

// Simple logging demonstration
async function simpleDemo() {
  console.log('🚀 Starting simple logging demo...');
  
  // Different log levels
  logger.debug('Debug message - only in console');
  logger.info('Info message - console and file', { userId: 123 });
  logger.warn('Warning message', { warning: 'High CPU usage' });
  logger.error('Error message', { error: 'Something went wrong' });
  
  // Logging with data
  logger.info('User action', {
    action: 'login',
    userId: 'user123',
    timestamp: new Date().toISOString()
  });
  
  console.log('✅ Logging completed!');
  console.log('📁 Check ./logs/simple-demo.log for file output');
  
  // Close logger
  await logger.close();
}

// Run the demo
if (require.main === module) {
  simpleDemo().catch(console.error);
}

export { logger };