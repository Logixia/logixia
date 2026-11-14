import { LogixiaLogger } from '../src/core/logixia-logger';

// Basic configuration with console and file output
const logger = new LogixiaLogger({
  appName: 'BasicApp',
  environment: 'development',
  level: 'debug',
  transports: {
    // Console output
    console: {
      level: 'debug',
      colorize: true,
      timestamp: true,
      format: 'text'
    },
    
    // File output with rotation
    file: {
      level: 'info',
      filename: './logs/basic-app.log',
      format: 'json',
      rotation: {
        maxSize: '5MB',
        maxFiles: 3,
        interval: '1d', // Daily rotation
        compress: true
      }
    }
  }
});

// Basic logging examples
async function basicLogging() {
  console.log('🚀 Starting basic file logging example...');
  
  // Different log levels
  logger.debug('Debug message - only in console');
  logger.info('Info message - console and file', { userId: 123 });
  logger.warn('Warning message', { warning: 'High CPU usage' });
  logger.error('Error message', { error: 'Database connection failed' });
  
  // Logging with structured data
  logger.info('User login', {
    userId: 'user123',
    email: 'user@example.com',
    timestamp: new Date().toISOString(),
    ip: '192.168.1.100'
  });
  
  // Performance timing
  logger.time('database-query');
  await new Promise(resolve => setTimeout(resolve, 100)); // Simulate work
  await logger.timeEnd('database-query');
  
  console.log('✅ Basic logging completed!');
  console.log('📁 Check ./logs/basic-app.log for file output');
  
  // Graceful shutdown
  await logger.close();
}

// Run the example
if (require.main === module) {
  basicLogging().catch(console.error);
}

export { logger };