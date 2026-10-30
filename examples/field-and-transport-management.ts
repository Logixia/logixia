import { createLogger } from '../src';

// Example demonstrating field management and transport level selection
async function demonstrateFieldAndTransportManagement() {
  console.log('🚀 Field and Transport Management Demo\n');

  // Create logger with multiple transports
  const logger = createLogger({
    appName: 'FieldTransportDemo',
    environment: 'development',
    transports: {
      console: {
        level: 'info'
      },
      file: {
        filename: 'app.log'
      },
      database: {
        type: 'mongodb',
        level: 'error',
        database: 'logs',
        connectionString: 'mongodb://localhost:27017/logs'
      }
    },
    fields: {
      timestamp: '[yyyy-mm-dd HH:MM:ss.MS]',
      level: '[log_level]',
      appName: '[app_name]',
      traceId: '[trace_id]',
      message: '[message]',
      payload: '[payload]'
    }
  });

  console.log('📋 Available transports:', logger.getAvailableTransports());
  console.log('📊 Current field state:', logger.getFieldState());
  console.log();

  // Demonstrate field management
  console.log('=== Field Management Demo ===');
  
  await logger.info('Initial log with all fields enabled', { userId: 123, action: 'login' });
  
  // Disable some fields
  logger.disableField('traceId');
  logger.disableField('appName');
  
  await logger.info('Log with traceId and appName disabled', { userId: 123, action: 'view_profile' });
  
  // Re-enable fields
  logger.enableField('traceId');
  
  await logger.info('Log with traceId re-enabled', { userId: 123, action: 'logout' });
  
  console.log('📊 Updated field state:', logger.getFieldState());
  console.log();

  // Demonstrate transport level management
  console.log('=== Transport Level Management Demo ===');
  
  // Enable prompting for transport levels (commented out for demo)
  // logger.enableTransportLevelPrompting();
  
  // Set specific levels for transports programmatically
  logger.setTransportLevels('console', ['error', 'warn', 'info']);
  logger.setTransportLevels('file', ['error', 'warn', 'info', 'debug']);
  logger.setTransportLevels('database', ['error']);
  
  console.log('🎯 Console transport levels:', logger.getTransportLevels('console'));
  console.log('🎯 File transport levels:', logger.getTransportLevels('file'));
  console.log('🎯 Database transport levels:', logger.getTransportLevels('database'));
  console.log();
  
  // Test different log levels
  console.log('Testing different log levels with transport filtering:');
  
  await logger.error('This should go to all transports', { error: 'Critical error' });
  await logger.warn('This should go to console and file', { warning: 'Performance warning' });
  await logger.info('This should go to console and file', { info: 'User action' });
  await logger.debug('This should only go to file', { debug: 'Debug information' });
  await logger.trace('This should not go anywhere (not configured)', { trace: 'Trace data' });
  
  console.log();
  
  // Reset field state
  logger.resetFieldState();
  console.log('🔄 Field state reset');
  console.log('📊 Field state after reset:', logger.getFieldState());
  
  await logger.info('Log after field state reset', { final: true });
  
  // Clear transport preferences
  logger.clearTransportLevelPreferences();
  console.log('🧹 Transport level preferences cleared');
  
  await logger.close();
  console.log('✅ Demo completed');
}

// Interactive example for user prompting
async function interactiveTransportConfiguration() {
  console.log('\n🔧 Interactive Transport Configuration Demo\n');
  
  const logger = createLogger({
    appName: 'InteractiveDemo',
    transports: {
      console: {},
      file: { filename: 'interactive.log' }
    }
  });
  
  // Enable interactive prompting
  logger.enableTransportLevelPrompting();
  
  console.log('📝 The next log will prompt you to configure transport levels...');
  
  // This will trigger prompts for each transport
  await logger.info('This log will trigger transport configuration prompts');
  
  // Subsequent logs will use the configured levels
  await logger.error('Error log');
  await logger.warn('Warning log');
  await logger.info('Info log');
  await logger.debug('Debug log');
  
  await logger.close();
}

// Run the demos
if (require.main === module) {
  demonstrateFieldAndTransportManagement()
    .then(() => {
      console.log('\n' + '='.repeat(50));
      console.log('Run with --interactive flag for interactive demo');
      
      if (process.argv.includes('--interactive')) {
        return interactiveTransportConfiguration();
      }
      return Promise.resolve();
    })
    .catch(console.error);
}

export { demonstrateFieldAndTransportManagement, interactiveTransportConfiguration };