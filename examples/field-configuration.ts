/**
 * Field Configuration Example for logixia Logger
 * Demonstrates how to enable/disable fields and customize their formats
 */

import { LogixiaLogger } from '../src/core/logitron-logger';
import { LoggerConfig, LogColor } from '../src/types';

// Example 1: Basic field configuration
const basicConfig: LoggerConfig = {
  level: 'info',
  service: 'FieldDemo',
  environment: 'development',
  formatters: ['text'],
  outputs: ['console'],
  levelOptions: {
    level: 'info',
    levels: {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      verbose: 4,
      trace: 5
    },
    colors: {
      error: 'red',
      warn: 'yellow',
      info: 'green',
      debug: 'blue',
      verbose: 'cyan',
      trace: 'magenta'
    }
  },
  // Enable/disable specific fields
  fields: {
    timestamp: '[yyyy-mm-dd HH:MM:ss.MS]', // Custom format
    level: true,                            // Enable with default format
    appName: false,                         // Disable this field
    service: '[service_name]',              // Custom format
    traceId: true,                          // Enable
    message: true,                          // Enable
    payload: true,                          // Enable
    timeTaken: '[duration_ms]',             // Custom format
    context: true,                          // Enable context
    environment: false                      // Disable environment
  }
};

// Example 2: Minimal field configuration
const minimalConfig: LoggerConfig = {
  level: 'info',
  service: 'MinimalDemo',
  environment: 'production',
  formatters: ['text'],
  outputs: ['console'],
  levelOptions: {
    level: 'info',
    levels: {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      verbose: 4,
      trace: 5
    },
    colors: {
      error: 'brightRed',
      warn: 'brightYellow',
      info: 'brightGreen',
      debug: 'brightBlue',
      verbose: 'brightCyan',
      trace: 'brightMagenta'
    }
  },
  // Only show essential fields
  fields: {
    timestamp: false,    // Hide timestamp
    level: true,         // Show level
    appName: false,      // Hide app name
    service: false,      // Hide service
    traceId: false,      // Hide trace ID
    message: true,       // Show message
    payload: true,       // Show payload
    timeTaken: false,    // Hide timing
    context: false       // Hide context
  }
};

// Example 3: Custom colors and levels
const customConfig: LoggerConfig = {
  level: 'debug',
  service: 'CustomDemo',
  environment: 'development',
  formatters: ['text'],
  outputs: ['console'],
  levelOptions: {
    level: 'debug',
    levels: {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      verbose: 4,
      trace: 5,
      // Custom levels
      analytics: 6,
      audit: 7
    },
    colors: {
      error: 'brightRed',
      warn: 'brightYellow',
      info: 'brightGreen',
      debug: 'brightBlue',
      verbose: 'brightCyan',
      trace: 'brightMagenta',
      // Custom colors
      analytics: 'gray',
      audit: 'brightWhite'
    }
  },
  fields: {
    timestamp: '[HH:MM:ss]',        // Short timestamp format
    level: '[LEVEL]',             // Custom level format
    service: '[SVC]',             // Short service format
    message: true,
    payload: true,
    context: '[CTX]'              // Custom context format
  }
};

async function demonstrateFieldConfiguration() {
  console.log('=== Field Configuration Examples ===\n');

  // Demo 1: Basic configuration
  console.log('1. Basic Field Configuration:');
  const basicLogger = new LogixiaLogger(basicConfig);
  await basicLogger.info('This is a basic log message', { userId: 123 });
  await basicLogger.warn('Warning with custom fields');
  await basicLogger.error('Error message', { errorCode: 'E001' });
  console.log('');

  // Demo 2: Minimal configuration
  console.log('2. Minimal Field Configuration:');
  const minimalLogger = new LogixiaLogger(minimalConfig);
  await minimalLogger.info('Minimal log output');
  await minimalLogger.debug('Debug message with minimal fields');
  console.log('');

  // Demo 3: Custom configuration
  console.log('3. Custom Levels and Colors:');
  const customLogger = new LogixiaLogger(customConfig);
  await customLogger.info('Custom configuration demo');
  await customLogger.debug('Debug with custom format');
  
  // Using custom log method (if implemented)
  try {
    // @ts-ignore - Custom levels might not be in interface yet
    await customLogger.log('analytics', 'Analytics event', { event: 'user_click' });
    // @ts-ignore
    await customLogger.log('audit', 'Audit trail', { action: 'user_login', userId: 456 });
  } catch (error) {
    console.log('Custom levels not yet implemented in core logger');
  }
  console.log('');

  // Demo 4: Field toggling at runtime
  console.log('4. Runtime Field Configuration:');
  const runtimeLogger = new LogixiaLogger({
    ...basicConfig,
    fields: {
      timestamp: true,
      level: true,
      message: true,
      payload: false  // Initially disabled
    }
  });
  
  await runtimeLogger.info('Log without payload field');
  
  // Enable payload field (conceptual - would need implementation)
  console.log('(Field toggling at runtime would require additional implementation)');
  console.log('');

  console.log('=== Field Configuration Demo Complete ===');
}

// Run the demonstration
if (require.main === module) {
  demonstrateFieldConfiguration().catch(console.error);
}

export { demonstrateFieldConfiguration };