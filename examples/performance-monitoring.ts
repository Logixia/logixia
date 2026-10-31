/**
 * Performance monitoring example using logixia
 */

import { createLogger, LogLevel } from '../src';

// Create logger with performance focus
const logger = createLogger({
  appName: 'PerformanceApp',
  environment: 'development',
  traceId: true,
  format: {
    timestamp: true,
    colorize: false,
    json: true // JSON format for better parsing in production
  },
  levelOptions: {
    level: LogLevel.INFO,
    levels: {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      trace: 4,
      verbose: 5
    },
    colors: {
      error: 'red',
      warn: 'yellow',
      info: 'green',
      debug: 'blue',
      trace: 'magenta',
      verbose: 'cyan'
    }
  },
  fields: {
    timestamp: '[yyyy-mm-dd HH:MM:ss.MS]',
    level: '[log_level]',
    appName: '[app_name]',
    traceId: '[trace_id]',
    message: '[message]',
    payload: '[payload]',
    timeTaken: '[time_taken_MS]'
  }
});

// Simulate database operations
class DatabaseService {
  async findUser(id: string) {
    logger.time(`db-find-user-${id}`);
    
    // Simulate database query
    await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
    
    const timeTaken = await logger.timeEnd(`db-find-user-${id}`);
    
    await logger.info('Database query completed', {
      operation: 'findUser',
      userId: id,
      timeTaken: `${timeTaken}ms`
    });
    
    return { id, name: `User ${id}`, email: `user${id}@example.com` };
  }
  
  async createUser(userData: any) {
    return await logger.timeAsync('db-create-user', async () => {
      await new Promise(resolve => setTimeout(resolve, Math.random() * 200 + 100));
      
      const user = { id: Date.now().toString(), ...userData };
      
      await logger.info('User created in database', {
        operation: 'createUser',
        userId: user.id,
        userData
      });
      
      return user;
    });
  }
  
  async updateUser(id: string, updates: any) {
    const dbLogger = logger.child('DatabaseService', { operation: 'updateUser', userId: id });
    
    dbLogger.time('update-operation');
    
    try {
      // Simulate update operation
      await new Promise(resolve => setTimeout(resolve, Math.random() * 150 + 75));
      
      const timeTaken = await dbLogger.timeEnd('update-operation');
      
      await dbLogger.info('User updated successfully', {
        updates,
        timeTaken: `${timeTaken}ms`
      });
      
      return { id, ...updates };
    } catch (error) {
      await dbLogger.error(error as Error, { updates });
      throw error;
    }
  }
}

// Simulate API service
class ApiService {
  private db = new DatabaseService();
  
  async processUserRequest(userId: string) {
    const apiLogger = logger.child('ApiService', { userId });
    
    return await apiLogger.timeAsync('process-user-request', async () => {
      await apiLogger.info('Processing user request started');
      
      // Multiple operations with individual timing
      const user = await this.db.findUser(userId);
      
      // Simulate external API call
      const enrichedData = await apiLogger.timeAsync('external-api-call', async () => {
        await new Promise(resolve => setTimeout(resolve, Math.random() * 300 + 200));
        return { ...user, preferences: { theme: 'dark', language: 'en' } };
      });
      
      await apiLogger.info('User request processed successfully', {
        enrichedData
      });
      
      return enrichedData;
    });
  }
  
  async batchProcessUsers(userIds: string[]) {
    const batchLogger = logger.child('ApiService', { operation: 'batchProcess', count: userIds.length });
    
    await batchLogger.info('Starting batch processing');
    
    const results: any[] = [];
    
    for (const userId of userIds) {
      try {
        const result = await this.processUserRequest(userId);
        results.push(result);
      } catch (error) {
        await batchLogger.error(error as Error, { userId });
        results.push({ error: 'Failed to process user', userId });
      }
    }
    
    await batchLogger.info('Batch processing completed', {
      totalProcessed: results.length,
      successful: results.filter((r: any) => !r.error).length,
      failed: results.filter((r: any) => r.error).length
    });
    
    return results;
  }
}

// Performance monitoring utilities
class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();
  
  async recordMetric(name: string, value: number) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    
    this.metrics.get(name)!.push(value);
    
    await logger.debug('Metric recorded', { name, value });
  }
  
  async getMetricsSummary(name: string) {
    const values = this.metrics.get(name) || [];
    
    if (values.length === 0) {
      return null;
    }
    
    const sorted = [...values].sort((a, b) => a - b);
    const summary = {
      count: values.length,
      min: Math.min(...values),
      max: Math.max(...values),
      avg: values.reduce((a, b) => a + b, 0) / values.length,
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };
    
    await logger.info('Metrics summary', { metric: name, summary });
    
    return summary;
  }
  
  async logAllMetrics() {
    await logger.info('Performance metrics summary');
    
    for (const [name] of this.metrics) {
      await this.getMetricsSummary(name);
    }
  }
}

// Example usage
async function performanceExample() {
  const apiService = new ApiService();
  const monitor = new PerformanceMonitor();
  
  await logger.info('Starting performance monitoring example');
  
  // Single user processing
  const singleResult = await apiService.processUserRequest('123');
  await logger.info('Single user processing completed', { result: singleResult });
  
  // Batch processing
  const userIds = ['1', '2', '3', '4', '5'];
  await apiService.batchProcessUsers(userIds);
  
  // Record some custom metrics
  for (let i = 0; i < 10; i++) {
    const responseTime = Math.random() * 1000 + 100;
    await monitor.recordMetric('api_response_time', responseTime);
  }
  
  // Generate metrics summary
  await monitor.logAllMetrics();
  
  await logger.info('Performance monitoring example completed');
}

// Memory usage monitoring
function logMemoryUsage() {
  const usage = process.memoryUsage();
  logger.info('Memory usage', {
    rss: `${Math.round(usage.rss / 1024 / 1024)}MB`,
    heapTotal: `${Math.round(usage.heapTotal / 1024 / 1024)}MB`,
    heapUsed: `${Math.round(usage.heapUsed / 1024 / 1024)}MB`,
    external: `${Math.round(usage.external / 1024 / 1024)}MB`
  });
}

// Run the example
if (require.main === module) {
  performanceExample()
    .then(() => {
      logMemoryUsage();
      logger.close();
    })
    .catch(async (error) => {
      await logger.error(error);
      process.exit(1);
    });
}

export { DatabaseService, ApiService, PerformanceMonitor, performanceExample };