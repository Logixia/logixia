import { LogixiaLogger } from '../src';
import { TransportConfig } from '../src/types/transport.types';

// Analytics Integration Example
// This example demonstrates how to integrate various analytics tools
// with logixia for comprehensive data tracking and monitoring

const analyticsConfig: TransportConfig = {
  console: {
    level: 'info',
    colorize: true
  },
  analytics: {
    // Mixpanel Configuration
    mixpanel: {
      token: process.env.MIXPANEL_TOKEN || 'your-mixpanel-token',
      apiKey: process.env.MIXPANEL_API_KEY || 'your-mixpanel-api-key',
      batchSize: 50,
      flushInterval: 5000,
      level: 'info'
    },
    
    // DataDog Configuration
    datadog: {
      apiKey: process.env.DATADOG_API_KEY || 'your-datadog-api-key',
      site: 'datadoghq.com',
      service: 'logixia-demo',
      version: '1.0.0',
      batchSize: 100,
      flushInterval: 10000,
      level: 'warn'
    },
    
    // Google Analytics Configuration
    googleAnalytics: {
      measurementId: process.env.GA_MEASUREMENT_ID || 'G-XXXXXXXXXX',
      apiSecret: process.env.GA_API_SECRET || 'your-ga-api-secret',
      apiKey: process.env.GA_API_KEY || 'your-ga-api-key',
      clientId: 'demo-client-123',
      batchSize: 25,
      flushInterval: 3000,
      level: 'info'
    },
    
    // Segment Configuration
    segment: {
      writeKey: process.env.SEGMENT_WRITE_KEY || 'your-segment-write-key',
      apiKey: process.env.SEGMENT_API_KEY || 'your-segment-api-key',
      dataPlaneUrl: 'https://api.segment.io',
      batchSize: 75,
      flushInterval: 7000,
      level: 'info'
    }
  }
};

// Create logger with analytics transports
const logger = new LogixiaLogger({
  appName: 'Analytics Demo',
  environment: 'development',
  transports: analyticsConfig
});

async function demonstrateAnalyticsIntegration() {
  console.log('🚀 Starting Analytics Integration Demo\n');
  
  // Wait for all transports to be ready
  await logger.waitForReady();
  
  // 1. Basic logging with analytics tracking
  console.log('📊 1. Basic Analytics Logging');
  logger.info('User logged in', {
    userId: 'user-123',
    email: 'demo@example.com',
    loginMethod: 'email',
    timestamp: new Date().toISOString()
  });
  
  logger.warn('API rate limit approaching', {
    endpoint: '/api/users',
    currentRequests: 95,
    limit: 100,
    resetTime: new Date(Date.now() + 3600000).toISOString()
  });
  
  // 2. E-commerce tracking
  console.log('\n🛒 2. E-commerce Event Tracking');
  logger.info('Product purchased', {
    eventType: 'purchase',
    productId: 'prod-456',
    productName: 'Premium Subscription',
    price: 29.99,
    currency: 'USD',
    userId: 'user-123',
    orderId: 'order-789'
  });
  
  logger.info('Cart abandoned', {
    eventType: 'cart_abandoned',
    cartValue: 149.97,
    itemCount: 3,
    userId: 'user-456',
    sessionId: 'session-abc'
  });
  
  // 3. Performance monitoring
  console.log('\n⚡ 3. Performance Metrics');
  logger.info('API response time', {
    eventType: 'performance',
    endpoint: '/api/products',
    responseTime: 245,
    statusCode: 200,
    method: 'GET',
    userAgent: 'Mozilla/5.0 (Demo Browser)'
  });
  
  logger.error('Database connection failed', {
    eventType: 'error',
    errorType: 'database_connection',
    errorMessage: 'Connection timeout after 30s',
    retryAttempt: 3,
    maxRetries: 5
  });
  
  // 4. User behavior tracking
  console.log('\n👤 4. User Behavior Analytics');
  logger.info('Page view', {
    eventType: 'page_view',
    page: '/dashboard',
    userId: 'user-123',
    sessionDuration: 1250,
    referrer: 'https://google.com',
    deviceType: 'desktop'
  });
  
  logger.info('Feature used', {
    eventType: 'feature_usage',
    feature: 'export_data',
    userId: 'user-123',
    exportFormat: 'csv',
    recordCount: 1500
  });
  
  // 5. Custom metrics and KPIs
  console.log('\n📈 5. Custom Business Metrics');
  logger.info('Monthly recurring revenue', {
    eventType: 'business_metric',
    metric: 'mrr',
    value: 45000,
    currency: 'USD',
    period: '2024-01',
    growth: 12.5
  });
  
  logger.info('User engagement score', {
    eventType: 'engagement',
    userId: 'user-123',
    score: 85,
    factors: {
      loginFrequency: 0.9,
      featureUsage: 0.8,
      supportTickets: 0.1
    }
  });
  
  // 6. A/B testing events
  console.log('\n🧪 6. A/B Testing Analytics');
  logger.info('A/B test exposure', {
    eventType: 'ab_test',
    testName: 'checkout_flow_v2',
    variant: 'treatment',
    userId: 'user-789',
    exposureTime: new Date().toISOString()
  });
  
  logger.info('A/B test conversion', {
    eventType: 'ab_conversion',
    testName: 'checkout_flow_v2',
    variant: 'treatment',
    userId: 'user-789',
    conversionType: 'purchase',
    conversionValue: 99.99
  });
  
  // Wait a moment for batch processing
  console.log('\n⏳ Waiting for batch processing...');
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Force flush all analytics transports
  console.log('\n🔄 Flushing all analytics data...');
  await logger.flush();
  
  // Display transport metrics
  console.log('\n📊 Transport Metrics:');
  const metrics = logger.getMetrics();
  metrics.forEach((metric: any) => {
    if (metric.type === 'analytics') {
      console.log(`  ${metric.name}: ${metric.logsWritten} events sent, ${metric.errors} errors`);
    }
  });
  
  console.log('\n✅ Analytics Integration Demo Complete!');
  console.log('\n💡 Tips:');
  console.log('  - Set environment variables for API keys in production');
  console.log('  - Adjust batch sizes and flush intervals based on your needs');
  console.log('  - Use different log levels for different analytics tools');
  console.log('  - Monitor transport metrics for debugging and optimization');
}

// Error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await logger.close();
  process.exit(0);
});

// Run the demo
if (require.main === module) {
  demonstrateAnalyticsIntegration().catch(console.error);
}

export { demonstrateAnalyticsIntegration, analyticsConfig };