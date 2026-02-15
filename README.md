# Logixia

**Enterprise-grade TypeScript logging library with comprehensive transport system, database integration, and advanced log management capabilities**

[![npm version](https://badge.fury.io/js/logixia.svg)](https://badge.fury.io/js/logixia)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-16+-green.svg)](https://nodejs.org/)
[![Hacktoberfest](https://img.shields.io/badge/Hacktoberfest-2025-orange.svg)](https://hacktoberfest.com/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Good First Issues](https://img.shields.io/github/issues/Logixia/logixia/good%20first%20issue?color=7057ff&label=good%20first%20issues)](https://github.com/Logixia/logixia/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
[![Contributors](https://img.shields.io/github/contributors/Logixia/logixia.svg)](https://github.com/Logixia/logixia/graphs/contributors)

## Features

### Core Logging Capabilities
- **TypeScript-First Architecture**: Complete type safety with intelligent IntelliSense support
- **Custom Log Levels**: Define application-specific log levels with configurable priorities and colors
- **Structured Logging**: Rich metadata support with nested object logging
- **Async/Await Support**: Full asynchronous operation support with proper error handling
- **Child Logger System**: Hierarchical logger creation with inherited context

### Transport System
- **Multiple Output Destinations**: Simultaneous logging to console, files, and databases
- **Console Transport**: Configurable console output with colorization and formatting options
- **File Transport**: Advanced file logging with rotation, compression, and cleanup
- **Database Transport**: Native support for MongoDB, PostgreSQL, MySQL, and SQLite
- **Custom Transport Support**: Extensible architecture for implementing custom log destinations

### Advanced Log Management
- **Log Rotation**: Time-based and size-based rotation with configurable intervals
- **Batch Processing**: Efficient batch writing with configurable batch sizes and flush intervals
- **Compression Support**: Automatic compression of rotated log files
- **Retention Policies**: Configurable cleanup of old log files based on count or age
- **Health Monitoring**: Built-in transport health checking and status reporting

### Performance and Monitoring
- **Performance Timing**: Built-in timing utilities for operation measurement
- **Trace ID Support**: Request tracing with async context propagation
- **Metrics Collection**: Transport-level metrics and performance monitoring
- **Resource Management**: Proper connection pooling and resource cleanup

### Framework Integration
- **NestJS Integration**: First-class NestJS module with dependency injection support
- **Express Middleware**: Ready-to-use Express middleware for request tracking
- **Field Configuration**: Granular control over log field inclusion and formatting

## Installation

```bash
# Using npm
npm install logixia

# Using yarn
yarn add logixia

# Using pnpm
pnpm add logixia
```

### Optional Database Dependencies

For database transport functionality, install the appropriate database drivers:

```bash
# MongoDB support
npm install mongodb

# PostgreSQL support
npm install pg @types/pg

# MySQL support
npm install mysql2

# SQLite support
npm install sqlite3 sqlite
```

## Quick Start

### Basic Usage

```typescript
import { createLogger } from 'logixia';

// Create a basic logger instance
const logger = createLogger({
  appName: 'MyApplication',
  environment: 'development'
});

// Basic logging operations
await logger.info('Application started', { version: '1.0.1', port: 3000 });
await logger.warn('High memory usage detected', { memoryUsage: '85%' });
await logger.error('Database connection failed', new Error('Connection timeout'));
```

### Multi-Transport Configuration

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'ProductionApp',
  environment: 'production',
  transports: {
    console: {
      level: 'info',
      colorize: true,
      format: 'text'
    },
    file: {
      filename: './logs/application.log',
      level: 'debug',
      format: 'json',
      rotation: {
        interval: '1d',
        maxFiles: 30,
        compress: true
      }
    },
    database: {
      type: 'mongodb',
      connectionString: 'mongodb://localhost:27017/logs',
      database: 'application_logs',
      collection: 'error_logs',
      batchSize: 100,
      flushInterval: 5000
    }
  }
});

// Logs will be written to console, file, and database simultaneously
await logger.error('Critical system error', {
  errorCode: 'SYS_001',
  component: 'database',
  severity: 'critical'
});
```

### Performance Monitoring

```typescript
// Simple timing
logger.time('database-query');
const users = await database.findUsers();
const duration = await logger.timeEnd('database-query');

// Async timing with automatic logging
const result = await logger.timeAsync('api-call', async () => {
  const response = await fetch('/api/users');
  return response.json();
});
```

## CLI Tool

Logixia includes a powerful command-line interface for log management, analysis, and monitoring. The CLI provides tools for analyzing log files, searching for patterns, exporting data, and monitoring logs in real-time.

### Installation

The CLI is included when you install Logixia globally:

```bash
npm install -g logixia
```

Or use it directly from your project:

```bash
npx logixia --help
```

### Available Commands

#### Analyze Command

Analyze log files for patterns, statistics, and insights:

```bash
# Basic analysis
logixia analyze examples/sample.log

# Filter by log level
logixia analyze app.log --level error

# Analyze logs from the last 24 hours
logixia analyze app.log --last 24h

# Output as JSON
logixia analyze app.log --format json
```

**Options:**
- `--level <level>`: Filter by log level (info, warn, error, debug)
- `--last <range>`: Time range (e.g., 24h, 7d, 30m)
- `--format <fmt>`: Output format (table, json) - default: table

#### Stats Command

Display detailed statistics for log files:

```bash
# Show statistics with pretty formatting
logixia stats examples/sample.log

# Group by different field
logixia stats app.log --group-by service

# Output as JSON
logixia stats app.log --format json
```

**Output Example:**
```
Log Statistics for sample.log
==================================================
Total Entries: 20
Time Range: 2025-10-15T08:00:00.000Z - 2025-10-15T08:19:23.456Z

Level Distribution:
  INFO             11 ( 55.0%) ████████████████
  ERROR             5 ( 25.0%) ███████
  WARN              3 ( 15.0%) ████
  DEBUG             1 (  5.0%) █
```

**Options:**
- `--group-by <field>`: Field to group by (default: level)
- `--format <fmt>`: Output format (pretty, json) - default: pretty

#### Search Command

Search log files with powerful query syntax:

```bash
# Search for specific user
logixia search app.log --query "user_id:123"

# Search for error messages
logixia search app.log --query "error"

# Output as table
logixia search app.log --query "user_id:123" --format table

# Output as JSON
logixia search app.log --query "level:error" --format json
```

**Query Syntax:**
- `field:value`: Search specific field (e.g., `user_id:123`, `level:error`)
- `text`: Search across all fields

**Options:**
- `--query <query>`: Search query (required)
- `--format <fmt>`: Output format (line, table, json) - default: line
- `--context <lines>`: Lines of context around matches - default: 0

#### Export Command

Export log files to different formats:

```bash
# Export to CSV
logixia export app.log --format csv --output logs.csv

# Export specific fields
logixia export app.log --format csv --fields "timestamp,level,message"

# Export to JSON
logixia export app.log --format json --output logs.json

# Export to stdout
logixia export app.log --format csv --fields "timestamp,level,message"
```

**Options:**
- `--format <fmt>`: Output format (csv, json) - default: json
- `--fields <fields>`: Comma-separated list of fields to export
- `--output <file>`: Output file path (default: stdout)

#### Tail Command

Monitor log files in real-time:

```bash
# View last 10 lines
logixia tail app.log

# Follow file changes
logixia tail app.log --follow

# Filter by log level
logixia tail app.log --follow --filter level:error

# Filter by user ID
logixia tail app.log --follow --filter user_id:123

# Highlight patterns with colors
logixia tail app.log --follow --highlight level
```

**Options:**
- `--follow`: Follow file changes (like `tail -f`)
- `--filter <filter>`: Filter criteria (e.g., `level:error`, `user_id:123`)
- `--highlight <pattern>`: Highlight pattern or color by level

### CLI Examples

#### Daily Operations

```bash
# Morning log review - check errors from yesterday
logixia analyze yesterday.log --level error

# Check stats for the week
logixia stats app.log

# Find all logs for a specific user
logixia search app.log --query "user_id:456" --format table
```

#### Development Workflow

```bash
# Debug session - follow logs for specific user
logixia tail debug.log --follow --filter user_id:123 --highlight level

# Export logs for analysis
logixia export app.log --format csv --fields "timestamp,level,message,user_id" --output analysis.csv

# Search for specific errors
logixia search app.log --query "Database connection timeout"
```

#### Production Monitoring

```bash
# Monitor production logs in real-time
logixia tail production.log --follow --filter level:error

# Analyze error patterns
logixia analyze production.log --level error --last 24h

# Generate daily report
logixia stats production.log --format json > daily-report.json
```

### Sample Log File

A sample log file is included at `examples/sample.log` for testing CLI commands:

```bash
# Try the CLI with the sample file
logixia analyze examples/sample.log
logixia stats examples/sample.log
logixia search examples/sample.log --query "user_id:123" --format table
logixia export examples/sample.log --format csv --fields "timestamp,level,message"
```

### CLI Development

To contribute to the CLI or run it in development mode:

```bash
# Run CLI in development (uses ts-node)
npm run cli:dev -- --help

# Build CLI
npm run cli:build

# Run compiled CLI
node dist/cli/index.js --help
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details on CLI development.

## Custom Log Levels

Define application-specific log levels with custom priorities and visual styling:

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'EcommerceApplication',
  levelOptions: {
    level: 'info',
    levels: {
      // Standard logging levels
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      // Business-specific levels
      order: 2,      // Order processing events
      payment: 1,    // Payment processing (high priority)
      inventory: 2,  // Inventory management operations
      customer: 3,   // Customer interaction tracking
      audit: 0,      // Audit trail (highest priority)
    },
    colors: {
      error: 'red',
      warn: 'yellow',
      info: 'blue',
      debug: 'green',
      order: 'brightBlue',
      payment: 'brightYellow',
      inventory: 'cyan',
      customer: 'brightGreen',
      audit: 'brightRed',
    }
  }
});

// Utilize custom levels with complete TypeScript support
await logger.order('Order processing initiated', {
  orderId: 'ORD-12345',
  customerId: 'CUST-67890',
  items: 3,
  totalAmount: 299.97
});

await logger.payment('Payment transaction completed', {
  transactionId: 'TXN-98765',
  amount: 299.97,
  method: 'credit_card',
  processor: 'stripe'
});

await logger.inventory('Stock level updated', {
  productId: 'PROD-ABC123',
  previousQuantity: 25,
  newQuantity: 50,
  operation: 'restock'
});

await logger.audit('User permission modified', {
  userId: 'USER-456',
  action: 'permission_grant',
  permission: 'admin_access',
  modifiedBy: 'USER-123'
});
```

## NestJS Integration

### Module Configuration

Integrate Logixia seamlessly into your NestJS application with full dependency injection support:

```typescript
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'NestJS-Application',
      environment: 'production',
      traceId: true,
      levelOptions: {
        level: 'info',
        levels: {
          error: 0,
          warn: 1,
          info: 2,
          debug: 3,
          verbose: 4
        }
      },
      transports: {
        console: {
          level: 'info',
          colorize: true,
          format: 'text'
        },
        file: {
          filename: './logs/nestjs-app.log',
          level: 'debug',
          format: 'json',
          rotation: {
            interval: '1d',
            maxFiles: 30
          }
        },
        database: {
          type: 'mongodb',
          connectionString: process.env.MONGODB_URI,
          database: 'application_logs',
          collection: 'nestjs_logs'
        }
      }
    })
  ],
})
export class AppModule {}
```

### Service Usage

```typescript
import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService } from 'logixia';

@Injectable()
export class UserService {
  constructor(private readonly logger: LogixiaLoggerService) {
    this.logger.setContext('UserService');
  }

  async findUser(id: string) {
    await this.logger.info('Fetching user', { userId: id });
    
    try {
      const user = await this.userRepository.findById(id);
      await this.logger.info('User found', { userId: id });
      return user;
    } catch (error) {
      await this.logger.error('User not found', { userId: id, error });
      throw error;
    }
  }

  async createUser(userData: any) {
    const childLogger = this.logger.child('createUser', { operation: 'create' });
    
    return await childLogger.timeAsync('user-creation', async () => {
      await childLogger.info('Creating user', { userData });
      const user = await this.userRepository.create(userData);
      await childLogger.info('User created', { userId: user.id });
      return user;
    });
  }
}
```

## Interceptors

### Kafka and WebSocket Interceptors

Logixia provides specialized interceptors for Kafka and WebSocket applications to automatically extract and propagate trace IDs across distributed systems.

#### Kafka Trace Interceptor

Automatically extract trace IDs from Kafka messages and add them to the logging context:

```typescript
import { KafkaTraceInterceptor } from 'logixia';
import { Controller, Post, Body, UseInterceptors } from '@nestjs/common';

@Controller('kafka')
@UseInterceptors(KafkaTraceInterceptor)
export class KafkaController {
  @Post('process-message')
  async processMessage(@Body() message: any) {
    // Trace ID is automatically extracted from message headers or body
    // and added to the logging context
    await this.logger.info('Processing Kafka message', {
      messageId: message.id,
      topic: message.topic
    });
    
    return { status: 'processed' };
  }
}
```

#### WebSocket Trace Interceptor

Extract trace IDs from WebSocket messages and maintain trace context across WebSocket connections:

```typescript
import { WebSocketTraceInterceptor } from 'logixia';
import { WebSocketGateway, SubscribeMessage, UseInterceptors } from '@nestjs/websockets';

@WebSocketGateway()
@UseInterceptors(WebSocketTraceInterceptor)
export class ChatGateway {
  @SubscribeMessage('message')
  async handleMessage(client: any, payload: any) {
    // Trace ID is automatically extracted from payload headers or query parameters
    await this.logger.info('WebSocket message received', {
      clientId: client.id,
      messageType: payload.type
    });
    
    return { event: 'response', data: 'Message processed' };
  }
}
```

#### Configuration

Configure interceptors through the LogixiaLoggerModule:

```typescript
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'MyApplication',
      environment: 'production',
      traceId: {
        enabled: true,
        extractor: {
          header: ['x-trace-id', 'x-request-id'],
          query: ['traceId'],
          body: ['traceId', 'requestId']
        }
      },
      transports: {
        console: { level: 'info' },
        file: { filename: './logs/app.log', level: 'debug' }
      }
    })
  ]
})
export class AppModule {}
```

#### Key Features

- **Automatic Trace Extraction**: Extracts trace IDs from headers, query parameters, or message body
- **Enable/Disable Support**: Can be enabled or disabled through configuration
- **No Auto-Generation**: Only uses existing trace IDs, doesn't generate new ones
- **Flexible Configuration**: Supports multiple extraction sources and patterns
- **Performance Optimized**: Minimal overhead when disabled

#### Usage with Custom Configuration

```typescript
// Async configuration with custom trace settings
LogixiaLoggerModule.forRootAsync({
  useFactory: async (configService: ConfigService) => ({
    appName: configService.get('APP_NAME'),
    environment: configService.get('NODE_ENV'),
    traceId: {
      enabled: configService.get('TRACE_ENABLED', true),
      extractor: {
        header: ['x-correlation-id', 'x-trace-id'],
        query: ['correlationId'],
        body: ['traceId']
      }
    },
    transports: {
      console: { level: 'info' },
      database: {
        type: 'mongodb',
        connectionString: configService.get('MONGODB_URI'),
        database: 'logs',
        collection: 'application_logs'
      }
    }
  }),
  inject: [ConfigService]
})
```

## Express Integration

Integrate comprehensive logging into Express applications with automatic request tracking and performance monitoring:

```typescript
import express from 'express';
import { createLogger, traceMiddleware, getCurrentTraceId } from 'logixia';

const app = express();
const logger = createLogger({
  appName: 'ExpressApplication',
  environment: 'production',
  transports: {
    console: { level: 'info', colorize: true },
    file: {
      filename: './logs/express-app.log',
      level: 'debug',
      format: 'json'
    },
    database: {
      type: 'mongodb',
      connectionString: process.env.MONGODB_URI,
      database: 'application_logs',
      collection: 'express_logs'
    }
  }
});

// Configure trace middleware for request tracking
app.use(traceMiddleware({
  enabled: true,
  extractor: {
    header: ['x-trace-id', 'x-request-id', 'x-correlation-id'],
    query: ['traceId', 'requestId']
  },
  generator: () => `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}));

// Request logging middleware with comprehensive context
app.use(async (req, res, next) => {
  const startTime = Date.now();
  const traceId = getCurrentTraceId();
  
  await logger.info('HTTP request initiated', {
    method: req.method,
    path: req.path,
    query: req.query,
    traceId,
    userAgent: req.get('User-Agent'),
    clientIp: req.ip,
    contentType: req.get('Content-Type')
  });
  
  // Log response when request completes
  res.on('finish', async () => {
    const duration = Date.now() - startTime;
    await logger.info('HTTP request completed', {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      traceId,
      contentLength: res.get('Content-Length')
    });
  });
  
  next();
});

// Error handling middleware
app.use(async (error, req, res, next) => {
  await logger.error('HTTP request error', {
    error: error.message,
    stack: error.stack,
    method: req.method,
    path: req.path,
    traceId: getCurrentTraceId(),
    statusCode: error.statusCode || 500
  });
  
  res.status(error.statusCode || 500).json({
    error: 'Internal Server Error',
    traceId: getCurrentTraceId()
  });
});

// Example route with contextual logging
app.get('/users/:id', async (req, res) => {
  const { id } = req.params;
  const userLogger = logger.child('UserController', {
    userId: id,
    operation: 'fetchUser'
  });
  
  try {
    const userData = await userLogger.timeAsync('database-fetch-user', async () => {
      // Simulate database operation
      await new Promise(resolve => setTimeout(resolve, 100));
      return {
        id,
        name: 'John Doe',
        email: 'john.doe@example.com',
        lastLogin: new Date().toISOString()
      };
    });
    
    await userLogger.info('User data retrieved successfully', {
      userId: id,
      fieldsReturned: Object.keys(userData).length
    });
    
    res.json(userData);
  } catch (error) {
    await userLogger.error('Failed to retrieve user data', {
      userId: id,
      error: error.message
    });
    
    res.status(500).json({
      error: 'Failed to retrieve user',
      traceId: getCurrentTraceId()
    });
  }
});

// Health check endpoint with logging
app.get('/health', async (req, res) => {
  const healthLogger = logger.child('HealthCheck');
  
  try {
    // Check database connectivity
    const dbHealth = await healthLogger.timeAsync('database-health-check', async () => {
      // Simulate health check
      return { status: 'healthy', latency: 45 };
    });
    
    await healthLogger.info('Health check completed', {
      database: dbHealth,
      uptime: process.uptime(),
      memory: process.memoryUsage()
    });
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        database: dbHealth
      }
    });
  } catch (error) {
    await healthLogger.error('Health check failed', {
      error: error.message
    });
    
    res.status(503).json({
      status: 'unhealthy',
      error: 'Service unavailable'
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await logger.info('Express server started', {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version
  });
});
```

## Performance Monitoring

Built-in performance monitoring capabilities for tracking operation durations and system metrics:

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'PerformanceMonitoringApp',
  environment: 'production',
  transports: {
    console: { level: 'info', format: 'text' },
    file: {
      filename: './logs/performance.log',
      level: 'debug',
      format: 'json' // Structured format for performance analysis
    },
    database: {
      type: 'mongodb',
      connectionString: process.env.MONGODB_URI,
      database: 'performance_logs',
      collection: 'timing_metrics'
    }
  }
});

class DatabaseService {
  private db: any; // Your database instance
  
  async findUser(id: string) {
    // Manual timing with detailed context
    const timerLabel = `database-find-user-${id}`;
    logger.time(timerLabel);
    
    try {
      const user = await this.db.findById(id);
      const duration = await logger.timeEnd(timerLabel);
      
      await logger.info('Database query completed successfully', {
        operation: 'findUser',
        userId: id,
        duration: `${duration}ms`,
        recordsFound: user ? 1 : 0,
        queryType: 'single_record_lookup'
      });
      
      return user;
    } catch (error) {
      await logger.timeEnd(timerLabel); // Still record timing on error
      await logger.error('Database query failed', {
        operation: 'findUser',
        userId: id,
        error: error.message
      });
      throw error;
    }
  }
  
  async createUser(userData: any) {
    // Automatic timing with comprehensive logging
    return await logger.timeAsync('database-create-user', async () => {
      await logger.debug('User creation initiated', {
        operation: 'createUser',
        dataFields: Object.keys(userData),
        estimatedSize: JSON.stringify(userData).length
      });
      
      const user = await this.db.create(userData);
      
      await logger.info('User created successfully', {
        operation: 'createUser',
        userId: user.id,
        createdFields: Object.keys(user).length
      });
      
      return user;
    }, {
      operationType: 'database_write',
      tableName: 'users',
      recordType: 'user_profile'
    });
  }
  
  async findUsersByQuery(query: any, limit: number = 100) {
    // Complex operation timing with nested operations
    const queryLogger = logger.child('DatabaseQuery', {
      operation: 'findUsersByQuery',
      queryComplexity: Object.keys(query).length,
      resultLimit: limit
    });
    
    return await queryLogger.timeAsync('complex-user-query', async () => {
      // Simulate query parsing time
      await queryLogger.timeAsync('query-parsing', async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
      });
      
      // Simulate database execution time
      const results = await queryLogger.timeAsync('database-execution', async () => {
        const users = await this.db.find(query).limit(limit);
        return users;
      });
      
      // Simulate result processing time
      const processedResults = await queryLogger.timeAsync('result-processing', async () => {
        return results.map(user => ({
          ...user,
          lastAccessed: new Date().toISOString()
        }));
      });
      
      await queryLogger.info('Complex query completed', {
        resultsCount: processedResults.length,
        queryParameters: Object.keys(query),
        processingSteps: 3
      });
      
      return processedResults;
    });
  }
}

class CacheService {
  private cache: Map<string, any> = new Map();
  
  async get(key: string) {
    return await logger.timeAsync('cache-get', async () => {
      const value = this.cache.get(key);
      
      await logger.debug('Cache access', {
        operation: 'get',
        key,
        hit: value !== undefined,
        cacheSize: this.cache.size
      });
      
      return value;
    }, {
      cacheOperation: 'read',
      keyPattern: key.split(':')[0] // Log key pattern for analysis
    });
  }
  
  async set(key: string, value: any, ttl?: number) {
    return await logger.timeAsync('cache-set', async () => {
      this.cache.set(key, value);
      
      if (ttl) {
        setTimeout(() => this.cache.delete(key), ttl * 1000);
      }
      
      await logger.debug('Cache write completed', {
        operation: 'set',
        key,
        valueSize: JSON.stringify(value).length,
        ttl: ttl || 'permanent',
        cacheSize: this.cache.size
      });
    }, {
      cacheOperation: 'write',
      keyPattern: key.split(':')[0]
    });
  }
}

// Performance monitoring for HTTP requests
class APIService {
  async fetchExternalData(endpoint: string) {
    const apiLogger = logger.child('ExternalAPI', {
      endpoint,
      service: 'third_party_api'
    });
    
    return await apiLogger.timeAsync('external-api-call', async () => {
      const response = await fetch(endpoint);
      
      await apiLogger.info('External API response received', {
        statusCode: response.status,
        contentLength: response.headers.get('content-length'),
        contentType: response.headers.get('content-type')
      });
      
      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }
      
      return response.json();
    }, {
      requestType: 'external_api',
      protocol: 'https',
      method: 'GET'
    });
  }
}
```

## Field Configuration

Configure global fields that are automatically included in all log entries for consistent metadata:

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'UserManagementService',
  environment: 'production',
  fields: {
    version: '2.1.4',
    service: 'user-management-api',
    region: 'us-east-1',
    datacenter: 'aws-virginia',
    buildNumber: process.env.BUILD_NUMBER || 'unknown',
    deploymentId: process.env.DEPLOYMENT_ID || 'local',
    nodeVersion: process.version,
    platform: process.platform
  },
  transports: {
    console: { level: 'info', format: 'text' },
    file: {
      filename: './logs/application.log',
      level: 'debug',
      format: 'json'
    },
    database: {
      type: 'mongodb',
      connectionString: process.env.MONGODB_URI,
      database: 'application_logs',
      collection: 'service_logs'
    }
  }
});

// Example usage with automatic field inclusion
class UserService {
  async authenticateUser(credentials: any) {
    // All logs automatically include the configured global fields
    await logger.info('User authentication attempt', {
      userId: credentials.username,
      authMethod: 'password',
      clientIP: credentials.ip,
      userAgent: credentials.userAgent
    });
    
    try {
      const user = await this.validateCredentials(credentials);
      
      await logger.info('User authentication successful', {
        userId: user.id,
        userRole: user.role,
        lastLogin: user.lastLogin,
        sessionId: user.sessionId
      });
      
      return user;
    } catch (error) {
      await logger.error('User authentication failed', {
        userId: credentials.username,
        errorCode: error.code,
        errorMessage: error.message,
        attemptCount: credentials.attemptCount || 1
      });
      
      throw error;
    }
  }
  
  async createUser(userData: any) {
    await logger.info('User creation initiated', {
      requestedUsername: userData.username,
      userRole: userData.role,
      registrationSource: userData.source || 'direct'
    });
    
    const user = await this.database.createUser(userData);
    
    await logger.info('User created successfully', {
      userId: user.id,
      username: user.username,
      userRole: user.role,
      accountStatus: user.status,
      createdAt: user.createdAt
    });
    
    return user;
  }
}

// Dynamic field configuration for different environments
const createEnvironmentLogger = (env: string) => {
  const baseFields = {
    version: '2.1.4',
    service: 'user-management-api',
    nodeVersion: process.version
  };
  
  const environmentFields = {
    development: {
      ...baseFields,
      region: 'local',
      datacenter: 'development',
      debugMode: true
    },
    staging: {
      ...baseFields,
      region: 'us-west-2',
      datacenter: 'aws-oregon',
      testingEnabled: true
    },
    production: {
      ...baseFields,
      region: 'us-east-1',
      datacenter: 'aws-virginia',
      performanceMonitoring: true,
      securityAudit: true
    }
  };
  
  return createLogger({
    appName: 'UserManagementService',
    environment: env,
    fields: environmentFields[env] || environmentFields.development,
    transports: {
      console: {
        level: env === 'production' ? 'warn' : 'debug',
        format: env === 'production' ? 'json' : 'text'
      },
      file: {
        filename: `./logs/${env}-application.log`,
        level: 'debug',
        format: 'json',
        rotation: {
          interval: '1d',
          maxFiles: env === 'production' ? 30 : 7
        }
      }
    }
  });
};

const logger = createEnvironmentLogger(process.env.NODE_ENV || 'development');

// All logs will automatically include the configured fields:
// {
//   level: 'info',
//   message: 'User authentication successful',
//   userId: 'user123',
//   userRole: 'admin',
//   lastLogin: '2024-01-15T10:30:00Z',
//   sessionId: 'sess_abc123',
//   version: '2.1.4',
//   service: 'user-management-api',
//   region: 'us-east-1',
//   datacenter: 'aws-virginia',
//   buildNumber: '1234',
//   deploymentId: 'deploy_xyz789',
//   nodeVersion: 'v18.17.0',
//   platform: 'linux',
//   performanceMonitoring: true,
//   securityAudit: true,
//   timestamp: '2024-01-15T10:30:15.123Z',
//   appName: 'UserManagementService',
//   environment: 'production'
// }
```

## Field Management

Dynamically control which fields are included in log entries at runtime with persistent state management:

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'FieldManagementApp',
  environment: 'development',
  fields: {
    version: '1.0.1',
    service: 'api-gateway',
    region: 'us-east-1'
  },
  transports: {
    console: { level: 'info', format: 'text' },
    file: { filename: './logs/app.log', level: 'debug', format: 'json' }
  }
});

// Enable specific fields for inclusion in logs
await logger.enableField('userId');
await logger.enableField('requestId');
await logger.enableField('sessionId');

// Check if a field is currently enabled
const isUserIdEnabled = logger.isFieldEnabled('userId'); // true
const isEmailEnabled = logger.isFieldEnabled('email'); // false

// Get current field state
const fieldState = logger.getFieldState();
console.log(fieldState);
// Output: { userId: true, requestId: true, sessionId: true }

// Disable specific fields
await logger.disableField('sessionId');

// Log with automatic field filtering
await logger.info('User action performed', {
  userId: 'user123',        // Included (enabled)
  requestId: 'req456',      // Included (enabled)
  sessionId: 'sess789',     // Excluded (disabled)
  email: 'user@example.com', // Excluded (not enabled)
  action: 'profile_update'   // Included (always included)
});

// Reset field state to default (all fields enabled)
await logger.resetFieldState();

// Batch field management
await logger.enableField(['userId', 'requestId', 'traceId']);
await logger.disableField(['sessionId', 'deviceId']);
```

### Field Management Use Cases

```typescript
// Privacy compliance - disable PII fields in production
if (process.env.NODE_ENV === 'production') {
  await logger.disableField(['email', 'phoneNumber', 'address']);
}

// Debug mode - enable all diagnostic fields
if (process.env.DEBUG_MODE === 'true') {
  await logger.enableField(['stackTrace', 'memoryUsage', 'cpuUsage']);
}

// Feature-specific logging
class PaymentService {
  constructor() {
    // Enable payment-specific fields
    logger.enableField(['transactionId', 'paymentMethod', 'amount']);
  }
  
  async processPayment(paymentData: any) {
    await logger.info('Payment processing started', {
      transactionId: paymentData.id,
      paymentMethod: paymentData.method,
      amount: paymentData.amount,
      customerEmail: paymentData.email, // Only included if enabled
      internalRef: paymentData.ref      // Always included
    });
  }
}
```

## Transport Level Selection

Configure different log levels for each transport with interactive prompting and programmatic control:

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'TransportLevelApp',
  environment: 'development',
  transports: {
    console: { level: 'info', format: 'text' },
    file: [
      { filename: './logs/app.log', level: 'debug', format: 'json' },
      { filename: './logs/error.log', level: 'error', format: 'json' }
    ],
    database: {
      type: 'mongodb',
      connectionString: 'mongodb://localhost:27017/logs',
      database: 'app_logs',
      collection: 'entries'
    }
  }
});

// Programmatic transport level configuration
await logger.setTransportLevels({
  'console': 'warn',      // Only warnings and errors to console
  'file-0': 'debug',      // All logs to main file
  'file-1': 'error',      // Only errors to error file
  'database': 'info'      // Info and above to database
});

// Get current transport levels
const currentLevels = logger.getTransportLevels();
console.log(currentLevels);
// Output: { 'console': 'warn', 'file-0': 'debug', 'file-1': 'error', 'database': 'info' }

// Get available transports for configuration
const availableTransports = logger.getAvailableTransports();
console.log(availableTransports);
// Output: ['console', 'file-0', 'file-1', 'database']

// Enable interactive transport level prompting
await logger.enableTransportLevelPrompting();

// Test logging with different levels
await logger.debug('Debug message');   // Only to file-0
await logger.info('Info message');     // To file-0 and database
await logger.warn('Warning message');  // To console, file-0, and database
await logger.error('Error message');   // To all transports
```

## Analytics Transports

Logixia supports integration with popular analytics and monitoring platforms to track application events, user behavior, and system metrics.

### Supported Analytics Platforms

- **Mixpanel** - Event tracking and user analytics
- **DataDog** - Application monitoring and log forwarding
- **Google Analytics** - Web analytics and event tracking
- **Segment** - Unified analytics platform

### Mixpanel Integration

Track user events and behavior with Mixpanel:

```typescript
import { LogixiaLogger } from 'logixia';

const logger = new LogixiaLogger({
  appName: 'MyApp',
  transports: {
    analytics: {
      mixpanel: {
        token: 'your-mixpanel-token',
        apiKey: 'your-mixpanel-api-key',
        batchSize: 50,
        flushInterval: 5000,
        level: 'info'
      }
    }
  }
});

// Track user events
logger.info('User signed up', {
  userId: 'user-123',
  email: 'user@example.com',
  plan: 'premium',
  source: 'landing_page'
});

logger.info('Feature used', {
  feature: 'export_data',
  userId: 'user-123',
  exportFormat: 'csv'
});
```

### DataDog Integration

Send logs and metrics to DataDog for monitoring:

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  transports: {
    analytics: {
      datadog: {
        apiKey: 'your-datadog-api-key',
        site: 'datadoghq.com',
        service: 'my-service',
        version: '1.0.1',
        batchSize: 100,
        flushInterval: 10000,
        level: 'warn'
      }
    }
  }
});

// Send application metrics
logger.error('API Error', {
  endpoint: '/api/users',
  statusCode: 500,
  responseTime: 1200,
  errorType: 'database_timeout'
});

logger.warn('High memory usage', {
  memoryUsage: 85,
  threshold: 80,
  service: 'user-service'
});
```

### Google Analytics Integration

Track web analytics and custom events:

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  transports: {
    analytics: {
      googleAnalytics: {
        measurementId: 'G-XXXXXXXXXX',
        apiSecret: 'your-ga-api-secret',
        apiKey: 'your-ga-api-key',
        clientId: 'client-123',
        batchSize: 25,
        flushInterval: 3000,
        level: 'info'
      }
    }
  }
});

// Track page views and events
logger.info('Page view', {
  page: '/dashboard',
  userId: 'user-123',
  sessionDuration: 1250,
  referrer: 'https://google.com'
});

logger.info('Conversion event', {
  eventType: 'purchase',
  value: 99.99,
  currency: 'USD',
  transactionId: 'txn-456'
});
```

### Segment Integration

Unify analytics across multiple platforms:

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  transports: {
    analytics: {
      segment: {
        writeKey: 'your-segment-write-key',
        apiKey: 'your-segment-api-key',
        dataPlaneUrl: 'https://api.segment.io',
        batchSize: 75,
        flushInterval: 7000,
        level: 'info'
      }
    }
  }
});

// Track user events
logger.info('Product purchased', {
  productId: 'prod-456',
  productName: 'Premium Plan',
  price: 29.99,
  currency: 'USD',
  userId: 'user-123',
  category: 'subscription'
});

logger.info('User identified', {
  userId: 'user-123',
  email: 'user@example.com',
  name: 'John Doe',
  plan: 'premium'
});
```

### Multiple Analytics Providers

Configure multiple analytics providers simultaneously:

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  transports: {
    console: { level: 'debug' },
    analytics: {
      mixpanel: {
        token: 'mixpanel-token',
        apiKey: 'mixpanel-api-key',
        level: 'info'
      },
      datadog: {
        apiKey: 'datadog-api-key',
        site: 'datadoghq.com',
        service: 'my-service',
        level: 'warn'
      },
      segment: {
        writeKey: 'segment-write-key',
        apiKey: 'segment-api-key',
        level: 'info'
      }
    }
  }
});

// Events will be sent to all configured analytics providers
logger.info('User action', {
  action: 'button_click',
  buttonId: 'signup-cta',
  userId: 'user-123',
  timestamp: new Date().toISOString()
});
```

### Analytics Configuration Options

#### Common Options

- `apiKey`: API key for authentication
- `batchSize`: Number of events to batch before sending (default: 50)
- `flushInterval`: Time in milliseconds between automatic flushes (default: 5000)
- `level`: Minimum log level to send to analytics platform

#### Platform-Specific Options

**Mixpanel:**
- `token`: Project token from Mixpanel dashboard

**DataDog:**
- `site`: DataDog site (e.g., 'datadoghq.com', 'datadoghq.eu')
- `service`: Service name for log correlation
- `version`: Application version

**Google Analytics:**
- `measurementId`: GA4 Measurement ID
- `apiSecret`: Measurement Protocol API secret
- `clientId`: Client identifier for user tracking

**Segment:**
- `writeKey`: Write key from Segment dashboard
- `dataPlaneUrl`: Custom data plane URL (optional)

### Best Practices

1. **Environment Variables**: Store API keys in environment variables
2. **Batch Configuration**: Adjust batch sizes based on your traffic volume
3. **Log Levels**: Use appropriate log levels for different analytics platforms
4. **Error Handling**: Monitor transport metrics for failed deliveries
5. **Privacy**: Ensure compliance with data privacy regulations

```typescript
// Production configuration example
const logger = new LogixiaLogger({
  appName: process.env.APP_NAME,
  environment: process.env.NODE_ENV,
  transports: {
    console: { level: 'error' },
    analytics: {
      mixpanel: {
        token: process.env.MIXPANEL_TOKEN,
        apiKey: process.env.MIXPANEL_API_KEY,
        batchSize: 100,
        flushInterval: 10000,
        level: 'info'
      },
      datadog: {
        apiKey: process.env.DATADOG_API_KEY,
        site: process.env.DATADOG_SITE || 'datadoghq.com',
        service: process.env.SERVICE_NAME,
        version: process.env.APP_VERSION,
        level: 'warn'
      }
    }
  }
});
```

### Interactive Transport Configuration

```typescript
// Enable interactive prompting for transport level selection
await logger.enableTransportLevelPrompting();

// When logging, user will be prompted to select levels for each transport
// Example interactive session:
// ? Select log level for transport 'console': (Use arrow keys)
// ❯ error
//   warn
//   info
//   debug
//   trace

// ? Select log level for transport 'file-0': (Use arrow keys)
//   error
//   warn
// ❯ info
//   debug
//   trace

// Disable interactive prompting
await logger.disableTransportLevelPrompting();

// Clear all transport level preferences (reset to defaults)
await logger.clearTransportLevelPreferences();
```

### Advanced Transport Level Management

```typescript
class ApplicationService {
  constructor() {
    this.configureTransportLevels();
  }
  
  private async configureTransportLevels() {
    const environment = process.env.NODE_ENV;
    
    if (environment === 'development') {
      // Development: verbose logging to console and file
      await logger.setTransportLevels({
        'console': 'debug',
        'file-0': 'trace',
        'database': 'info'
      });
    } else if (environment === 'production') {
      // Production: minimal console, comprehensive file and database
      await logger.setTransportLevels({
        'console': 'error',
        'file-0': 'warn',
        'file-1': 'error',
        'database': 'info'
      });
    }
  }
  
  async handleRequest(request: any) {
    // These logs will be filtered based on transport-specific levels
    await logger.debug('Request received', { requestId: request.id });
    await logger.info('Processing request', { userId: request.userId });
    await logger.warn('High load detected', { activeConnections: 150 });
    await logger.error('Request failed', { error: 'Database timeout' });
  }
}

// Runtime transport level adjustment
class MonitoringService {
  async adjustLoggingBasedOnLoad(systemLoad: number) {
    if (systemLoad > 0.8) {
      // High load: reduce logging verbosity
      await logger.setTransportLevels({
        'console': 'error',
        'file-0': 'warn',
        'database': 'error'
      });
      await logger.warn('Reduced logging verbosity due to high system load');
    } else if (systemLoad < 0.3) {
      // Low load: increase logging for debugging
      await logger.setTransportLevels({
        'console': 'info',
        'file-0': 'debug',
        'database': 'info'
      });
      await logger.info('Increased logging verbosity due to low system load');
    }
  }
}
```

## Child Loggers

Create contextual child loggers for better organization and hierarchical logging:

```typescript
import { createLogger } from 'logixia';

const mainLogger = createLogger({ 
  appName: 'EcommerceApplication',
  environment: 'production',
  transports: {
    console: { level: 'info', format: 'text' },
    file: {
      filename: './logs/application.log',
      level: 'debug',
      format: 'json'
    }
  }
});

// Create service-level child logger with persistent context
const userLogger = mainLogger.child('UserService', { 
  module: 'user-management',
  version: '2.1.0',
  component: 'authentication'
});

// Child logger inherits parent configuration and adds its own context
await userLogger.info('User service initialized', {
  maxConcurrentUsers: 1000,
  cacheEnabled: true
});
// Output includes: context: 'UserService', module: 'user-management', version: '2.1.0', component: 'authentication'

// Create operation-specific nested child loggers
class UserService {
  private logger = userLogger;
  
  async authenticateUser(userId: string, sessionId: string) {
    // Create operation-specific logger with additional context
    const operationLogger = this.logger.child('AuthenticateUser', {
      operation: 'authentication',
      userId,
      sessionId,
      startTime: new Date().toISOString()
    });
    
    await operationLogger.info('Authentication process started', {
      authMethod: 'password',
      ipAddress: '192.168.1.100'
    });
    
    try {
      // Simulate authentication steps with detailed logging
      await operationLogger.debug('Validating user credentials');
      const user = await this.validateCredentials(userId);
      
      await operationLogger.debug('Checking user permissions', {
        userRole: user.role,
        permissions: user.permissions.length
      });
      
      await operationLogger.info('Authentication successful', {
        userId: user.id,
        userRole: user.role,
        lastLogin: user.lastLogin
      });
      
      return user;
    } catch (error) {
      await operationLogger.error('Authentication failed', {
        errorCode: error.code,
        errorMessage: error.message,
        attemptNumber: error.attemptNumber || 1
      });
      throw error;
    }
  }
  
  async createUser(userData: any) {
    // Create another operation-specific logger
    const createLogger = this.logger.child('CreateUser', {
      operation: 'user_creation',
      requestId: `req_${Date.now()}`,
      targetRole: userData.role
    });
    
    await createLogger.info('User creation initiated', {
      username: userData.username,
      email: userData.email,
      registrationSource: userData.source
    });
    
    // Create validation-specific sub-logger
    const validationLogger = createLogger.child('Validation', {
      step: 'input_validation'
    });
    
    await validationLogger.debug('Validating user input', {
      fieldsToValidate: Object.keys(userData)
    });
    
    // Validation logic here...
    await validationLogger.info('Input validation completed');
    
    // Create database-specific sub-logger
    const dbLogger = createLogger.child('Database', {
      step: 'database_operation'
    });
    
    await dbLogger.debug('Inserting user record');
    const user = await this.database.createUser(userData);
    await dbLogger.info('User record created', {
      userId: user.id,
      createdAt: user.createdAt
    });
    
    await createLogger.info('User creation completed successfully', {
      userId: user.id,
      totalProcessingTime: Date.now() - parseInt(createLogger.getContext().split('_')[1])
    });
    
    return user;
  }
}

// Example of service-to-service communication logging
class OrderService {
  private logger = mainLogger.child('OrderService', {
    module: 'order-management',
    version: '1.5.0'
  });
  
  async processOrder(orderId: string) {
    const orderLogger = this.logger.child('ProcessOrder', {
      orderId,
      operation: 'order_processing'
    });
    
    await orderLogger.info('Order processing started');
    
    // When calling user service, create a cross-service logger
    const userServiceLogger = orderLogger.child('UserServiceCall', {
      targetService: 'user-service',
      operation: 'user_lookup'
    });
    
    await userServiceLogger.debug('Fetching user information for order');
    // User service call here...
    await userServiceLogger.info('User information retrieved');
    
    await orderLogger.info('Order processing completed');
  }
}

// All child loggers maintain the full context hierarchy:
// {
//   level: 'info',
//   message: 'Authentication successful',
//   context: 'UserService > AuthenticateUser',
//   module: 'user-management',
//   version: '2.1.0',
//   component: 'authentication',
//   operation: 'authentication',
//   userId: 'user123',
//   sessionId: 'sess_abc',
//   startTime: '2024-01-15T10:30:00Z',
//   userRole: 'admin',
//   lastLogin: '2024-01-14T15:20:00Z',
//   appName: 'EcommerceApplication',
//   environment: 'production',
//   timestamp: '2024-01-15T10:30:15.123Z'
// }
```

## Trace ID Support

Built-in request tracing across your application for comprehensive request flow tracking:

```typescript
import { createLogger, runWithTraceId, getCurrentTraceId } from 'logixia';

const logger = createLogger({ 
  appName: 'DistributedApplication',
  environment: 'production',
  traceId: true,
  transports: {
    console: { level: 'info', format: 'text' },
    file: {
      filename: './logs/traced-application.log',
      level: 'debug',
      format: 'json'
    },
    database: {
      type: 'mongodb',
      connectionString: process.env.MONGODB_URI,
      database: 'application_logs',
      collection: 'traced_requests'
    }
  }
});

// Manual trace ID management for specific operations
class PaymentService {
  async processPayment(paymentData: any) {
    // Use custom trace ID for payment processing
    const traceId = `payment_${paymentData.orderId}_${Date.now()}`;
    
    return await runWithTraceId(traceId, async () => {
      await logger.info('Payment processing initiated', {
        orderId: paymentData.orderId,
        amount: paymentData.amount,
        currency: paymentData.currency,
        paymentMethod: paymentData.method
      });
      
      // Get current trace ID for external service calls
      const currentTraceId = getCurrentTraceId();
      console.log('Processing with trace ID:', currentTraceId); // 'payment_ORD123_1642234567890'
      
      try {
        // Simulate payment gateway call
        await this.callPaymentGateway(paymentData, currentTraceId);
        
        // Simulate fraud detection
        await this.performFraudCheck(paymentData, currentTraceId);
        
        await logger.info('Payment processed successfully', {
          transactionId: 'txn_abc123',
          processingTime: '1.2s',
          gatewayResponse: 'approved'
        });
        
        return { success: true, transactionId: 'txn_abc123' };
      } catch (error) {
        await logger.error('Payment processing failed', {
          errorCode: error.code,
          errorMessage: error.message,
          gatewayError: error.gatewayError
        });
        throw error;
      }
    });
  }
  
  private async callPaymentGateway(paymentData: any, traceId: string) {
    await logger.debug('Calling payment gateway', {
      gateway: 'stripe',
      endpoint: '/v1/charges',
      traceId // Explicitly log trace ID for external calls
    });
    
    // Simulate API call with trace ID in headers
    // fetch('/api/payment', { headers: { 'X-Trace-ID': traceId } })
  }
  
  private async performFraudCheck(paymentData: any, traceId: string) {
    await logger.debug('Performing fraud detection', {
      service: 'fraud-detection',
      riskScore: 'calculating',
      traceId
    });
    
    // Fraud detection logic here
    await logger.info('Fraud check completed', {
      riskScore: 0.15,
      decision: 'approved',
      factors: ['amount_normal', 'location_verified', 'device_known']
    });
  }
}

// Automatic trace ID generation for web requests
class OrderService {
  async createOrder(orderData: any) {
    // Auto-generate trace ID for new operations
    return await runWithTraceId(async () => {
      const traceId = getCurrentTraceId();
      
      await logger.info('Order creation started', {
        customerId: orderData.customerId,
        itemCount: orderData.items.length,
        totalAmount: orderData.total,
        autoGeneratedTraceId: traceId
      });
      
      // Create child services with same trace context
      const inventoryResult = await this.checkInventory(orderData.items);
      const paymentResult = await this.processPayment(orderData.payment);
      
      await logger.info('Order created successfully', {
        orderId: 'ORD-12345',
        inventoryReserved: inventoryResult.reserved,
        paymentProcessed: paymentResult.success
      });
      
      return { orderId: 'ORD-12345', status: 'confirmed' };
    });
  }
  
  private async checkInventory(items: any[]) {
    // This will automatically use the same trace ID
    await logger.debug('Checking inventory availability', {
      itemsToCheck: items.length,
      operation: 'inventory_check'
    });
    
    // Inventory check logic
    return { reserved: true, availableQuantity: 100 };
  }
  
  private async processPayment(paymentData: any) {
    // This will automatically use the same trace ID
    await logger.debug('Processing order payment', {
      amount: paymentData.amount,
      method: paymentData.method,
      operation: 'payment_processing'
    });
    
    // Payment processing logic
    return { success: true, transactionId: 'txn_xyz789' };
  }
}

// Cross-service trace ID propagation
class NotificationService {
  async sendOrderConfirmation(orderId: string, customerEmail: string) {
    // Inherit trace ID from calling context or create new one
    const existingTraceId = getCurrentTraceId();
    
    if (existingTraceId) {
      // Continue with existing trace
      await logger.info('Sending order confirmation', {
        orderId,
        customerEmail,
        notificationType: 'order_confirmation',
        inheritedTrace: true
      });
    } else {
      // Create new trace for standalone notification
      await runWithTraceId(`notification_${orderId}_${Date.now()}`, async () => {
        await logger.info('Sending standalone notification', {
          orderId,
          customerEmail,
          notificationType: 'order_confirmation',
          newTrace: true
        });
      });
    }
  }
}

// Example usage in an Express route
app.post('/orders', async (req, res) => {
  // Extract trace ID from request headers or generate new one
  const incomingTraceId = req.headers['x-trace-id'] || 
                         req.headers['x-request-id'] ||
                         `api_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  await runWithTraceId(incomingTraceId, async () => {
    await logger.info('API request received', {
      endpoint: '/orders',
      method: 'POST',
      clientIP: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    try {
      const orderService = new OrderService();
      const result = await orderService.createOrder(req.body);
      
      await logger.info('API request completed successfully', {
        endpoint: '/orders',
        orderId: result.orderId,
        responseStatus: 201
      });
      
      res.status(201).json({
        ...result,
        traceId: getCurrentTraceId() // Return trace ID to client
      });
    } catch (error) {
      await logger.error('API request failed', {
        endpoint: '/orders',
        errorMessage: error.message,
        responseStatus: 500
      });
      
      res.status(500).json({
        error: 'Order creation failed',
        traceId: getCurrentTraceId()
      });
    }
  });
});

// All logs within the trace context will include the trace ID:
// {
//   level: 'info',
//   message: 'Payment processed successfully',
//   traceId: 'payment_ORD123_1642234567890',
//   transactionId: 'txn_abc123',
//   processingTime: '1.2s',
//   gatewayResponse: 'approved',
//   appName: 'DistributedApplication',
//   environment: 'production',
//   timestamp: '2024-01-15T10:30:15.123Z'
// }
```

## Custom Formatters

Create custom log formatters for specialized output requirements:

```typescript
import { ILogFormatter, LogEntry } from 'logixia';

// Production-ready JSON formatter with structured output
class StructuredJSONFormatter implements ILogFormatter {
  format(entry: LogEntry): string {
    const structured = {
      '@timestamp': entry.timestamp,
      '@version': '1',
      level: entry.level.toUpperCase(),
      logger_name: entry.context || 'root',
      message: entry.message,
      application: {
        name: entry.appName,
        environment: entry.environment,
        version: entry.version
      },
      trace: {
        id: entry.traceId
      },
      metadata: entry.payload || {},
      host: {
        name: require('os').hostname(),
        platform: process.platform,
        arch: process.arch
      },
      process: {
        pid: process.pid,
        memory_usage: process.memoryUsage(),
        uptime: process.uptime()
      }
    };
    
    return JSON.stringify(structured);
  }
}

// Human-readable console formatter with colors and alignment
class EnhancedConsoleFormatter implements ILogFormatter {
  private colors = {
    error: '\x1b[31m',   // Red
    warn: '\x1b[33m',    // Yellow
    info: '\x1b[36m',    // Cyan
    debug: '\x1b[32m',   // Green
    trace: '\x1b[35m',   // Magenta
    reset: '\x1b[0m'     // Reset
  };
  
  format(entry: LogEntry): string {
    const timestamp = new Date(entry.timestamp).toISOString();
    const level = entry.level.toUpperCase().padEnd(5);
    const context = entry.context ? `[${entry.context}]` : '';
    const traceId = entry.traceId ? `{${entry.traceId.slice(-8)}}` : '';
    const color = this.colors[entry.level] || this.colors.reset;
    
    let formatted = `${timestamp} ${color}${level}${this.colors.reset} ${context}${traceId} ${entry.message}`;
    
    if (entry.payload && Object.keys(entry.payload).length > 0) {
      const payloadStr = JSON.stringify(entry.payload, null, 2)
        .split('\n')
        .map(line => `    ${line}`)
        .join('\n');
      formatted += `\n${payloadStr}`;
    }
    
    return formatted;
  }
}

// Metrics-focused formatter for performance monitoring
class MetricsFormatter implements ILogFormatter {
  format(entry: LogEntry): string {
    if (entry.payload?.duration || entry.payload?.timeTaken) {
      const metrics = {
        timestamp: entry.timestamp,
        metric_type: 'performance',
        operation: entry.context || 'unknown',
        duration_ms: entry.payload.duration || entry.payload.timeTaken,
        trace_id: entry.traceId,
        service: entry.appName,
        environment: entry.environment,
        additional_data: { ...entry.payload }
      };
      
      delete metrics.additional_data.duration;
      delete metrics.additional_data.timeTaken;
      
      return JSON.stringify(metrics);
    }
    
    // For non-performance logs, use standard format
    return JSON.stringify({
      timestamp: entry.timestamp,
      level: entry.level,
      message: entry.message,
      context: entry.context,
      trace_id: entry.traceId,
      data: entry.payload
    });
  }
}

// Security audit formatter for compliance logging
class SecurityAuditFormatter implements ILogFormatter {
  format(entry: LogEntry): string {
    const auditEntry = {
      audit_timestamp: entry.timestamp,
      event_type: entry.level,
      event_description: entry.message,
      actor: {
        user_id: entry.payload?.userId,
        session_id: entry.payload?.sessionId,
        ip_address: entry.payload?.clientIP,
        user_agent: entry.payload?.userAgent
      },
      resource: {
        type: entry.payload?.resourceType,
        id: entry.payload?.resourceId,
        action: entry.payload?.action
      },
      outcome: {
        success: entry.level !== 'error',
        error_code: entry.payload?.errorCode,
        error_message: entry.payload?.errorMessage
      },
      context: {
        application: entry.appName,
        environment: entry.environment,
        trace_id: entry.traceId,
        component: entry.context
      },
      compliance: {
        retention_period: '7_years',
        classification: entry.payload?.dataClassification || 'internal',
        regulation: ['SOX', 'GDPR', 'HIPAA']
      }
    };
    
    return JSON.stringify(auditEntry);
  }
}

// Configure logger with multiple formatters for different transports
const logger = createLogger({
  appName: 'EnterpriseApplication',
  environment: 'production',
  transports: {
    console: {
      level: 'info',
      formatter: new EnhancedConsoleFormatter()
    },
    file: {
      filename: './logs/application.log',
      level: 'debug',
      formatter: new StructuredJSONFormatter()
    },
    database: {
      type: 'mongodb',
      connectionString: process.env.MONGODB_URI,
      database: 'application_logs',
      collection: 'structured_logs',
      formatter: new StructuredJSONFormatter()
    }
  },
  // Separate transport for metrics
  metricsTransport: {
    file: {
      filename: './logs/metrics.log',
      level: 'info',
      formatter: new MetricsFormatter()
    }
  },
  // Separate transport for security audit logs
  auditTransport: {
    file: {
      filename: './logs/security-audit.log',
      level: 'info',
      formatter: new SecurityAuditFormatter()
    },
    database: {
      type: 'mongodb',
      connectionString: process.env.AUDIT_DB_URI,
      database: 'security_audit',
      collection: 'audit_events',
      formatter: new SecurityAuditFormatter()
    }
  }
});

// Usage examples with different formatters
class UserAuthenticationService {
  async authenticateUser(credentials: any, clientInfo: any) {
    // This will be formatted differently by each transport
    await logger.info('User authentication attempt', {
      userId: credentials.username,
      clientIP: clientInfo.ip,
      userAgent: clientInfo.userAgent,
      authMethod: 'password',
      resourceType: 'user_account',
      resourceId: credentials.username,
      action: 'authenticate',
      dataClassification: 'confidential'
    });
    
    // Performance timing with metrics formatter
    const result = await logger.timeAsync('user-authentication', async () => {
      // Authentication logic here
      return { success: true, userId: 'user123', role: 'admin' };
    });
    
    await logger.info('User authentication successful', {
      userId: result.userId,
      userRole: result.role,
      sessionId: 'sess_abc123',
      resourceType: 'user_session',
      resourceId: 'sess_abc123',
      action: 'create_session',
      dataClassification: 'confidential'
    });
    
    return result;
  }
}

// Console output (EnhancedConsoleFormatter):
// 2024-01-15T10:30:15.123Z INFO  [UserAuthenticationService]{abc123ef} User authentication attempt
//     {
//       "userId": "john.doe",
//       "clientIP": "192.168.1.100",
//       "userAgent": "Mozilla/5.0...",
//       "authMethod": "password"
//     }

// Application log file (StructuredJSONFormatter):
// {"@timestamp":"2024-01-15T10:30:15.123Z","@version":"1","level":"INFO","logger_name":"UserAuthenticationService","message":"User authentication attempt","application":{"name":"EnterpriseApplication","environment":"production"},"trace":{"id":"abc123ef"},"metadata":{"userId":"john.doe","clientIP":"192.168.1.100"}}

// Security audit log (SecurityAuditFormatter):
// {"audit_timestamp":"2024-01-15T10:30:15.123Z","event_type":"info","event_description":"User authentication attempt","actor":{"user_id":"john.doe","ip_address":"192.168.1.100"},"resource":{"type":"user_account","id":"john.doe","action":"authenticate"},"compliance":{"retention_period":"7_years","classification":"confidential"}}
```

## Configuration Options

Comprehensive configuration interface for all logger features and transport systems:

```typescript
interface LoggerConfig {
  // Core application settings
  appName: string;
  environment?: 'development' | 'staging' | 'production' | string;
  level?: LogLevel; // Global minimum log level
  
  // Global field configuration
  fields?: Record<string, any>; // Fields included in all log entries
  
  // Trace ID configuration
  traceId?: boolean | {
    enabled: boolean;
    generator?: () => string; // Custom trace ID generation
  };
  
  // Output formatting
  format?: {
    json?: boolean; // JSON vs text format
    timestamp?: boolean | string; // Include timestamp, custom format
    colorize?: boolean; // Console color output
    prettyPrint?: boolean; // Pretty-printed JSON
    includeStack?: boolean; // Include stack traces for errors
  };
  
  // Transport configuration
  transports?: {
    console?: ConsoleTransportConfig;
    file?: FileTransportConfig | FileTransportConfig[]; // Multiple file outputs
    database?: DatabaseTransportConfig | DatabaseTransportConfig[]; // Multiple databases
    http?: HttpTransportConfig; // HTTP endpoint logging
    syslog?: SyslogTransportConfig; // System log integration
    custom?: CustomTransportConfig[]; // Custom transport implementations
  };
  
  // Performance and monitoring
  performance?: {
    enableTiming?: boolean; // Enable performance timing
    enableMetrics?: boolean; // Enable metrics collection
    metricsInterval?: number; // Metrics collection interval (ms)
    slowOperationThreshold?: number; // Threshold for slow operation warnings (ms)
  };
  
  // Batch processing configuration
  batching?: {
    enabled?: boolean;
    batchSize?: number; // Number of logs per batch
    flushInterval?: number; // Time interval for batch flushing (ms)
    maxRetries?: number; // Retry attempts for failed batches
  };
  
  // Error handling
  errorHandling?: {
    suppressErrors?: boolean; // Suppress logger internal errors
    fallbackTransport?: 'console' | 'file'; // Fallback when primary transport fails
    errorCallback?: (error: Error) => void; // Custom error handler
  };
  
  // Security and compliance
  security?: {
    sanitizeFields?: string[]; // Fields to sanitize in logs
    encryptFields?: string[]; // Fields to encrypt
    auditMode?: boolean; // Enable audit logging
    retentionPolicy?: {
      days?: number;
      maxSize?: string; // '100MB', '1GB', etc.
    };
  };
  
  // Legacy options for backward compatibility
  silent?: boolean; // Disable all output
  levelOptions?: {
    level?: string; // Current log level
    levels?: Record<string, number>; // Custom levels with priorities
    colors?: Record<string, LogColor>; // Custom colors for levels
  };
}

// Console transport configuration
interface ConsoleTransportConfig {
  level?: LogLevel;
  format?: 'text' | 'json';
  colorize?: boolean;
  timestamp?: boolean;
  formatter?: ILogFormatter;
  silent?: boolean; // Disable console output
}

// File transport configuration
interface FileTransportConfig {
  filename: string;
  level?: LogLevel;
  format?: 'text' | 'json';
  formatter?: ILogFormatter;
  
  // File rotation settings
  rotation?: {
    interval?: '1h' | '6h' | '12h' | '1d' | '1w' | '1m'; // Time-based rotation
    maxSize?: string; // Size-based rotation: '10MB', '100MB', '1GB'
    maxFiles?: number; // Maximum number of rotated files to keep
    compress?: boolean; // Compress rotated files
    datePattern?: string; // Custom date pattern for file naming
  };
  
  // File handling options
  options?: {
    flags?: string; // File system flags ('a', 'w', etc.)
    mode?: number; // File permissions
    encoding?: string; // File encoding
    highWaterMark?: number; // Stream buffer size
  };
}

// Database transport configuration
interface DatabaseTransportConfig {
  type: 'mongodb' | 'postgresql' | 'mysql' | 'sqlite' | 'redis';
  connectionString?: string;
  
  // Connection options
  connection?: {
    host?: string;
    port?: number;
    database?: string;
    username?: string;
    password?: string;
    ssl?: boolean;
    poolSize?: number;
    timeout?: number;
  };
  
  // Database-specific settings
  mongodb?: {
    collection: string;
    capped?: boolean; // Capped collection
    cappedSize?: number; // Capped collection size
    indexes?: string[]; // Fields to index
  };
  
  postgresql?: {
    table: string;
    schema?: string;
    createTable?: boolean; // Auto-create table
    columns?: Record<string, string>; // Custom column definitions
  };
  
  mysql?: {
    table: string;
    database?: string;
    createTable?: boolean;
    engine?: 'InnoDB' | 'MyISAM';
  };
  
  sqlite?: {
    filename: string;
    table: string;
    createTable?: boolean;
  };
  
  redis?: {
    key: string; // Redis key for log storage
    listType?: 'list' | 'stream'; // Storage type
    maxLength?: number; // Maximum list/stream length
    ttl?: number; // Time to live (seconds)
  };
  
  level?: LogLevel;
  formatter?: ILogFormatter;
  
  // Batch processing for database writes
  batching?: {
    enabled?: boolean;
    batchSize?: number;
    flushInterval?: number;
  };
}

// HTTP transport configuration
interface HttpTransportConfig {
  url: string;
  method?: 'POST' | 'PUT' | 'PATCH';
  headers?: Record<string, string>;
  level?: LogLevel;
  formatter?: ILogFormatter;
  
  // HTTP-specific options
  options?: {
    timeout?: number;
    retries?: number;
    retryDelay?: number;
    auth?: {
      username: string;
      password: string;
    } | {
      bearer: string;
    };
  };
  
  // Batch processing for HTTP requests
  batching?: {
    enabled?: boolean;
    batchSize?: number;
    flushInterval?: number;
  };
}

// Example comprehensive configuration
const productionConfig: LoggerConfig = {
  appName: 'EnterpriseApplication',
  environment: 'production',
  level: 'info',
  
  fields: {
    version: '2.1.4',
    service: 'user-management-api',
    region: process.env.AWS_REGION || 'us-east-1',
    datacenter: 'aws-virginia',
    buildNumber: process.env.BUILD_NUMBER,
    deploymentId: process.env.DEPLOYMENT_ID
  },
  
  traceId: {
    enabled: true,
    header: 'x-trace-id',
    generator: () => `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  },
  
  format: {
    json: true,
    timestamp: true,
    prettyPrint: false,
    includeStack: true
  },
  
  transports: {
    console: {
      level: 'warn',
      format: 'text',
      colorize: false
    },
    
    file: [
      {
        filename: './logs/application.log',
        level: 'info',
        format: 'json',
        rotation: {
          interval: '1d',
          maxFiles: 30,
          compress: true
        }
      },
      {
        filename: './logs/error.log',
        level: 'error',
        format: 'json',
        rotation: {
          maxSize: '100MB',
          maxFiles: 10
        }
      }
    ],
    
    database: [
      {
        type: 'mongodb',
        connectionString: process.env.MONGODB_URI,
        mongodb: {
          collection: 'application_logs',
          capped: true,
          cappedSize: 1000000000, // 1GB
          indexes: ['timestamp', 'level', 'traceId']
        },
        level: 'debug',
        batching: {
          enabled: true,
          batchSize: 100,
          flushInterval: 5000
        }
      }
    ],
    
    http: {
      url: 'https://logs.example.com/api/logs',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.LOG_API_TOKEN}`,
        'Content-Type': 'application/json'
      },
      level: 'error',
      options: {
        timeout: 10000,
        retries: 3,
        retryDelay: 1000
      },
      batching: {
        enabled: true,
        batchSize: 50,
        flushInterval: 10000
      }
    }
  },
  
  performance: {
    enableTiming: true,
    enableMetrics: true,
    metricsInterval: 60000, // 1 minute
    slowOperationThreshold: 1000 // 1 second
  },
  
  batching: {
    enabled: true,
    batchSize: 100,
    flushInterval: 5000,
    maxRetries: 3
  },
  
  errorHandling: {
    suppressErrors: false,
    fallbackTransport: 'console',
    errorCallback: (error) => {
      console.error('Logger error:', error);
      // Send to monitoring service
    }
  },
  
  security: {
    sanitizeFields: ['password', 'creditCard', 'ssn'],
    encryptFields: ['personalData', 'sensitiveInfo'],
    auditMode: true,
    retentionPolicy: {
      days: 2555, // 7 years for compliance
      maxSize: '10GB'
    }
  }
};

const logger = createLogger(productionConfig);
```

## API Reference

### Logger Creation

#### createLogger(config: LoggerConfig): ILogger

Creates a new logger instance with the specified configuration.

```typescript
import { createLogger, LogLevel } from 'logixia';

const logger = createLogger({
  appName: 'MyApplication',
  environment: 'production',
  levelOptions: {
    level: LogLevel.INFO,
    colors: {
      error: 'red',
      warn: 'yellow',
      info: 'green',
      debug: 'blue'
    }
  },
  transports: {
    console: { level: 'info', colorize: true },
    file: { filename: './logs/app.log', level: 'debug' },
    database: { type: 'mongodb', connectionString: 'mongodb://localhost:27017' }
  }
});
```

### Core Logging Methods

#### Standard Log Levels

```typescript
// Error level - critical errors that require immediate attention
await logger.error(message: string | Error, context?: Record<string, any>): Promise<void>

// Warning level - potentially harmful situations
await logger.warn(message: string, context?: Record<string, any>): Promise<void>

// Info level - general application flow information
await logger.info(message: string, context?: Record<string, any>): Promise<void>

// Debug level - detailed diagnostic information
await logger.debug(message: string, context?: Record<string, any>): Promise<void>

// Trace level - most detailed diagnostic information
await logger.trace(message: string, context?: Record<string, any>): Promise<void>

// Verbose level - extremely detailed diagnostic information
await logger.verbose(message: string, context?: Record<string, any>): Promise<void>
```

#### Custom Level Logging

```typescript
// Log with custom level
await logger.logLevel(level: string, message: string, context?: Record<string, any>): Promise<void>

// Example with custom business levels
await logger.logLevel('order', 'Order processing started', { orderId: '12345' });
await logger.logLevel('payment', 'Payment processed', { amount: 99.99, method: 'card' });
```

### Performance Monitoring

#### Timing Operations

```typescript
// Start a timer
logger.time(label: string): void

// End timer and return duration in milliseconds
await logger.timeEnd(label: string): Promise<number | undefined>

// Automatic timing wrapper for async operations
await logger.timeAsync<T>(label: string, operation: () => Promise<T>, context?: Record<string, any>): Promise<T>
```

**Usage Examples:**

```typescript
// Manual timing
logger.time('database-query');
const users = await database.findUsers();
const duration = await logger.timeEnd('database-query');

// Automatic timing with context
const result = await logger.timeAsync('api-call', async () => {
  const response = await fetch('/api/users');
  return response.json();
}, { endpoint: '/api/users', method: 'GET' });
```

### Context Management

#### Logger Context

```typescript
// Set context for all subsequent log entries
logger.setContext(context: string): void

// Get current context
logger.getContext(): string | undefined

// Set minimum log level
logger.setLevel(level: string): void

// Get current log level
logger.getLevel(): string
```

### Field Management

#### Dynamic Field Control

```typescript
// Enable specific fields for inclusion in logs
await logger.enableField(fieldName: string | string[]): Promise<void>

// Disable specific fields from logs
await logger.disableField(fieldName: string | string[]): Promise<void>

// Check if a field is currently enabled
logger.isFieldEnabled(fieldName: string): boolean

// Get current field state
logger.getFieldState(): Record<string, boolean>

// Reset field state to default (all fields enabled)
await logger.resetFieldState(): Promise<void>
```

**Usage Examples:**

```typescript
// Enable multiple fields
await logger.enableField(['userId', 'requestId', 'sessionId']);

// Disable sensitive fields
await logger.disableField(['email', 'phoneNumber']);

// Check field status
if (logger.isFieldEnabled('userId')) {
  // Field is enabled
}

// Get all field states
const fieldStates = logger.getFieldState();
console.log(fieldStates); // { userId: true, email: false, ... }
```

### Transport Level Selection

#### Transport-Specific Level Configuration

```typescript
// Set log levels for specific transports
await logger.setTransportLevels(levels: Record<string, string>): Promise<void>

// Get current transport level configuration
logger.getTransportLevels(): Record<string, string>

// Get available transport identifiers
logger.getAvailableTransports(): string[]

// Enable interactive transport level prompting
await logger.enableTransportLevelPrompting(): Promise<void>

// Disable interactive transport level prompting
await logger.disableTransportLevelPrompting(): Promise<void>

// Clear all transport level preferences
await logger.clearTransportLevelPreferences(): Promise<void>
```

**Usage Examples:**

```typescript
// Configure different levels for each transport
await logger.setTransportLevels({
  'console': 'warn',
  'file-0': 'debug',
  'database': 'info'
});

// Get current configuration
const levels = logger.getTransportLevels();
console.log(levels); // { console: 'warn', 'file-0': 'debug', database: 'info' }

// List available transports
const transports = logger.getAvailableTransports();
console.log(transports); // ['console', 'file-0', 'database']

// Enable interactive configuration
await logger.enableTransportLevelPrompting();
```

#### Child Loggers

```typescript
// Create child logger with additional context
logger.child(context: string, persistentData?: Record<string, any>): ILogger
```

**Usage Example:**

```typescript
const userLogger = logger.child('UserService', { module: 'authentication' });
const operationLogger = userLogger.child('LoginOperation', { sessionId: 'sess_123' });

// All logs from operationLogger will include both contexts
await operationLogger.info('User login attempt', { userId: 'user_456' });
```

### Batch Processing

#### Manual Batch Management

```typescript
// Add entry to batch queue
logger.addToBatch(entry: {
  level: string;
  message: string;
  context?: Record<string, any>;
}): void

// Manually flush all batched entries
await logger.flushBatch(): Promise<void>

// Get current batch size
logger.getBatchSize(): number
```

### Transport Management

#### Health Monitoring

```typescript
// Check health status of all configured transports
await logger.checkTransportHealth(): Promise<Record<string, TransportHealthStatus>>
```

**Response Format:**

```typescript
interface TransportHealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  latency: number;              // Response time in milliseconds
  error?: string;               // Error message if unhealthy
  lastCheck: Date;              // Timestamp of last health check
}
```

### Resource Management

#### Cleanup Operations

```typescript
// Gracefully close logger and all transports
await logger.close(): Promise<void>

// Force flush all pending operations
await logger.flush(): Promise<void>
```

### NestJS Integration

#### LogixiaLoggerService Methods

```typescript
// Standard NestJS LoggerService interface
log(message: any, context?: string): void
error(message: any, trace?: string, context?: string): void
warn(message: any, context?: string): void
debug(message: any, context?: string): void
verbose(message: any, context?: string): void

// Extended Logixia methods (async versions)
await info(message: string, context?: Record<string, any>): Promise<void>
await trace(message: string, context?: Record<string, any>): Promise<void>

// Trace ID management
getCurrentTraceId(): string | undefined

// Child logger creation
child(context: string, persistentData?: Record<string, any>): LogixiaLoggerService

// Context management
setContext(context: string): void
getContext(): string | undefined
```

### Trace ID Management

#### Global Trace Functions

```typescript
// Run operation with specific trace ID
runWithTraceId(traceId: string, operation: () => Promise<void>): Promise<void>
runWithTraceId(operation: () => Promise<void>): Promise<void>  // Auto-generate ID

// Get current trace ID from async context
getCurrentTraceId(): string | undefined

// Express middleware for automatic trace ID extraction
traceMiddleware(options: TraceMiddlewareOptions): express.RequestHandler
```

**TraceMiddlewareOptions:**

```typescript
interface TraceMiddlewareOptions {
  enabled: boolean;
  extractor: {
    header?: string[];          // Header names to check for trace ID
    query?: string[];           // Query parameter names to check
    body?: string[];            // Body field names to check
  };
  generator?: () => string;     // Custom trace ID generator
}
```

## Examples

The `/examples` directory contains comprehensive usage demonstrations:

### Available Examples

- **Basic Usage** (`examples/basic-usage.ts`) - Fundamental logging operations and setup
- **Advanced Logging** (`examples/advanced-logging.ts`) - Multi-transport configuration with database integration
- **Custom Levels** (`examples/custom-levels.ts`) - Business-specific log levels and custom priorities
- **NestJS Integration** (`examples/nestjs-example.ts`) - Complete NestJS module integration
- **Express Integration** (`examples/express-example.ts`) - Express middleware and request tracking
- **Performance Monitoring** (`examples/performance-monitoring.ts`) - Timing utilities and performance metrics
- **Field Configuration** (`examples/field-configuration.ts`) - Custom field formatting and inclusion
- **Field and Transport Management** (`examples/field-and-transport-management.ts`) - Dynamic field control and transport-specific log levels
- **Database Transport** (`examples/database-transport.ts`) - Database-specific transport configurations
- **Log Rotation** (`examples/log-rotation.ts`) - File rotation and retention policies

### Running Examples

```bash
# Execute basic usage demonstration
npm run dev:basic-usage

# Run advanced multi-transport example
npm run dev:advanced-logging

# Test custom business log levels
npm run dev:custom-levels

# Demonstrate NestJS integration
npm run dev:nestjs

# Show Express middleware usage
npm run dev:express

# Performance monitoring examples
npm run dev:performance

# Field configuration demonstration
npm run dev:fields

# Field and transport management demonstration
npx ts-node examples/field-and-transport-management.ts

# Interactive field and transport management
npx ts-node examples/field-and-transport-management.ts --interactive

# Database transport examples
npm run dev:database

# Log rotation demonstration
npm run dev:rotation
```

## Development

### Setup and Build

```bash
# Install project dependencies
npm install

# Build TypeScript source
npm run build

# Build with watch mode for development
npm run build:watch

# Clean build artifacts
npm run clean
```

### Testing and Quality Assurance

```bash
# Execute test suite
npm test

# Run tests with coverage report
npm run test:coverage

# Execute tests in watch mode
npm run test:watch

# Run ESLint code analysis
npm run lint

# Fix automatically correctable linting issues
npm run lint:fix

# Format code with Prettier
npm run format

# Validate code formatting
npm run format:check
```

### Documentation

```bash
# Generate API documentation
npm run docs:generate

# Serve documentation locally
npm run docs:serve

# Validate documentation completeness
npm run docs:validate
```

## System Requirements

### Runtime Requirements

- **Node.js**: Version 16.0.0 or higher
- **Operating System**: Cross-platform (Windows, macOS, Linux)
- **Memory**: Minimum 512MB available RAM

### Development Requirements

- **TypeScript**: Version 5.0.0 or higher
- **npm**: Version 8.0.0 or higher (or equivalent package manager)
- **Git**: Version 2.20.0 or higher

### Optional Database Dependencies

- **MongoDB**: Version 4.4 or higher (for MongoDB transport)
- **PostgreSQL**: Version 12 or higher (for PostgreSQL transport)
- **MySQL**: Version 8.0 or higher (for MySQL transport)
- **SQLite**: Version 3.35 or higher (for SQLite transport)

## Contributing

🚀 **We're building the world's most advanced TypeScript logging library!** 🚀

Logixia is an **open source project** and we welcome contributions from developers worldwide. Whether you're fixing bugs, adding features, improving documentation, or sharing ideas, your contribution helps make Logixia better for everyone.

### 🎃 Hacktoberfest 2024

**We're excited to participate in Hacktoberfest 2024!** 

- 🏷️ Look for issues labeled with `hacktoberfest` for contribution opportunities
- 🌟 Issues labeled `good first issue` are perfect for newcomers
- 📋 All contributions must follow our [Code of Conduct](CODE_OF_CONDUCT.md)
- ✅ Quality over quantity - we review all PRs carefully
- 🎯 Focus on meaningful contributions that improve the project

### Why Contribute?

- 🌟 **Impact**: Help shape the future of logging in TypeScript/Node.js ecosystem
- 🎯 **Learning**: Work with cutting-edge TypeScript patterns and enterprise architecture
- 🤝 **Community**: Join a growing community of passionate developers
- 📈 **Recognition**: Get recognized for your contributions in our contributors hall of fame
- 🎃 **Hacktoberfest**: Earn your Hacktoberfest swag by contributing to open source!

### Quick Start for Contributors

```bash
# 1. Fork and clone the repository
git clone https://github.com/Logixia/logixia.git
cd logixia

# 2. Install dependencies
npm install

# 3. Run tests to ensure everything works
npm test

# 4. Start developing!
npm run build:watch
```

### Ways to Contribute

#### 🐛 **Bug Reports & Fixes**
- Found a bug? [Open an issue](https://github.com/Logixia/logixia/issues/new)
- Want to fix it? Submit a pull request!

#### ✨ **New Features**
- **Transport Integrations**: Add support for new logging services (Elasticsearch, Splunk, etc.)
- **Performance Optimizations**: Help us make Logixia even faster
- **Developer Tools**: Build tools that make Logixia easier to use

#### 📚 **Documentation & Examples**
- Improve existing documentation
- Create tutorials and guides
- Add real-world examples
- Translate documentation

#### 🧪 **Testing & Quality**
- Add test cases
- Improve test coverage
- Performance benchmarking
- Security auditing

### Contribution Guidelines

Please read our detailed [CONTRIBUTING.md](CONTRIBUTING.md) for:

- 📋 **Development setup** and workflow
- 🎨 **Code style** and standards
- 🧪 **Testing** requirements
- 📝 **Documentation** guidelines
- 🔄 **Pull request** process

### Recognition

All contributors are recognized in:
- 🏆 **Contributors section** below
- 📦 **Package.json** contributors field
- 🎉 **Release notes** for significant contributions
- 💫 **Special mentions** in our community channels

### Community

- 💬 **Discussions**: [GitHub Discussions](https://github.com/Logixia/logixia/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/Logixia/logixia/issues)
- 📧 **Email**: logixia@example.com
- 🐦 **Twitter**: [@LogixiaJS](https://twitter.com/LogixiaJS)

### Contributors

Thanks to all our amazing contributors! 🙏

<!-- Contributors will be automatically added here -->

### 🎃 Hacktoberfest Ready!

**We're officially participating in Hacktoberfest 2024!** 

- 🏷️ **Labeled Issues**: Look for `hacktoberfest` and `good first issue` labels
- 📋 **Quality Focus**: We prioritize meaningful contributions over quantity
- 🤝 **Welcoming Community**: New contributors are always welcome
- 📚 **Comprehensive Docs**: Check our [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines
- 🎯 **Clear Scope**: Well-defined issues with clear acceptance criteria

## License

📄 **Open Source & Free Forever**

Logixia is proudly **open source** and licensed under the [MIT License](LICENSE). This means:

✅ **Free to use** - Commercial and personal projects  
✅ **Free to modify** - Customize to your needs  
✅ **Free to distribute** - Share with your team  
✅ **No attribution required** - Though we appreciate it!  

### What this means for you:

- 🏢 **Enterprise-friendly**: Use in commercial applications without licensing fees
- 🔧 **Modification rights**: Fork, modify, and customize as needed
- 📦 **Distribution rights**: Include in your own packages and applications
- 🤝 **Community-driven**: Benefit from community contributions and improvements

### MIT License Summary

```
MIT License

Copyright (c) 2025 Logixia Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

See the complete [LICENSE](LICENSE) file for full terms and conditions.

### Third-Party Licenses

Logixia respects all third-party licenses. See [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md) for details about dependencies and their licenses.

## Acknowledgments

### Technical Foundation

- **TypeScript**: Leveraging advanced type system for enhanced developer experience
- **Node.js**: Built on the robust Node.js runtime environment
- **Modern JavaScript**: Utilizing latest ECMAScript features and best practices

### Design Philosophy

- **Enterprise-Ready**: Designed for production environments and scalable applications
- **Developer Experience**: Prioritizing intuitive APIs and comprehensive documentation
- **Performance**: Optimized for high-throughput logging scenarios
- **Extensibility**: Architected for easy customization and extension

### Community

Built for and by the TypeScript and Node.js development community, with a focus on modern logging requirements and enterprise-grade reliability.