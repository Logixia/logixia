/**
 * Express integration example for logixia
 */

import express from 'express';
import {
  createLogger,
  DEFAULT_TRACE_HEADERS,
  extractTraceId,
  generateTraceId,
  getCurrentTraceId,
  runWithTraceId,
} from '../src';

// Create Express app
const app = express();
app.use(express.json());

// Create logger instance
const logger = createLogger({
  appName: 'ExpressApp',
  environment: 'development',
  traceId: true,
  format: {
    timestamp: true,
    colorize: true,
    json: false
  },
  levelOptions: {
    level: 'info',
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

// Trace middleware: reuse a validated incoming trace ID (traceparent, x-trace-id, ...) or generate one
app.use((req, res, next) => {
  const traceId =
    extractTraceId(req, { header: DEFAULT_TRACE_HEADERS, query: ['traceId'] }) ?? generateTraceId();
  res.setHeader('X-Trace-Id', traceId);
  runWithTraceId(traceId, () => next());
});

// Request logging middleware
app.use((req, res, next) => {
  const traceId = getCurrentTraceId();
  logger.info(`${req.method} ${req.path}`, {
    method: req.method,
    path: req.path,
    traceId,
    userAgent: req.get('User-Agent'),
    ip: req.ip
  });
  next();
});

// Routes
app.get('/', async (req, res) => {
  await logger.info('Processing home route');
  res.json({ message: 'Hello from the logixia Express example!', traceId: getCurrentTraceId() });
});

app.get('/users/:id', async (req, res) => {
  const { id } = req.params;
  const userLogger = logger.child('UserRoute', { userId: id });
  
  await userLogger.info('Fetching user data');
  
  // Simulate async operation with timing
  const userData = await logger.timeAsync('fetch-user', async () => {
    await new Promise(resolve => setTimeout(resolve, 100));
    return { id, name: 'John Doe', email: 'john@example.com' };
  });
  
  await userLogger.info('User data fetched successfully');
  res.json(userData);
});

app.post('/users', async (req, res) => {
  const userData = req.body;
  
  try {
    await logger.info('Creating new user', { userData });
    
    // Simulate user creation
    logger.time('create-user');
    await new Promise(resolve => setTimeout(resolve, 150));
    const timeTaken = await logger.timeEnd('create-user');
    
    const newUser = { id: Date.now(), ...userData };
    
    await logger.info('User created successfully', { 
      userId: newUser.id, 
      timeTaken: `${timeTaken}ms` 
    });
    
    res.status(201).json(newUser);
  } catch (error) {
    await logger.error(error as Error, { userData });
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.get('/error', async (req, res) => {
  try {
    throw new Error('Intentional error for testing');
  } catch (error) {
    await logger.error(error as Error, { route: '/error' });
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Error handling middleware
app.use(async (err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  await logger.error(err, {
    method: req.method,
    path: req.path,
    traceId: getCurrentTraceId()
  });
  
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  await logger.info(`Express server started on port ${PORT}`);
  await logger.info('Available routes:', {
    routes: [
      'GET /',
      'GET /users/:id',
      'POST /users',
      'GET /error'
    ]
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  await logger.info('Received SIGTERM, shutting down gracefully');
  await logger.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  await logger.info('Received SIGINT, shutting down gracefully');
  await logger.close();
  process.exit(0);
});

export { app, logger };