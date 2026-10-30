# Logixia Customization Guide

## Log Level Customization

### Predefined Log Levels

Logixia comes with predefined log levels:

- `error` (0) - Highest priority
- `warn` (1)
- `info` (2) - Default level
- `debug` (3)
- `trace` (4)
- `verbose` (5) - Lowest priority

### Custom Log Levels

You can define custom log levels with custom colors:

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  outputs: ['console'],
  levelOptions: {
    level: 'info',
    levels: {
      // Predefined levels (with intellisense)
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      trace: 4,
      verbose: 5,
      // Custom levels
      critical: 0,
      notice: 2,
      audit: 1,
    },
    colors: {
      // Predefined colors (with intellisense)
      error: 'red',
      warn: 'yellow',
      info: 'blue',
      debug: 'green',
      trace: 'gray',
      verbose: 'cyan',
      // Custom colors
      critical: 'magenta',
      notice: 'white',
      audit: 'brightYellow',
    },
  },
});
```

## Field Customization

### Default Fields

By default, Logitron includes these fields in log output:

- `timestamp` - Current date/time
- `level` - Log level
- `appName` - Application name
- `traceId` - Request trace ID
- `message` - Log message
- `payload` - Additional data
- `timeTaken` - Execution time (for timers)

### Disabling/Enabling Fields

You can control which fields appear in your logs:

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  outputs: ['console'],
  fields: {
    timestamp: true, // Show timestamp
    level: true, // Show log level
    appName: true, // Show app name
    traceId: false, // Hide trace ID
    message: true, // Show message
    payload: false, // Hide payload
    timeTaken: true, // Show execution time
  },
});
```

### Custom Field Formats

You can customize the format of individual fields:

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  outputs: ['console'],
  fields: {
    timestamp: '[YYYY-MM-DD HH:mm:ss]', // Custom timestamp format
    level: '[LEVEL]', // Custom level format
    appName: '{APP}', // Custom app name format
    traceId: 'ID:{TRACE}', // Custom trace ID format
    message: 'MSG: {MESSAGE}', // Custom message format
    payload: 'DATA: {PAYLOAD}', // Custom payload format
    timeTaken: 'TIME: {TIME}ms', // Custom timing format
  },
});
```

## Runtime Configuration

### Changing Log Level at Runtime

```typescript
// Set level using string
logger.setLevel('debug');

// Set level using enum
logger.setLevel(LogLevel.ERROR);

// Get current level
const currentLevel = logger.getLevel(); // Returns string
```

### Dynamic Field Configuration

```typescript
// Note: This feature requires additional implementation
// Future enhancement for runtime field toggling
logger.toggleField('payload', false); // Hide payload field
logger.toggleField('traceId', true); // Show trace ID field
```

## Color Customization

### Available Colors

- `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`
- `gray`, `brightRed`, `brightGreen`, `brightYellow`, `brightBlue`, `brightMagenta`, `brightCyan`, `brightWhite`

### Custom Color Schemes

```typescript
const logger = new LogixiaLogger({
  appName: 'MyApp',
  outputs: ['console'],
  levelOptions: {
    level: 'info',
    colors: {
      error: 'brightRed',
      warn: 'brightYellow',
      info: 'brightBlue',
      debug: 'brightGreen',
      trace: 'gray',
      verbose: 'brightCyan',
      // Custom level colors
      critical: 'magenta',
      audit: 'brightMagenta',
    },
  },
});
```

## Examples

### Minimal Configuration

```typescript
const minimalLogger = new LogixiaLogger({
  appName: 'MinimalApp',
  outputs: ['console'],
  fields: {
    timestamp: true,
    level: true,
    message: true,
    // All other fields disabled by default
  },
});
```

### Production Configuration

```typescript
const prodLogger = new LogixiaLogger({
  appName: 'ProdApp',
  outputs: ['file'],
  levelOptions: {
    level: 'warn', // Only warn and error in production
  },
  fields: {
    timestamp: true,
    level: true,
    appName: true,
    traceId: true,
    message: true,
    payload: true,
    timeTaken: false, // Disable timing in production
  },
});
```

### Development Configuration

```typescript
const devLogger = new LogixiaLogger({
  appName: 'DevApp',
  outputs: ['console'],
  levelOptions: {
    level: 'debug', // Show all logs in development
    colors: {
      error: 'brightRed',
      warn: 'brightYellow',
      info: 'brightBlue',
      debug: 'brightGreen',
      trace: 'gray',
      verbose: 'brightCyan',
    },
  },
  fields: {
    timestamp: true,
    level: true,
    appName: true,
    traceId: true,
    message: true,
    payload: true,
    timeTaken: true,
  },
});
```

## Best Practices

1. **Environment-based Configuration**: Use different configurations for development, staging, and production
2. **Consistent Field Naming**: Use consistent field names across your application
3. **Appropriate Log Levels**: Use appropriate log levels for different types of messages
4. **Performance Considerations**: Disable unnecessary fields in high-performance scenarios
5. **Security**: Be careful not to log sensitive information in payload fields

## Future Enhancements

- Runtime field toggling
- Custom field validators
- Field-level formatting functions
- Conditional field display
- Field encryption for sensitive data
