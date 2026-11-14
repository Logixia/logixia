import { LogixiaLogger } from "../src/core/logixia-logger";
import { TransportConfig } from "../src/types/transport.types";

// Advanced logging configuration with multiple transports
const config: TransportConfig = {
  // Console output with colors and timestamps
  console: {
    level: "debug",
    colorize: true,
    timestamp: true,
    format: "text",
  },

  // File output with rotation
  file: {
    level: "info",
    filename: "./logs/app.log",
    format: "csv",
    batchSize: 100,
    flushInterval: 5000, // 5 seconds
    rotation: {
      maxSize: "10MB",
      maxFiles: 5,
      interval: "1h", // Hourly rotation
      compress: true,
    },
  },

  // Database export (MongoDB example)
  database: {
    level: "warn",
    type: "mongodb",
    connectionString: "mongodb://localhost:27017/logs",
    database: "application_logs",
    collection: "error_logs",
    batchSize: 50,
    flushInterval: 10000, // 10 seconds
  },

  // Custom transports can be added here
  custom: [],
};

// Initialize logger with transport configuration
const logger = new LogixiaLogger({
  appName: "MyApp",
  environment: "production",
  level: "debug",
  transports: config,
  fields: {
    appName: true,
timestamp: false
  },
});

// Example usage demonstrating different log levels and data
async function demonstrateLogging() {
  console.log("🚀 Starting advanced logging demonstration...");

  // Debug logs (console only)
  logger.debug("Application starting up", {
    version: "1.0.0",
    nodeVersion: process.version,
  });

  // Info logs (console + file)
  logger.info("User authentication successful", {
    userId: "user123",
    sessionId: "sess456",
    ip: "192.168.1.100",
  });

  // Warning logs (console + file + database)
  logger.warn("High memory usage detected", {
    memoryUsage: process.memoryUsage(),
    threshold: "80%",
    action: "monitoring",
  });

  // Error logs (all transports)
  logger.error("Database connection failed", {
    error: "Connection timeout",
    database: "primary",
    retryAttempt: 3,
    stack: new Error("Sample error").stack,
  });

  // Batch logging example
  console.log("\n📦 Generating batch logs...");
  for (let i = 0; i < 150; i++) {
    logger.info(`Batch log entry ${i + 1}`, {
      batchId: "batch001",
      sequence: i + 1,
      timestamp: new Date().toISOString(),
    });
  }

  // Wait for batch processing
  console.log("⏳ Waiting for batch processing...");
  await new Promise((resolve) => setTimeout(resolve, 6000));

  // Force flush all transports
  console.log("🔄 Flushing all transports...");
  await logger.flush();

  // Demonstrate rotation (simulate time passage)
  console.log("\n🔄 Demonstrating log rotation...");
  for (let hour = 0; hour < 3; hour++) {
    logger.info(`Hourly log entry for hour ${hour}`, {
      hour,
      simulatedTime: new Date(Date.now() + hour * 3600000).toISOString(),
    });
  }

  // Health check
  console.log("\n🏥 Checking transport health...");
  const health = await logger.healthCheck();
  console.log("Transport health status:", health);

  // Graceful shutdown
  console.log("\n🛑 Shutting down logger...");
  await logger.close();

  console.log("✅ Advanced logging demonstration completed!");
}

// Time-based rotation examples
function demonstrateRotationPatterns() {
  console.log("\n⏰ Available rotation patterns:");
  console.log("- YYYY-MM-DD-HH: Hourly rotation");
  console.log("- YYYY-MM-DD: Daily rotation");
  console.log("- YYYY-[W]WW: Weekly rotation");
  console.log("- YYYY-MM: Monthly rotation");
  console.log("- Custom intervals: 1h, 6h, 12h, 1d, 7d, 30d");
}

// Error handling example
process.on("uncaughtException", (error) => {
  logger.error("Uncaught exception", {
    error: error.message,
    stack: error.stack,
    type: "uncaughtException",
  });

  // Ensure logs are flushed before exit
  logger.flush().then(() => {
    process.exit(1);
  });
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled promise rejection", {
    reason: String(reason),
    promise: String(promise),
    type: "unhandledRejection",
  });
});

// Run the demonstration
if (require.main === module) {
  demonstrateRotationPatterns();
  demonstrateLogging().catch(console.error);
}

export { config, logger };
