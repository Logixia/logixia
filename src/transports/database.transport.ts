import {
  IAsyncTransport,
  IBatchTransport,
  TransportLogEntry,
  DatabaseTransportConfig,
} from "../types/transport.types";

export class DatabaseTransport implements IAsyncTransport, IBatchTransport {
  public readonly name = "database";
  public readonly batchSize: number;
  public readonly flushInterval: number;

  private batch: TransportLogEntry[] = [];
  private flushTimer?: NodeJS.Timeout;
  private connection: any;
  private isConnected = false;
  private connectionPromise?: Promise<void>;

  constructor(private config: DatabaseTransportConfig) {
    this.batchSize = config.batchSize || 100;
    this.flushInterval = config.flushInterval || 5000; // 5 seconds
    this.setupFlushTimer();
  }

  async write(entry: TransportLogEntry): Promise<void> {
    if (!this.isConnected) {
      await this.connect();
    }

    this.addToBatch(entry);

    if (this.batch.length >= this.batchSize) {
      await this.flush();
    }
  }

  addToBatch(entry: TransportLogEntry): void {
    this.batch.push(entry);
  }

  async flush(): Promise<void> {
    if (this.batch.length === 0) return;

    const entriesToFlush = [...this.batch];
    this.batch = [];

    try {
      switch (this.config.type) {
        case "mongodb":
          await this.flushToMongoDB(entriesToFlush);
          break;
        case "postgresql":
          await this.flushToPostgreSQL(entriesToFlush);
          break;
        case "mysql":
          await this.flushToMySQL(entriesToFlush);
          break;
        case "sqlite":
          await this.flushToSQLite(entriesToFlush);
          break;
        default:
          throw new Error(`Unsupported database type: ${this.config.type}`);
      }
    } catch (error) {
      console.error("Database flush error:", error);
      // Re-add failed entries to batch for retry
      this.batch.unshift(...entriesToFlush);
      throw error;
    }
  }

  async isReady(): Promise<boolean> {
    try {
      if (!this.isConnected) {
        await this.connect();
      }
      return this.isConnected;
    } catch {
      return false;
    }
  }

  private async connect(): Promise<void> {
    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = this.establishConnection();
    return this.connectionPromise;
  }

  private async establishConnection(): Promise<void> {
    try {
      switch (this.config.type) {
        case "mongodb":
          await this.connectMongoDB();
          break;
        case "postgresql":
          await this.connectPostgreSQL();
          break;
        case "mysql":
          await this.connectMySQL();
          break;
        case "sqlite":
          await this.connectSQLite();
          break;
      }
      this.isConnected = true;
    } catch (error) {
      this.isConnected = false;
      throw new Error(`Database connection failed: ${error}`);
    }
  }

  private async connectMongoDB(): Promise<void> {
    try {
      const { MongoClient } = await import("mongodb").catch(() => {
        throw new Error(
          "MongoDB driver not installed. Run: npm install mongodb",
        );
      });
      const connectionString =
        this.config.connectionString ||
        `mongodb://${this.config.host}:${this.config.port}/${this.config.database}`;

      this.connection = new MongoClient(connectionString);
      await this.connection.connect();

      // Test connection
      await this.connection.db(this.config.database).admin().ping();
    } catch (error) {
      throw new Error(`MongoDB connection failed: ${error}`);
    }
  }

  private async connectPostgreSQL(): Promise<void> {
    try {
      const { Client } = await import("pg").catch(() => {
        throw new Error(
          "PostgreSQL driver not installed. Run: npm install pg @types/pg",
        );
      });

      const config: any = {
        connectionString: this.config.connectionString,
        host: this.config.host,
        port: this.config.port,
        database: this.config.database,
      };

      if (this.config.username) config.user = this.config.username;
      if (this.config.password) config.password = this.config.password;
      if (this.config.ssl)
        config.ssl =
          typeof this.config.ssl === "boolean" ? {} : this.config.ssl;

      this.connection = new Client(config);

      await this.connection.connect();
      await this.createPostgreSQLTable();
    } catch (error) {
      throw new Error(`PostgreSQL connection failed: ${error}`);
    }
  }

  private async connectMySQL(): Promise<void> {
    try {
      const mysql = await import("mysql2/promise").catch(() => {
        throw new Error("MySQL driver not installed. Run: npm install mysql2");
      });

      const config: any = {
        host: this.config.host,
        port: this.config.port,
        database: this.config.database,
      };

      if (this.config.username) config.user = this.config.username;
      if (this.config.password) config.password = this.config.password;
      if (this.config.ssl)
        config.ssl =
          typeof this.config.ssl === "boolean" ? {} : this.config.ssl;

      this.connection = await mysql.createConnection(config);

      await this.createMySQLTable();
    } catch (error) {
      throw new Error(`MySQL connection failed: ${error}`);
    }
  }

  private async connectSQLite(): Promise<void> {
    try {
      const sqlite3 = await import("sqlite3").catch(() => {
        throw new Error(
          "SQLite driver not installed. Run: npm install sqlite3 sqlite",
        );
      });
      const { open } = await import("sqlite").catch(() => {
        throw new Error(
          "SQLite driver not installed. Run: npm install sqlite3 sqlite",
        );
      });

      this.connection = await open({
        filename: this.config.database,
        driver: sqlite3.Database,
      });

      await this.createSQLiteTable();
    } catch (error) {
      throw new Error(`SQLite connection failed: ${error}`);
    }
  }

  private async flushToMongoDB(entries: TransportLogEntry[]): Promise<void> {
    const db = this.connection.db(this.config.database);
    const collection = db.collection(this.config.collection || "logs");

    const documents = entries.map((entry) => ({
      timestamp: entry.timestamp,
      level: entry.level,
      message: entry.message,
      payload: entry.data,
      context: entry.context,
      traceId: entry.traceId,
      appName: entry.appName,
      environment: entry.environment,
    }));

    await collection.insertMany(documents);
  }

  private async flushToPostgreSQL(entries: TransportLogEntry[]): Promise<void> {
    const tableName = this.config.table || "logs";
    const values = entries.map((entry) => [
      entry.timestamp,
      entry.level,
      entry.message,
      JSON.stringify(entry.data || {}),
      entry.context,
      entry.traceId,
      entry.appName,
      entry.environment,
    ]);

    const placeholders = values
      .map(
        (_, i) =>
          `($${i * 9 + 1}, $${i * 9 + 2}, $${i * 9 + 3}, $${i * 9 + 4}, $${i * 9 + 5}, $${i * 9 + 6}, $${i * 9 + 7}, $${i * 9 + 8}, $${i * 9 + 9})`,
      )
      .join(", ");

    const query = `
      INSERT INTO ${tableName} 
      (timestamp, level, message, payload, context, trace_id, app_name, environment)
      VALUES ${placeholders}
    `;

    await this.connection.query(query, values.flat());
  }

  private async flushToMySQL(entries: TransportLogEntry[]): Promise<void> {
    const tableName = this.config.table || "logs";
    const values = entries.map((entry) => [
      entry.timestamp,
      entry.level,
      entry.message,
      JSON.stringify(entry.data || {}),
      entry.context,
      entry.traceId,
      entry.appName,
      entry.environment,
    ]);

    const query = `
      INSERT INTO ${tableName} 
      (timestamp, level, message, payload, context, trace_id, app_name, environment)
      VALUES ?
    `;

    await this.connection.query(query, [values]);
  }

  private async flushToSQLite(entries: TransportLogEntry[]): Promise<void> {
    const tableName = this.config.table || "logs";

    const stmt = await this.connection.prepare(`
      INSERT INTO ${tableName} 
      (timestamp, level, message, payload, context, trace_id, app_name, environment)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const entry of entries) {
      await stmt.run(
        entry.timestamp instanceof Date
          ? entry.timestamp.toISOString()
          : entry.timestamp,
        entry.level,
        entry.message,
        JSON.stringify(entry.data || {}),
        entry.context,
        entry.traceId,
        entry.appName,
        entry.environment,
      );
    }

    await stmt.finalize();
  }

  private async createPostgreSQLTable(): Promise<void> {
    const tableName = this.config.table || "logs";
    const query = `
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
        level VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        payload JSONB,
        context VARCHAR(255),
        trace_id VARCHAR(255),
        app_name VARCHAR(255),
        environment VARCHAR(50),
        time_taken INTEGER,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;

    await this.connection.query(query);

    // Create indexes for better performance
    await this.connection.query(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_timestamp ON ${tableName} (timestamp)`,
    );
    await this.connection.query(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_level ON ${tableName} (level)`,
    );
    await this.connection.query(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_trace_id ON ${tableName} (trace_id)`,
    );
  }

  private async createMySQLTable(): Promise<void> {
    const tableName = this.config.table || "logs";
    const query = `
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME NOT NULL,
        level VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        payload JSON,
        context VARCHAR(255),
        trace_id VARCHAR(255),
        app_name VARCHAR(255),
        environment VARCHAR(50),
        time_taken INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_timestamp (timestamp),
        INDEX idx_level (level),
        INDEX idx_trace_id (trace_id)
      )
    `;

    await this.connection.execute(query);
  }

  private async createSQLiteTable(): Promise<void> {
    const tableName = this.config.table || "logs";
    const query = `
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        payload TEXT,
        context TEXT,
        trace_id TEXT,
        app_name TEXT,
        environment TEXT,
        time_taken INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;

    await this.connection.exec(query);

    // Create indexes
    await this.connection.exec(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_timestamp ON ${tableName} (timestamp)`,
    );
    await this.connection.exec(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_level ON ${tableName} (level)`,
    );
    await this.connection.exec(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_trace_id ON ${tableName} (trace_id)`,
    );
  }

  private setupFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush().catch((error) => {
        console.error("Scheduled flush error:", error);
      });
    }, this.flushInterval);
  }

  async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }

    // Flush remaining entries
    await this.flush();

    // Close connection
    if (this.connection) {
      switch (this.config.type) {
        case "mongodb":
          await this.connection.close();
          break;
        case "postgresql":
          await this.connection.end();
          break;
        case "mysql":
          await this.connection.end();
          break;
        case "sqlite":
          await this.connection.close();
          break;
      }
    }

    this.isConnected = false;
  }

  // Utility methods
  getBatchInfo() {
    return {
      batchSize: this.batchSize,
      currentBatchLength: this.batch.length,
      flushInterval: this.flushInterval,
      isConnected: this.isConnected,
    };
  }

  async getLogCount(): Promise<number> {
    if (!this.isConnected) return 0;

    try {
      switch (this.config.type) {
        case "mongodb":
          const collection = this.connection
            .db(this.config.database)
            .collection(this.config.collection || "logs");
          return await collection.countDocuments();

        case "postgresql":
        case "mysql":
        case "sqlite":
          const tableName = this.config.table || "logs";
          const result = await this.connection.query(
            `SELECT COUNT(*) as count FROM ${tableName}`,
          );
          return result.rows?.[0]?.count || result[0]?.count || 0;

        default:
          return 0;
      }
    } catch {
      return 0;
    }
  }
}
