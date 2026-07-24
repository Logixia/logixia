import type {
  DatabaseTransportConfig,
  IAsyncTransport,
  IBatchTransport,
  TransportLogEntry,
} from '../types/transport.types';
import { internalError } from '../utils/internal-log';

/**
 * Validates that a SQL identifier (table/index name) contains only safe characters.
 * Prevents SQL injection via user-supplied table names.
 */
function validateSqlIdentifier(name: string, label = 'table'): void {
  if (!/^[a-zA-Z_]\w*$/.test(name)) {
    throw new Error(
      `Invalid ${label} name "${name}". Only letters, digits, and underscores are allowed, and the name must start with a letter or underscore.`
    );
  }
}

/**
 * Persists log entries to a database in batches.
 *
 * Supports MongoDB, PostgreSQL, MySQL, and SQLite. Entries are buffered and
 * flushed on a configurable interval or batch size threshold to minimize
 * round-trips.
 *
 * @example
 * transports: {
 *   database: { type: 'postgresql', host: 'localhost', database: 'appdb', table: 'logs' }
 * }
 */
export class DatabaseTransport implements IAsyncTransport, IBatchTransport {
  public readonly name = 'database';
  public readonly batchSize: number;
  public readonly flushInterval: number;
  public readonly filter?: (entry: TransportLogEntry) => boolean;

  private batch: TransportLogEntry[] = [];
  private flushTimer?: NodeJS.Timeout | undefined;
  /**
   * The in-flight drain promise, or undefined when idle. Concurrent flush()
   * calls (the un-awaited threshold flush write() fires, plus the interval
   * timer) all await this single promise instead of starting their own drain,
   * so a batch is never snapshotted and written twice. Mirrors the FileTransport
   * fix for the overlapping-batch-flush duplication bug.
   */
  private flushPromise?: Promise<void> | undefined;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- dynamic database driver connection object
  private connection: any;
  private isConnected = false;
  private connectionPromise?: Promise<void> | undefined;

  constructor(private config: DatabaseTransportConfig) {
    this.batchSize = config.batchSize || 100;
    this.flushInterval = config.flushInterval || 5000; // 5 seconds
    if (config.filter) this.filter = config.filter;
    // Validate table name early so misconfiguration fails at construction, not at first write
    if (config.table) {
      validateSqlIdentifier(config.table, 'table');
    }
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
    // Serialize concurrent flushes. write() fires flush() un-awaited once the
    // batch crosses batchSize, and the interval timer fires it too, so a burst
    // of writes can trigger many overlapping flushes. Every caller joins the
    // SAME in-flight drain, so a batch is never snapshotted and written twice —
    // the same overlapping-flush duplication that turned N file logs into N²
    // lines (see FileTransport fix). Awaiters still see the batch fully drained
    // because they await the shared drain promise.
    if (!this.flushPromise) {
      this.flushPromise = this.drain().finally(() => {
        this.flushPromise = undefined;
      });
    }

    await this.flushPromise;
  }

  /**
   * Drains the batch to the database one snapshot at a time. The current batch
   * is detached SYNCHRONOUSLY before awaiting the write, so entries appended by
   * concurrent write() calls land in a fresh array and are never written twice.
   * On write failure the snapshot is restored to the front of the batch for the
   * next flush cycle and the loop stops, so a persistently failing DB does not
   * hot-spin retrying the same entries.
   */
  private async drain(): Promise<void> {
    while (this.batch.length > 0) {
      const entriesToFlush = this.batch;
      this.batch = [];

      try {
        switch (this.config.type) {
          case 'mongodb':
            await this.flushToMongoDB(entriesToFlush);
            break;
          case 'postgresql':
            await this.flushToPostgreSQL(entriesToFlush);
            break;
          case 'mysql':
            await this.flushToMySQL(entriesToFlush);
            break;
          case 'sqlite':
            await this.flushToSQLite(entriesToFlush);
            break;
          default:
            throw new Error(`Unsupported database type: ${this.config.type}`);
        }
      } catch (error) {
        internalError('Database flush error', error);
        // Restore failed entries to the front of the batch (ahead of anything
        // appended while the write was in flight) so ordering is preserved and
        // they retry on the next flush. Stop draining to avoid a tight retry loop.
        this.batch.unshift(...entriesToFlush);
        throw error;
      }
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

    // Clear the memoized promise on failure so a transient startup error does
    // not permanently wedge the transport — the next write() retries the connect
    // instead of re-awaiting a forever-rejected promise.
    this.connectionPromise = this.establishConnection().catch((error: unknown) => {
      this.connectionPromise = undefined;
      throw error;
    });
    return this.connectionPromise;
  }

  private async establishConnection(): Promise<void> {
    try {
      switch (this.config.type) {
        case 'mongodb':
          await this.connectMongoDB();
          break;
        case 'postgresql':
          await this.connectPostgreSQL();
          break;
        case 'mysql':
          await this.connectMySQL();
          break;
        case 'sqlite':
          await this.connectSQLite();
          break;
      }
      this.isConnected = true;
    } catch (error) {
      this.isConnected = false;
      throw new Error(`Database connection failed: ${error}`, { cause: error });
    }
  }

  private async connectMongoDB(): Promise<void> {
    try {
      const { MongoClient } = await import('mongodb').catch(() => {
        throw new Error('MongoDB driver not installed. Run: npm install mongodb');
      });
      const connectionString =
        this.config.connectionString ||
        `mongodb://${this.config.host}:${this.config.port}/${this.config.database}`;

      this.connection = new MongoClient(connectionString);
      await this.connection.connect();

      // Test connection
      await this.connection.db(this.config.database).admin().ping();
    } catch (error) {
      throw new Error(`MongoDB connection failed: ${error}`, { cause: error });
    }
  }

  private async connectPostgreSQL(): Promise<void> {
    try {
      const { Client } = await import('pg').catch(() => {
        throw new Error('PostgreSQL driver not installed. Run: npm install pg @types/pg');
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- pg.Client accepts any config shape
      const config: any = {
        connectionString: this.config.connectionString,
        host: this.config.host,
        port: this.config.port,
        database: this.config.database,
      };

      if (this.config.username) config.user = this.config.username;
      if (this.config.password) config.password = this.config.password;
      if (this.config.ssl) config.ssl = typeof this.config.ssl === 'boolean' ? {} : this.config.ssl;

      this.connection = new Client(config);

      await this.connection.connect();
      await this.createPostgreSQLTable();
    } catch (error) {
      throw new Error(`PostgreSQL connection failed: ${error}`, { cause: error });
    }
  }

  private async connectMySQL(): Promise<void> {
    try {
      const mysql = await import('mysql2/promise').catch(() => {
        throw new Error('MySQL driver not installed. Run: npm install mysql2');
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- mysql2 accepts any config shape
      const config: any = {
        host: this.config.host,
        port: this.config.port,
        database: this.config.database,
      };

      if (this.config.username) config.user = this.config.username;
      if (this.config.password) config.password = this.config.password;
      if (this.config.ssl) config.ssl = typeof this.config.ssl === 'boolean' ? {} : this.config.ssl;

      this.connection = await mysql.createConnection(config);

      await this.createMySQLTable();
    } catch (error) {
      throw new Error(`MySQL connection failed: ${error}`, { cause: error });
    }
  }

  private async connectSQLite(): Promise<void> {
    try {
      // Optional peer dependencies resolved at runtime only.
      // Variable module specifiers bypass TS static resolution so logixia can
      // ship without declaring `sqlite`/`sqlite3` as devDependencies.
      const sqlite3ModuleName = 'sqlite3';
      const sqliteModuleName = 'sqlite';
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- optional runtime dependency without bundled types
      const sqlite3: any = await import(sqlite3ModuleName).catch(() => {
        throw new Error('SQLite driver not installed. Run: npm install sqlite3 sqlite');
      });
      const { open } = (await import(sqliteModuleName).catch(() => {
        throw new Error('SQLite driver not installed. Run: npm install sqlite3 sqlite');
      })) as { open: (opts: { filename: string; driver: unknown }) => Promise<unknown> };

      this.connection = await open({
        filename: this.config.database,
        driver: sqlite3.Database,
      });

      await this.createSQLiteTable();
    } catch (error) {
      throw new Error(`SQLite connection failed: ${error}`, { cause: error });
    }
  }

  private async flushToMongoDB(entries: TransportLogEntry[]): Promise<void> {
    const db = this.connection.db(this.config.database);
    const collection = db.collection(this.config.collection || 'logs');

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
    const tableName = this.config.table || 'logs';
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
          `($${i * 8 + 1}, $${i * 8 + 2}, $${i * 8 + 3}, $${i * 8 + 4}, $${i * 8 + 5}, $${i * 8 + 6}, $${i * 8 + 7}, $${i * 8 + 8})`
      )
      .join(', ');

    const query = `
      INSERT INTO ${tableName} 
      (timestamp, level, message, payload, context, trace_id, app_name, environment)
      VALUES ${placeholders}
    `;

    await this.connection.query(query, values.flat());
  }

  private async flushToMySQL(entries: TransportLogEntry[]): Promise<void> {
    const tableName = this.config.table || 'logs';
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
    const tableName = this.config.table || 'logs';

    const stmt = await this.connection.prepare(`
      INSERT INTO ${tableName} 
      (timestamp, level, message, payload, context, trace_id, app_name, environment)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const entry of entries) {
      await stmt.run(
        entry.timestamp instanceof Date ? entry.timestamp.toISOString() : entry.timestamp,
        entry.level,
        entry.message,
        JSON.stringify(entry.data || {}),
        entry.context,
        entry.traceId,
        entry.appName,
        entry.environment
      );
    }

    await stmt.finalize();
  }

  private async createPostgreSQLTable(): Promise<void> {
    const tableName = this.config.table || 'logs';
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
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_timestamp ON ${tableName} (timestamp)`
    );
    await this.connection.query(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_level ON ${tableName} (level)`
    );
    await this.connection.query(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_trace_id ON ${tableName} (trace_id)`
    );
  }

  private async createMySQLTable(): Promise<void> {
    const tableName = this.config.table || 'logs';
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
    const tableName = this.config.table || 'logs';
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
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_timestamp ON ${tableName} (timestamp)`
    );
    await this.connection.exec(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_level ON ${tableName} (level)`
    );
    await this.connection.exec(
      `CREATE INDEX IF NOT EXISTS idx_${tableName}_trace_id ON ${tableName} (trace_id)`
    );
  }

  private setupFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush().catch((error: unknown) => {
        internalError('Scheduled database flush error', error);
      });
    }, this.flushInterval);
  }

  async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = undefined;
    }

    // Drain remaining entries before closing the connection. This is the
    // shutdown path — losing buffered logs here is exactly the "last N seconds
    // of logs lost on deploy" problem the library promises to avoid, so we must
    // NOT let a single failed flush abort with entries still buffered.
    //
    // Retry a bounded number of times: each attempt flushes the current batch,
    // and a failed flush re-buffers its entries (see drain()) so the next
    // attempt picks them up. We stop early once the batch is empty, and cap the
    // attempts so a permanently-dead DB can't hang shutdown forever (the
    // flushOnExit force-exit timer is the outer backstop).
    const MAX_CLOSE_FLUSH_ATTEMPTS = 3;
    for (
      let attempt = 0;
      attempt < MAX_CLOSE_FLUSH_ATTEMPTS && this.batch.length > 0;
      attempt += 1
    ) {
      try {
        await this.flush();
      } catch (error) {
        internalError('Database flush during close failed; entries remain buffered', error);
      }
    }
    if (this.batch.length > 0) {
      internalError(
        `Database transport closing with ${this.batch.length} unflushed log entr${this.batch.length === 1 ? 'y' : 'ies'} after ${MAX_CLOSE_FLUSH_ATTEMPTS} attempts`
      );
    }

    // Close connection
    if (this.connection) {
      switch (this.config.type) {
        case 'mongodb':
          await this.connection.close();
          break;
        case 'postgresql':
          await this.connection.end();
          break;
        case 'mysql':
          await this.connection.end();
          break;
        case 'sqlite':
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
        case 'mongodb': {
          const collection = this.connection
            .db(this.config.database)
            .collection(this.config.collection || 'logs');
          return await collection.countDocuments();
        }

        case 'postgresql':
        case 'mysql':
        case 'sqlite': {
          const tableName = this.config.table || 'logs';
          const result = await this.connection.query(`SELECT COUNT(*) as count FROM ${tableName}`);
          // pg returns bigint COUNT as a string and mysql2 as a string too, so
          // coerce to a number — the declared return type is Promise<number>.
          const rawCount = result.rows?.[0]?.count ?? result[0]?.count ?? 0;
          return Number(rawCount) || 0;
        }

        default:
          return 0;
      }
    } catch {
      return 0;
    }
  }
}
