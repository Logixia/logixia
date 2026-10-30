import type {
  DatabaseTransportConfig,
  IAsyncTransport,
  IBatchTransport,
  TransportLogEntry,
} from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';
import { BufferCap } from './buffer-cap';
import { protectSecrets, scrubError, urlSecrets } from './secret-config';

/**
 * Validates that a SQL identifier (table/index name) contains only safe characters.
 * Prevents SQL injection via user-supplied table names.
 */
const POSTGRES_MAX_PARAMS = 65535;
const POSTGRES_COLUMNS = 8;
const POSTGRES_ROWS_PER_INSERT = Math.floor(POSTGRES_MAX_PARAMS / POSTGRES_COLUMNS);
const MYSQL_ROWS_PER_INSERT = 5000;

/** Postgres rejects NUL in TEXT and JSONB. */
function stripNul(value: unknown): unknown {
  return typeof value === 'string' ? value.split('\u0000').join('') : value;
}

/** JSONB also rejects the \u0000 escape, which JSON.stringify writes for a NUL. */
function stripJsonNulEscape(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return value.replace(/(?<!\\)((?:\\\\)*)\\u0000/g, '$1');
}

const PG_DATA_CLASSES = ['22', '23', '54'];
const MYSQL_DATA_CODES = new Set([
  'ER_DATA_TOO_LONG',
  'ER_TRUNCATED_WRONG_VALUE',
  'ER_TRUNCATED_WRONG_VALUE_FOR_FIELD',
  'ER_BAD_NULL_ERROR',
  'ER_WARN_DATA_OUT_OF_RANGE',
  'ER_DUP_ENTRY',
  'ER_INVALID_JSON_TEXT',
  'ER_INVALID_CHARACTER_STRING',
]);
const MYSQL_DATA_ERRNOS = new Set([1048, 1062, 1264, 1292, 1366, 1406, 3140]);
const SQLITE_DATA_CODES = new Set(['SQLITE_CONSTRAINT', 'SQLITE_TOOBIG', 'SQLITE_MISMATCH']);
const MONGO_DATA_CODES = new Set([2, 121, 10334, 11000]);

interface DriverError {
  code?: unknown;
  errno?: unknown;
  name?: unknown;
  cause?: unknown;
}

function isDataErrorLayer(type: string, e: DriverError): boolean {
  const code = e.code;
  switch (type) {
    case 'postgresql':
      return typeof code === 'string' && PG_DATA_CLASSES.includes(code.slice(0, 2));
    case 'mysql':
      return (
        (typeof code === 'string' && MYSQL_DATA_CODES.has(code)) ||
        (typeof e.errno === 'number' && MYSQL_DATA_ERRNOS.has(e.errno))
      );
    case 'sqlite':
      return (
        typeof code === 'string' &&
        (SQLITE_DATA_CODES.has(code) || code.startsWith('SQLITE_CONSTRAINT_'))
      );
    case 'mongodb':
      return (
        e.name === 'BSONObjectTooLarge' || (typeof code === 'number' && MONGO_DATA_CODES.has(code))
      );
    default:
      return false;
  }
}

/**
 * True when the database refused the data itself (bad value, constraint, size),
 * which retrying cannot fix. Connection, timeout, auth and unknown errors are
 * not data errors and must be retried, never dropped.
 */
export function isDataError(type: string, error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 3 && current && typeof current === 'object'; depth += 1) {
    if (isDataErrorLayer(type, current as DriverError)) return true;
    current = (current as DriverError).cause;
  }
  return false;
}

interface IsolationState {
  budget: number;
  rejected: number;
  requeue: TransportLogEntry[];
  stopped: boolean;
  error?: unknown;
}

/** A write that stored part of a batch: only `remaining` still needs to be written. */
class PartialWriteError extends Error {
  constructor(
    message: string,
    public readonly remaining: TransportLogEntry[],
    cause: unknown
  ) {
    super(message, { cause });
  }
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

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
  private readonly cap: BufferCap;

  constructor(private config: DatabaseTransportConfig) {
    this.batchSize = config.batchSize || 100;
    this.flushInterval = config.flushInterval || 5000; // 5 seconds
    this.cap = new BufferCap('DatabaseTransport', config.maxBufferSize, this.batchSize);
    if (config.filter) this.filter = config.filter;
    // Validate table name early so misconfiguration fails at construction, not at first write
    if (config.table) {
      validateSqlIdentifier(config.table, 'table');
    }
    this.setupFlushTimer();
    protectSecrets(this, ['config', 'connection']);
  }

  private secretValues(): (string | undefined)[] {
    const { connectionString, password } = this.config;
    return [connectionString, password, ...(connectionString ? urlSecrets(connectionString) : [])];
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
    this.cap.enforce(this.batch);
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
   * Drains the buffer to the database one batch at a time. A batch is detached
   * SYNCHRONOUSLY before awaiting the write, so entries appended by concurrent
   * write() calls land in a fresh array and are never written twice.
   *
   * A failure that is not a data error (connection, timeout, auth, unknown) puts
   * the batch back at the front of the buffer, bounded by `maxBufferSize`, and
   * stops the loop so a down database is not hammered. A data error means the
   * database refused some entry itself, so that batch alone is split to find and
   * drop the refused entries; see isolate().
   */
  private async drain(): Promise<void> {
    while (this.batch.length > 0) {
      const entries = this.batch.splice(0, this.batchSize);

      try {
        await this.writeEntries(entries);
      } catch (error) {
        internalError('Database flush error', error);
        if (error instanceof PartialWriteError) {
          this.requeue(error.remaining);
          throw error.cause;
        }
        if (!isDataError(this.config.type, error)) {
          this.requeue(entries);
          throw error;
        }
        const state: IsolationState = {
          budget: 2 * this.batchSize,
          rejected: 0,
          requeue: [],
          stopped: false,
        };
        await this.isolate(entries, state);
        if (state.rejected > 0) {
          internalWarn(
            `DatabaseTransport: dropped ${state.rejected} log entr${state.rejected === 1 ? 'y' : 'ies'} the database rejected`
          );
        }
        this.requeue(state.requeue);
        if (state.stopped) throw state.error;
      }
    }
  }

  private requeue(entries: TransportLogEntry[]): void {
    if (entries.length === 0) return;
    this.batch = entries.concat(this.batch);
    this.cap.enforce(this.batch);
  }

  private async writeEntries(entries: TransportLogEntry[]): Promise<void> {
    switch (this.config.type) {
      case 'mongodb':
        await this.flushToMongoDB(entries);
        break;
      case 'postgresql':
        await this.flushToPostgreSQL(entries);
        break;
      case 'mysql':
        await this.flushToMySQL(entries);
        break;
      case 'sqlite':
        await this.flushToSQLite(entries);
        break;
      default:
        throw new Error(`Unsupported database type: ${this.config.type}`);
    }
  }

  /**
   * `entries` failed with a data error. Splits them in half until the refused
   * entries are alone and drops those. A write that fails with anything but a
   * data error, or running out of the per-flush write budget, stops the search:
   * the entries not yet written go back to the buffer.
   */
  private async isolate(entries: TransportLogEntry[], state: IsolationState): Promise<void> {
    if (entries.length === 1) {
      state.rejected += 1;
      return;
    }
    const mid = Math.ceil(entries.length / 2);
    for (const half of [entries.slice(0, mid), entries.slice(mid)]) {
      if (state.stopped || state.budget <= 0) {
        state.requeue.push(...half);
        continue;
      }
      state.budget -= 1;
      try {
        await this.writeEntries(half);
      } catch (error) {
        if (error instanceof PartialWriteError) {
          state.requeue.push(...error.remaining);
          state.stopped = true;
          state.error = error.cause;
        } else if (isDataError(this.config.type, error)) {
          await this.isolate(half, state);
        } else {
          state.requeue.push(...half);
          state.stopped = true;
          state.error = error;
        }
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
      scrubError(error, this.secretValues());
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

    try {
      await collection.insertMany(documents, { ordered: false });
    } catch (error) {
      const raw = (error as { writeErrors?: unknown }).writeErrors;
      let list: unknown[] = [];
      if (Array.isArray(raw)) list = raw;
      else if (raw) list = [raw];
      const writeErrors = list as Array<{
        index?: number;
        code?: number;
      }>;
      if (writeErrors.length === 0) throw error;
      // Unordered inserts store every document that was not refused, so only
      // refused documents may be retried or dropped.
      const remaining: TransportLogEntry[] = [];
      let rejected = 0;
      for (const writeError of writeErrors) {
        const entry = typeof writeError.index === 'number' ? entries[writeError.index] : undefined;
        if (!entry) throw error;
        if (isDataError('mongodb', writeError)) rejected += 1;
        else remaining.push(entry);
      }
      if (rejected > 0) {
        internalWarn(
          `DatabaseTransport: dropped ${rejected} log entr${rejected === 1 ? 'y' : 'ies'} the database rejected`
        );
      }
      if (remaining.length > 0) {
        throw new PartialWriteError('MongoDB insert partially failed', remaining, error);
      }
    }
  }

  private async flushToPostgreSQL(entries: TransportLogEntry[]): Promise<void> {
    const tableName = this.config.table || 'logs';
    const values = entries.map((entry) =>
      [
        entry.timestamp,
        entry.level,
        entry.message,
        stringifyForLog(entry.data || {}),
        entry.context,
        entry.traceId,
        entry.appName,
        entry.environment,
      ].map((value, column) => stripNul(column === 3 ? stripJsonNulEscape(value) : value))
    );

    const chunks = chunk(values, POSTGRES_ROWS_PER_INSERT);
    const insertChunk = async (rows: unknown[][]): Promise<void> => {
      const placeholders = rows
        .map((_, i) => {
          const params = Array.from(
            { length: POSTGRES_COLUMNS },
            (_unused, c) => `$${i * POSTGRES_COLUMNS + c + 1}`
          );
          return `(${params.join(', ')})`;
        })
        .join(', ');

      const query = `
      INSERT INTO ${tableName} 
      (timestamp, level, message, payload, context, trace_id, app_name, environment)
      VALUES ${placeholders}
    `;

      await this.connection.query(query, rows.flat());
    };

    if (chunks.length === 1) {
      await insertChunk(chunks[0] as unknown[][]);
      return;
    }

    await this.connection.query('BEGIN');
    try {
      for (const rows of chunks) {
        await insertChunk(rows);
      }
      await this.connection.query('COMMIT');
    } catch (error) {
      await this.connection.query('ROLLBACK').catch(() => {});
      throw error;
    }
  }

  private async flushToMySQL(entries: TransportLogEntry[]): Promise<void> {
    const tableName = this.config.table || 'logs';
    const values = entries.map((entry) => [
      entry.timestamp,
      entry.level,
      entry.message,
      stringifyForLog(entry.data || {}),
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

    const chunks = chunk(values, MYSQL_ROWS_PER_INSERT);
    if (chunks.length === 1) {
      await this.connection.query(query, [values]);
      return;
    }

    await this.connection.beginTransaction();
    try {
      for (const rows of chunks) {
        await this.connection.query(query, [rows]);
      }
      await this.connection.commit();
    } catch (error) {
      await this.connection.rollback().catch(() => {});
      throw error;
    }
  }

  private async flushToSQLite(entries: TransportLogEntry[]): Promise<void> {
    const tableName = this.config.table || 'logs';

    const stmt = await this.connection.prepare(`
      INSERT INTO ${tableName} 
      (timestamp, level, message, payload, context, trace_id, app_name, environment)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await this.connection.exec('BEGIN');
    try {
      for (const entry of entries) {
        await stmt.run(
          entry.timestamp instanceof Date ? entry.timestamp.toISOString() : entry.timestamp,
          entry.level,
          entry.message,
          stringifyForLog(entry.data || {}),
          entry.context,
          entry.traceId,
          entry.appName,
          entry.environment
        );
      }
      await this.connection.exec('COMMIT');
    } catch (error) {
      await this.connection.exec('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      await stmt.finalize().catch(() => {});
    }
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
    this.flushTimer.unref?.();
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
    // A drain already running has detached its snapshot, so batch.length can be
    // 0 while rows are still being written. Wait for it before touching the
    // connection; a failure re-buffers its entries and the loop below retries.
    if (this.flushPromise) {
      await this.flushPromise.catch(() => {});
    }
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

    this.cap.report(0);

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

        case 'postgresql': {
          const tableName = this.config.table || 'logs';
          const result = await this.connection.query(`SELECT COUNT(*) as count FROM ${tableName}`);
          return Number(result.rows?.[0]?.count) || 0;
        }

        case 'mysql': {
          const tableName = this.config.table || 'logs';
          const [rows] = await this.connection.query(`SELECT COUNT(*) as count FROM ${tableName}`);
          return Number(rows?.[0]?.count) || 0;
        }

        case 'sqlite': {
          const tableName = this.config.table || 'logs';
          const row = await this.connection.get(`SELECT COUNT(*) as count FROM ${tableName}`);
          return Number(row?.count) || 0;
        }

        default:
          return 0;
      }
    } catch {
      return 0;
    }
  }
}
