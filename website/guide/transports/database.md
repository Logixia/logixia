---
title: Database Transport
description: Store logixia logs in PostgreSQL, MySQL, MongoDB or SQLite with batched inserts, automatic tables, bounded buffering and isolation of rows the database rejects.
order: 4
---

# Database Transport

The database transport writes entries to PostgreSQL, MySQL, MongoDB or SQLite in batches. It connects on the first write, creates the table for you (SQL databases), and keeps entries in a bounded buffer while the database is unreachable.

## Install a driver

logixia does not bundle database drivers, and it does not list them as dependencies. Install the one you use. The transport loads it on first connect and throws a clear "driver not installed" error if it is missing.

::: code-group

```bash [npm]
npm install logixia pg
```

```bash [pnpm]
pnpm add logixia pg
```

```bash [yarn]
yarn add logixia pg
```

:::

| `type`         | Packages to install                      |
| -------------- | ---------------------------------------- |
| `'postgresql'` | `pg`                                     |
| `'mysql'`      | `mysql2`                                 |
| `'mongodb'`    | `mongodb`                                |
| `'sqlite'`     | `sqlite3` and `sqlite` (both are needed) |

## Quick start

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    database: {
      type: 'postgresql',
      host: 'localhost',
      port: 5432,
      database: 'appdb',
      table: 'logs',
      username: 'logger',
      password: process.env.DB_PASSWORD!,
      batchSize: 100,
      flushInterval: 5000,
    },
  },
});

await logger.error('Payment failed', { orderId: 'o_1' });
await logger.close();
```

## Options

| Option             | Type                                               | Default  | Description                                                                                   |
| ------------------ | -------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------- |
| `type`             | `'mongodb' \| 'postgresql' \| 'mysql' \| 'sqlite'` | required | Which database to use.                                                                        |
| `database`         | `string`                                           | required | Database name. For SQLite this is the file path.                                              |
| `connectionString` | `string`                                           | unset    | Used by PostgreSQL and MongoDB. MySQL ignores it; use `host`, `port`, `username`, `password`. |
| `host`             | `string`                                           | unset    | Server host.                                                                                  |
| `port`             | `number`                                           | unset    | Server port.                                                                                  |
| `username`         | `string`                                           | unset    | Database user.                                                                                |
| `password`         | `string`                                           | unset    | Database password.                                                                            |
| `ssl`              | `boolean`                                          | unset    | `true` enables TLS for PostgreSQL and MySQL with default options.                             |
| `table`            | `string`                                           | `'logs'` | Table name for the SQL databases.                                                             |
| `collection`       | `string`                                           | `'logs'` | Collection name for MongoDB.                                                                  |
| `batchSize`        | `number`                                           | `100`    | Entries per insert.                                                                           |
| `flushInterval`    | `number` (ms)                                      | `5000`   | Write whatever is buffered after this long.                                                   |
| `maxBufferSize`    | `number`                                           | `10000`  | Most entries buffered while the database is unreachable. Never below `batchSize`.             |
| `level`            | `string`                                           | unset    | Minimum level for this transport.                                                             |
| `filter`           | `(entry) => boolean`                               | unset    | Return `false` to skip an entry on this transport.                                            |

For MongoDB, prefer `connectionString`. Without it, the transport builds `mongodb://host:port/database` from the other fields.

## Examples

### MongoDB

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    database: {
      type: 'mongodb',
      connectionString: process.env.MONGO_URI!,
      database: 'appdb',
      collection: 'logs',
    },
  },
});
```

### SQLite

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'development',
  transports: {
    database: {
      type: 'sqlite',
      database: './logs/app.sqlite',
      table: 'logs',
    },
  },
});
```

### Two databases at once

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    database: [
      {
        type: 'postgresql',
        connectionString: process.env.PG_URL!,
        database: 'appdb',
        table: 'logs',
      },
      { type: 'mongodb', connectionString: process.env.MONGO_URI!, database: 'appdb' },
    ],
  },
});
```

## What gets stored

The SQL tables are created with `CREATE TABLE IF NOT EXISTS` on first connect. The table name must start with a letter or underscore and contain only letters, digits and underscores; anything else throws when the transport is constructed.

| Column        | Meaning                                                                       |
| ------------- | ----------------------------------------------------------------------------- |
| `id`          | Auto-increment primary key                                                    |
| `timestamp`   | Entry time                                                                    |
| `level`       | Level name                                                                    |
| `message`     | Message text                                                                  |
| `payload`     | Your structured data (`JSONB` on PostgreSQL, `JSON` on MySQL, text on SQLite) |
| `context`     | Logger context                                                                |
| `trace_id`    | Trace ID                                                                      |
| `app_name`    | `appName`                                                                     |
| `environment` | `environment`                                                                 |
| `created_at`  | Row creation time                                                             |

The tables also have a `time_taken` column that the transport does not fill. Indexes are created on `timestamp`, `level` and `trace_id`.

MongoDB documents have `timestamp`, `level`, `message`, `payload`, `context`, `traceId`, `appName` and `environment`. logixia does not create indexes in MongoDB.

## When the database is down

Entries are buffered in memory and sent in batches of `batchSize`. If a write fails because of a connection, timeout, authentication or other non-data error:

1. The batch goes back to the front of the buffer, in its original order.
2. The flush stops, so a dead database is not hammered. The next timer tick or threshold tries again.
3. The buffer never grows past `maxBufferSize`. The oldest entries are dropped first, and the count is reported on stderr at most every 5 seconds.

A failed connect clears itself, so the next write tries to connect again.

## When the database rejects a row

Some failures say the data itself is bad and will never succeed, such as a constraint violation, a value that is too long or a document that is too large. Retrying those forever would block every log behind one bad row, so logixia treats them differently:

- It recognizes data errors per driver: PostgreSQL SQLSTATE classes `22`, `23` and `54`; a fixed set of MySQL codes (for example `ER_DATA_TOO_LONG`, `ER_DUP_ENTRY`); SQLite `SQLITE_CONSTRAINT*`, `SQLITE_TOOBIG` and `SQLITE_MISMATCH`; and MongoDB codes `2`, `121`, `10334` and `11000` plus `BSONObjectTooLarge`. It also looks at the error's `cause` up to three levels deep.
- When a batch fails with a data error, it splits the batch in half repeatedly to find the refused entries, writes the rest, and drops only the refused ones. A warning says how many entries were dropped.
- The search has a write budget of twice `batchSize` per flush. If it runs out, or a non-data error shows up mid-search, the entries not yet written go back to the buffer.
- MongoDB inserts are unordered, so only the documents the server refused are retried or dropped; the others are stored once.
- PostgreSQL text and JSONB reject NUL characters, so logixia strips them before inserting.

::: tip
Large batches are split to stay inside driver limits: at most 8,191 rows per PostgreSQL insert and 5,000 per MySQL insert.
:::

## Closing

`close()` stops the timer, then tries to flush up to three times. If entries are still buffered after that, it reports how many on stderr and closes the connection anyway, so a permanently dead database cannot hang shutdown. Pair it with [Graceful shutdown](/guide/graceful-shutdown).

## Related

- [Transports overview](/guide/transports/)
- [Worker thread transport](/guide/transports/worker) to run the database writes in a worker
- [Security](/guide/security) for how credentials are kept out of serialized output and errors
