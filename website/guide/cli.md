---
title: Command line tool
description: Analyze, search, query, tail, export and explore JSON log files from the terminal with the logixia CLI, including SQL-like queries and an interactive explorer.
order: 19
---

# Command line tool

The `logixia` command reads log files and helps you answer questions about them: how many errors, which user, what happened in the last hour. It ships in the same package as the library.

```bash
npx logixia --help
```

Or install it globally:

::: code-group

```bash [npm]
npm install -g logixia
```

```bash [pnpm]
pnpm add -g logixia
```

```bash [yarn]
yarn global add logixia
```

:::

## Input format

The commands read a file of newline-delimited JSON (one object per line), which is what logixia's JSON file transport writes. Lines that are not valid JSON are kept as `{ "message": "<the line>" }`. Files are read into memory, and standard input (`-`) is not supported.

Commands that filter by level read the `level` field, and time filters read `timestamp`.

## Commands

| Command   | Purpose                                                       |
| --------- | ------------------------------------------------------------- |
| `analyze` | Count entries by level, with optional level and time filters. |
| `stats`   | Distribution of entries over a field, plus the time range.    |
| `search`  | Find entries matching a text or `field:value` query.          |
| `query`   | SQL-like queries, aggregations and time ranges.               |
| `tail`    | Show the last lines of a file and optionally follow it.       |
| `export`  | Convert to CSV or JSON, choosing fields.                      |
| `explore` | Interactive terminal explorer.                                |

Every command takes the file path as its first argument and exits with status 2 if the file does not exist. Use `logixia <command> --help` for the options.

### analyze

```bash
logixia analyze app.log
logixia analyze app.log --level error
logixia analyze app.log --last 24h
logixia analyze app.log --format json
```

| Option            | Description                                                                                                               |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `--level <level>` | Count only this level (case-insensitive).                                                                                 |
| `--last <range>`  | Only entries from this long ago. Units: `s`, `m`, `h`, `d` (`30m`, `24h`, `7d`). Entries without a timestamp are dropped. |
| `--format <fmt>`  | `table` (default) or `json` (`{ total, byLevel }`).                                                                       |

::: warning
`--format csv` is listed in the help text but is not implemented; it prints the table.
:::

### stats

```bash
logixia stats app.log
logixia stats app.log --group-by service
logixia stats app.log --format json
```

`--group-by <field>` (default `level`) chooses the field to count; `--format` is `pretty` (default, with percentages and bars) or `json` (`total`, `groupBy`, `distribution`, `timeRange`).

### search

```bash
logixia search app.log --query "user_id:123"
logixia search app.log --query "timeout" --format table
```

`--query` is required. `field:value` matches a field whose value contains `value`, case-insensitively; any other text is searched across the whole entry. `--format` is `line` (default), `table` (first four columns) or `json`.

Output starts with a `Found N matches` line, even with `--format json`, so piping to `jq` needs that line removed first, for example `| sed 1,2d | jq .`. The `--context` option is accepted but currently has no effect.

### query

`query` works on NDJSON or JSON files and understands a small SQL dialect.

```bash
logixia query app.log --sql "SELECT * FROM logs WHERE level='error' AND duration > 500"
logixia query app.log --sql "COUNT BY level"
logixia query app.log --sql "AVG(duration) BY endpoint"
logixia query app.log --since "last 2 hours" --format table
logixia query app.log --follow --sql "WHERE level='error'"
```

| Option               | Description                                    |
| -------------------- | ---------------------------------------------- |
| `--sql <query>`      | The query.                                     |
| `--since <time>`     | Only entries after this time.                  |
| `--until <time>`     | Only entries before this time.                 |
| `--limit <n>`        | Maximum results.                               |
| `--order-by <field>` | Sort by a field.                               |
| `--format <fmt>`     | `line` (default), `table`, `json` or `ndjson`. |
| `--follow`           | Keep watching the file and print new matches.  |

Time values accept `last N minutes|hours|days|weeks`, `today`, `yesterday` or an ISO date.

Supported SQL:

- `SELECT <fields|*> FROM logs WHERE ... ORDER BY <field> [ASC|DESC] LIMIT <n>`
- `WHERE` conditions with `=`, `!=`, `>`, `>=`, `<`, `<=`, `LIKE`, `NOT LIKE`, `IN` and `NOT IN`, combined with `AND` and `OR` (`AND` binds tighter)
- Shorthand aggregations: `COUNT BY <field>`, `GROUP BY <field>`, and `AVG|SUM|MIN|MAX(<field>) BY <field>`

### tail

```bash
logixia tail app.log
logixia tail app.log --follow --filter level:error
logixia tail app.log --follow --highlight level
```

Prints the last 10 lines that match the filter. `--follow` keeps watching the file. `--filter field:value` matches by substring; on non-JSON lines it matches the text. `--highlight` colors JSON lines by level (error red, warn yellow, info blue, debug gray); for plain-text lines it highlights the pattern as a literal string.

### export

```bash
logixia export app.log --format csv --fields "timestamp,level,message" --output logs.csv
logixia export app.log --format json
```

`--format` is `json` (default) or `csv`. Without `--fields`, CSV uses the keys of the first entry as columns. Without `--output` the result goes to stdout. CSV cells that start with `=`, `+`, `-`, `@` or a tab are prefixed with a quote so spreadsheets do not run them as formulas, and fields containing commas, quotes or line breaks are quoted.

### explore

```bash
logixia explore app.log --follow --levels error,warn --search timeout
```

An interactive terminal UI with a list, a detail pane, search, level filters and export. Options: `--follow`, `--levels <list>` and `--search <query>`.

| Key                     | Action                                                  |
| ----------------------- | ------------------------------------------------------- |
| `j` / `k`, arrows       | Move down and up                                        |
| `g` / `G`               | First and last entry                                    |
| PageUp / PageDown       | Page through the list                                   |
| `J` / `K`               | Scroll the detail pane                                  |
| `/`                     | Search (Enter applies, Esc clears)                      |
| `E` `W` `I` `D` `T` `V` | Toggle error, warn, info, debug, trace and verbose      |
| `f`                     | Toggle follow mode                                      |
| `x`                     | Export to a path ending in `.json`, `.csv` or `.ndjson` |
| `q`                     | Quit                                                    |

## Terminal safety

Log content is untrusted. The CLI replaces control characters (escape sequences, carriage returns and similar) with visible `\xNN` escapes before printing, so a crafted log line cannot rewrite your terminal.

## Examples

```bash
# Yesterday's errors, as JSON, with a count per level
logixia analyze yesterday.log --level error --format json

# Errors for one user as a table
logixia query app.log --sql "SELECT timestamp, message FROM logs WHERE level='error' AND user_id='123'" --format table

# Daily report
logixia stats production.log --format json > daily-report.json
```

## Developing the CLI

From a clone of the repository, `npm run cli:dev -- --help` runs it with `ts-node`, and `node dist/cli/index.js --help` runs the built version.
