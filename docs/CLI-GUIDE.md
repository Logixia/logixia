# Logixia CLI - Quick Reference Guide

The Logixia CLI provides powerful command-line tools for log management, analysis, and monitoring.

## Installation

```bash
# Global installation
npm install -g logixia

# Or use with npx
npx logixia --help
```

## Commands

### analyze - Analyze log patterns and statistics

```bash
# Basic analysis
logixia analyze app.log

# Filter by level
logixia analyze app.log --level error

# Time-based filtering
logixia analyze app.log --last 24h
logixia analyze app.log --last 7d

# JSON output
logixia analyze app.log --format json
```

### stats - Detailed log statistics

```bash
# Pretty formatted statistics
logixia stats app.log

# Group by custom field
logixia stats app.log --group-by service

# JSON output
logixia stats app.log --format json
```

### search - Search logs with queries

```bash
# Search by field
logixia search app.log --query "user_id:123"
logixia search app.log --query "level:error"

# Search all fields
logixia search app.log --query "database"

# Different output formats
logixia search app.log --query "user_id:123" --format table
logixia search app.log --query "error" --format json
```

### export - Export logs to different formats

```bash
# Export to CSV
logixia export app.log --format csv --output logs.csv

# Export specific fields
logixia export app.log --format csv --fields "timestamp,level,message"

# Export to JSON
logixia export app.log --format json --output logs.json

# Print to stdout
logixia export app.log --format csv
```

### tail - Monitor logs in real-time

```bash
# View last 10 lines
logixia tail app.log

# Follow mode (like tail -f)
logixia tail app.log --follow

# Filter while following
logixia tail app.log --follow --filter level:error
logixia tail app.log --follow --filter user_id:123

# Highlight patterns
logixia tail app.log --follow --highlight level
```

## Common Workflows

### Morning Log Review

```bash
# Check yesterday's errors
logixia analyze yesterday.log --level error

# Get statistics
logixia stats yesterday.log

# Find specific issues
logixia search yesterday.log --query "timeout" --format table
```

### Development Debugging

```bash
# Follow logs for specific user
logixia tail debug.log --follow --filter user_id:123 --highlight level

# Search for stack traces
logixia search debug.log --query "stack"

# Export errors to CSV for analysis
logixia search debug.log --query "level:error" | logixia export - --format csv
```

### Production Monitoring

```bash
# Monitor errors in real-time
logixia tail production.log --follow --filter level:error

# Analyze error patterns (last 24 hours)
logixia analyze production.log --level error --last 24h

# Generate daily report
logixia stats production.log --format json > daily-report.json
```

### Data Export & Analysis

```bash
# Export to CSV for spreadsheet analysis
logixia export app.log --format csv --fields "timestamp,level,user_id,message" --output export.csv

# Export errors only
logixia search app.log --query "level:error" --format json > errors.json

# Extract specific user activity
logixia search app.log --query "user_id:456" --format table
```

## Query Syntax

### Field-based queries
- `field:value` - Search specific field
- Examples:
  - `user_id:123` - Find logs for user 123
  - `level:error` - Find all errors
  - `service:api` - Find logs from API service

### Full-text queries
- Any text without `:` searches across all fields
- Case-insensitive by default
- Examples:
  - `database` - Find logs mentioning "database"
  - `timeout` - Find timeout-related logs

## Time Range Format

- `24h` - Last 24 hours
- `7d` - Last 7 days
- `30m` - Last 30 minutes
- `1h` - Last 1 hour

## Output Formats

- `table` - Human-readable table (default for analyze/search)
- `json` - JSON format for scripting
- `csv` - CSV format for spreadsheets
- `pretty` - Colored, formatted output (stats default)

## Tips & Tricks

1. **Pipe commands together:**
   ```bash
   logixia search app.log --query "error" --format json | jq '.[] | .message'
   ```

2. **Watch live with filters:**
   ```bash
   logixia tail app.log --follow --filter level:error --highlight level
   ```

3. **Export for external analysis:**
   ```bash
   logixia export app.log --format csv --output /tmp/logs.csv
   open /tmp/logs.csv  # Opens in Excel/Numbers
   ```

4. **Test with sample data:**
   ```bash
   logixia analyze examples/sample.log
   logixia stats examples/sample.log
   ```

5. **Quick error summary:**
   ```bash
   logixia analyze app.log --level error --format json | jq '.byLevel'
   ```

## Sample Log File

Try the CLI with the included sample:

```bash
logixia analyze examples/sample.log
logixia stats examples/sample.log
logixia search examples/sample.log --query "user_id:123" --format table
```

## Development

```bash
# Run in dev mode
npm run cli:dev -- --help

# Build CLI
npm run cli:build

# Test compiled version
node dist/cli/index.js --help
```

## Need Help?

- Run any command with `--help` for detailed options
- Check [CONTRIBUTING.md](../CONTRIBUTING.md) for development guide
- See [README.md](../README.md) for full documentation
