import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { safeParseLogs, formatAsTable } from '../utils';

interface SearchCriteria {
  field?: string;
  value: string;
}

function parseQuery(query: string): SearchCriteria {
  const match = query.match(/^(\w+):(.+)$/);
  if (match) {
    return { field: match[1]!, value: match[2]! };
  }
  return { value: query };
}

export async function searchLogs(raw: string, opts: any = {}) {
  const entries = safeParseLogs(raw);
  const criteria = parseQuery(opts.query || '');
  
  const results = entries.filter((entry: any) => {
    if (criteria.field) {
      // Field-specific search
      const fieldValue = entry[criteria.field];
      if (fieldValue === undefined) return false;
      return fieldValue.toString().toLowerCase().includes(criteria.value.toLowerCase());
    } else {
      // Search across all fields
      const str = JSON.stringify(entry).toLowerCase();
      return str.includes(criteria.value.toLowerCase());
    }
  });

  return results;
}

function formatSearchResults(results: any[], format: string, context: number): string {
  if (format === 'json') {
    return JSON.stringify(results, null, 2);
  }
  
  if (format === 'table') {
    if (results.length === 0) return chalk.yellow('No results found');
    
    // Determine columns from first result
    const columns = Object.keys(results[0] || {});
    const displayColumns = columns.slice(0, 4); // Show first 4 columns
    
    return formatAsTable(results, displayColumns);
  }
  
  // Default: line format with context
  if (results.length === 0) return chalk.yellow('No results found');
  
  return results.map((r, idx) => {
    const line = JSON.stringify(r);
    return `${chalk.gray(`${idx + 1}:`)} ${line}`;
  }).join('\n');
}

export const searchCommand = new Command('search')
  .description('Search log files with query patterns')
  .argument('<file>', 'Path to log file')
  .option('--query <query>', 'Search query (e.g., "user_id:123" or "error")', '')
  .option('--format <fmt>', 'Output format (table, json, line)', 'line')
  .option('--context <lines>', 'Lines of context around matches', '0')
  .action(async (file: string, opts: any) => {
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      console.error(`File not found: ${full}`);
      process.exit(2);
    }

    if (!opts.query) {
      console.error('--query is required');
      process.exit(2);
    }

    const raw = fs.readFileSync(full, 'utf8');
    const results = await searchLogs(raw, opts);
    
    console.log(chalk.bold(`\nFound ${results.length} matches`));
    console.log(formatSearchResults(results, opts.format, parseInt(opts.context || '0')));
  });
