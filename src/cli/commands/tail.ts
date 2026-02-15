import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { safeParseLogs } from '../utils';

function parseFilter(filter?: string): { field: string; value: string } | null {
  if (!filter) return null;
  const match = filter.match(/^(\w+):(.+)$/);
  if (!match) return null;
  return { field: match[1]!, value: match[2]! };
}

function applyFilter(line: string, filter: { field: string; value: string } | null): boolean {
  if (!filter) return true;
  
  try {
    const parsed = JSON.parse(line);
    const fieldValue = parsed[filter.field];
    if (fieldValue === undefined) return false;
    return fieldValue.toString().toLowerCase().includes(filter.value.toLowerCase());
  } catch (e) {
    // For non-JSON lines, check if the pattern exists
    return line.toLowerCase().includes(filter.value.toLowerCase());
  }
}

function highlightLine(line: string, highlight?: string): string {
  if (!highlight) return line;
  
  try {
    const parsed = JSON.parse(line);
    const level = (parsed.level || '').toUpperCase();
    
    // Color by level
    if (level === 'ERROR') return chalk.red(line);
    if (level === 'WARN') return chalk.yellow(line);
    if (level === 'INFO') return chalk.blue(line);
    if (level === 'DEBUG') return chalk.gray(line);
    
    return line;
  } catch (e) {
    // Highlight pattern matches
    const regex = new RegExp(highlight, 'gi');
    return line.replace(regex, (match) => chalk.bgYellow.black(match));
  }
}

export const tailCommand = new Command('tail')
  .description('Follow log files in real-time')
  .argument('<file>','Path to log file')
  .option('--follow','Follow file changes', false)
  .option('--filter <filter>','Filter criteria (e.g., level:error, user_id:123)')
  .option('--highlight <pattern>','Highlight pattern or color by level')
  .action(async (file: string, opts: any) => {
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      console.error(`File not found: ${full}`);
      process.exit(2);
    }

    const filterCriteria = parseFilter(opts.filter);

    // print last 10 lines
    const data = fs.readFileSync(full, 'utf8');
    const lines = data.split(/\r?\n/).filter(Boolean);
    const filteredLines = lines.filter(line => applyFilter(line, filterCriteria));
    const last = filteredLines.slice(-10);
    
    last.forEach(line => {
      console.log(highlightLine(line, opts.highlight));
    });

    if (opts.follow) {
      console.log(chalk.dim('--- following (ctrl-c to exit) ---'));
      let pos = fs.statSync(full).size;
      let buffer = '';

      fs.watchFile(full, { interval: 500 }, (curr) => {
        if (curr.size > pos) {
          const rs = fs.createReadStream(full, { start: pos, end: curr.size, encoding: 'utf8' });
          rs.on('data', chunk => {
            buffer += chunk;
            const lines = buffer.split(/\r?\n/);
            buffer = lines.pop() || '';
            
            lines.filter(Boolean).forEach(line => {
              if (applyFilter(line, filterCriteria)) {
                console.log(highlightLine(line, opts.highlight));
              }
            });
          });
          rs.on('end', () => { pos = curr.size; });
        }
      });
    }
  });