/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */
import fs from 'node:fs';
import path from 'node:path';

import { Command } from 'commander';
import pc from 'picocolors';

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
  } catch {
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
    if (level === 'ERROR') return pc.red(line);
    if (level === 'WARN') return pc.yellow(line);
    if (level === 'INFO') return pc.blue(line);
    if (level === 'DEBUG') return pc.gray(line);

    return line;
  } catch {
    // Highlight pattern matches. picocolors doesn't chain like chalk did
    // (`chalk.bgYellow.black(...)`), so we nest the calls explicitly.
    const regex = new RegExp(highlight, 'gi');
    return line.replace(regex, (match) => pc.bgYellow(pc.black(match)));
  }
}

export const tailCommand = new Command('tail')
  .description('Follow log files in real-time')
  .argument('<file>', 'Path to log file')
  .option('--follow', 'Follow file changes', false)
  .option('--filter <filter>', 'Filter criteria (e.g., level:error, user_id:123)')
  .option('--highlight <pattern>', 'Highlight pattern or color by level')
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
    const filteredLines = lines.filter((line) => applyFilter(line, filterCriteria));
    const last = filteredLines.slice(-10);

    for (const line of last) {
      console.log(highlightLine(line, opts.highlight));
    }

    if (opts.follow) {
      console.log(pc.dim('--- following (ctrl-c to exit) ---'));
      let pos = fs.statSync(full).size;
      let buffer = '';

      fs.watchFile(full, { interval: 500 }, (curr) => {
        if (curr.size > pos) {
          const rs = fs.createReadStream(full, { start: pos, end: curr.size, encoding: 'utf8' });
          rs.on('data', (chunk) => {
            buffer += chunk;
            const lines = buffer.split(/\r?\n/);
            buffer = lines.pop() || '';

            for (const line of lines.filter(Boolean)) {
              if (applyFilter(line, filterCriteria)) {
                console.log(highlightLine(line, opts.highlight));
              }
            }
          });
          rs.on('end', () => {
            pos = curr.size;
          });
        }
      });
    }
  });
