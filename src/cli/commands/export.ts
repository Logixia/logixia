import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import { safeParseLogs } from '../utils';

export async function exportLogs(raw: string, opts: any = {}) {
  const entries = safeParseLogs(raw);
  const fields = opts.fields ? opts.fields.split(',').map((f: string) => f.trim()) : null;
  
  if (opts.format === 'csv') {
    return exportAsCSV(entries, fields);
  } else if (opts.format === 'json') {
    return exportAsJSON(entries, fields);
  }
  
  return JSON.stringify(entries, null, 2);
}

function exportAsCSV(entries: any[], fields: string[] | null): string {
  if (entries.length === 0) return '';
  
  // Use specified fields or all fields from first entry
  const columns = fields || Object.keys(entries[0] || {});
  
  const lines: string[] = [];
  
  // Header
  lines.push(columns.join(','));
  
  // Rows
  for (const entry of entries) {
    const row = columns.map(col => {
      const value = entry[col];
      if (value === undefined || value === null) return '';
      
      // Escape CSV values
      const str = String(value);
      if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    });
    lines.push(row.join(','));
  }
  
  return lines.join('\n');
}

function exportAsJSON(entries: any[], fields: string[] | null): string {
  if (!fields) {
    return JSON.stringify(entries, null, 2);
  }
  
  // Filter to only specified fields
  const filtered = entries.map(entry => {
    const obj: any = {};
    for (const field of fields) {
      if (entry[field] !== undefined) {
        obj[field] = entry[field];
      }
    }
    return obj;
  });
  
  return JSON.stringify(filtered, null, 2);
}

export const exportCommand = new Command('export')
  .description('Export log files to different formats')
  .argument('<file>', 'Path to log file')
  .option('--format <fmt>', 'Output format (csv, json)', 'json')
  .option('--fields <fields>', 'Comma-separated list of fields to export (e.g., timestamp,level,message)')
  .option('--output <file>', 'Output file path (default: stdout)')
  .action(async (file: string, opts: any) => {
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      console.error(`File not found: ${full}`);
      process.exit(2);
    }

    const raw = fs.readFileSync(full, 'utf8');
    const output = await exportLogs(raw, opts);
    
    if (opts.output) {
      const outPath = path.resolve(process.cwd(), opts.output);
      fs.writeFileSync(outPath, output, 'utf8');
      console.log(`Exported to: ${outPath}`);
    } else {
      console.log(output);
    }
  });
