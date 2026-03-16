/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */
import fs from 'node:fs';
import path from 'node:path';

import chalk from 'chalk';
import { Command } from 'commander';

import { safeParseLogs } from '../utils';

// ── Types ──────────────────────────────────────────────────────────────────────

interface LogEntry {
  timestamp?: string;
  level?: string | number;
  message?: string;
  stack?: string;
  [key: string]: unknown;
}

// ── ANSI / terminal helpers ────────────────────────────────────────────────────

const CSI = '\x1b[';
const clearScreen = CSI + '2J';
const clearLine = CSI + 'K';
const hideCursor = CSI + '?25l';
const showCursor = CSI + '?25h';
const altScreen = CSI + '?1049h';
const mainScreen = CSI + '?1049l';

function moveTo(row: number, col: number): string {
  return `${CSI}${row};${col}H`;
}

function write(s: string): void {
  process.stdout.write(s);
}

// Strips ANSI color/style escape sequences from a string.
// eslint-disable-next-line no-control-regex
const ANSI_STRIP_RE = /\x1b\[[0-9;]*m/g;
function stripAnsi(s: string): string {
  return s.replace(ANSI_STRIP_RE, '');
}

// ── Level helpers ──────────────────────────────────────────────────────────────

export function normalizeLevel(level: unknown): string {
  if (typeof level === 'number') {
    if (level >= 50) return 'error';
    if (level >= 40) return 'warn';
    if (level >= 30) return 'info';
    if (level >= 20) return 'debug';
    return 'trace';
  }
  return String(level ?? 'info').toLowerCase();
}

function levelColor(level: string): (s: string) => string {
  switch (level) {
    case 'error': {
      return chalk.bgRed.white;
    }
    case 'warn': {
      return chalk.bgYellow.black;
    }
    case 'info': {
      return chalk.bgBlue.white;
    }
    case 'debug': {
      return chalk.bgGray.white;
    }
    case 'trace': {
      return chalk.bgMagenta.white;
    }
    case 'verbose': {
      return chalk.bgCyan.black;
    }
    default: {
      return chalk.bgGray.white;
    }
  }
}

const LEVEL_SHORT: Record<string, string> = {
  error: 'ERR',
  warn: 'WRN',
  info: 'INF',
  debug: 'DBG',
  trace: 'TRC',
  verbose: 'VRB',
};

function levelBadge(level: string): string {
  const label = ` ${(LEVEL_SHORT[level] ?? level.slice(0, 3).toUpperCase()).padEnd(3)} `;
  return levelColor(level)(label);
}

// ── Time formatting ────────────────────────────────────────────────────────────

export function formatTime(ts: unknown): string {
  if (!ts) return '            ';
  try {
    const d = new Date(String(ts));
    if (Number.isNaN(d.getTime())) return String(ts).slice(0, 12).padEnd(12);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${hh}:${mm}:${ss}.${ms}`;
  } catch {
    return String(ts).slice(0, 12).padEnd(12);
  }
}

// ── JSON syntax coloriser (no catastrophic-backtracking regexes) ──────────────

export function syntaxColorJson(line: string): string {
  // Color JSON keys  → cyan
  // Color string values → green
  // Color numeric values → yellow
  // Color booleans / null → magenta / dim
  return line
    .replace(/"([^"]+)":/g, (_, k: string) => chalk.cyan(`"${k}"`) + ':')
    .replace(/: "([^"]*)"/g, (_, v: string) => ': ' + chalk.green(`"${v}"`))
    .replace(/: (-?\d+(?:\.\d+)?)/g, (_, v: string) => ': ' + chalk.yellow(v))
    .replace(/: (true|false)/g, (_, v: string) => ': ' + chalk.magenta(v))
    .replace(/: null/g, ': ' + chalk.dim('null'));
}

// ── At-frame parser (no .+ capture groups → no slow-regex) ────────────────────

export function coloriseStackFrame(frame: string): string {
  const trimmed = frame.trim();
  if (!trimmed.startsWith('at ')) return chalk.dim('  ' + trimmed);

  const withoutAt = trimmed.slice(3); // drop leading "at "
  const parenOpen = withoutAt.lastIndexOf('(');
  const parenClose = withoutAt.lastIndexOf(')');

  if (parenOpen !== -1 && parenClose > parenOpen) {
    const name = withoutAt.slice(0, parenOpen).trimEnd();
    const loc = withoutAt.slice(parenOpen + 1, parenClose);
    return '    ' + chalk.dim('at ') + chalk.cyan(name) + ' ' + chalk.dim('(' + loc + ')');
  }

  return '    ' + chalk.dim('at ') + chalk.cyan(withoutAt);
}

// ── Detail lines builder ───────────────────────────────────────────────────────

export function buildDetailLines(entry: LogEntry | undefined): string[] {
  if (!entry) return [chalk.dim('  No entry selected')];

  const lines: string[] = [];

  // Pretty-print all fields except `stack` (handled separately below)
  const { stack, ...rest } = entry;
  const jsonText = JSON.stringify(rest, null, 2);
  for (const l of jsonText.split('\n')) {
    lines.push('  ' + syntaxColorJson(l));
  }

  // Stack trace section
  if (stack) {
    lines.push('');
    lines.push(chalk.bold.red('  ▼ STACK TRACE'));
    for (const sl of String(stack).split('\n')) {
      if (!sl.trim()) continue;
      if (sl.trim().startsWith('at ')) {
        lines.push(coloriseStackFrame(sl));
      } else {
        lines.push('  ' + chalk.red(sl.trim()));
      }
    }
  }

  return lines;
}

// ── TUI Explorer class ─────────────────────────────────────────────────────────

export class TUIExplorer {
  private allEntries: LogEntry[] = [];
  private filteredEntries: LogEntry[] = [];
  private selectedIndex = 0;
  private listScrollOffset = 0;
  private detailScrollOffset = 0;
  private searchQuery = '';
  private searchMode = false;
  private searchBuffer = '';
  private exportMode = false;
  private exportBuffer = '';
  private followMode: boolean;
  private levelFilters: Set<string>;
  private fileWatcher: fs.StatWatcher | undefined;
  private filePath: string;
  private filePos = 0;
  private width = 80;
  private height = 24;

  // Layout constants
  private readonly HEADER_ROWS = 3; // title bar + filter bar + col header
  private readonly STATUS_ROWS = 1; // key-bindings bar
  private readonly DETAIL_ROWS = 9; // 1 separator + 8 content lines

  private get LIST_ROWS(): number {
    return Math.max(4, this.height - this.HEADER_ROWS - this.STATUS_ROWS - this.DETAIL_ROWS);
  }

  constructor(
    filePath: string,
    private readonly opts: { follow: boolean; levels?: string; search?: string }
  ) {
    this.filePath = path.resolve(process.cwd(), filePath);
    this.levelFilters = new Set(['error', 'warn', 'info', 'debug', 'trace', 'verbose']);
    if (opts.levels) {
      this.levelFilters = new Set(
        opts.levels
          .split(',')
          .map((l) => l.trim().toLowerCase())
          .filter(Boolean)
      );
    }
    if (opts.search) this.searchQuery = opts.search;
    this.followMode = opts.follow;
  }

  run(): void {
    if (!fs.existsSync(this.filePath)) {
      console.error(chalk.red(`File not found: ${this.filePath}`));
      process.exit(2);
    }

    const raw = fs.readFileSync(this.filePath, 'utf8');
    this.filePos = fs.statSync(this.filePath).size;
    this.allEntries = safeParseLogs(raw) as LogEntry[];
    this.applyFilters();

    // Enter alternate screen and hide cursor
    write(altScreen + hideCursor);
    this.getTerminalSize();

    process.stdout.on('resize', () => {
      this.getTerminalSize();
      this.redraw();
    });

    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', (buf: Buffer) => {
      this.handleKey(buf);
    });

    if (this.followMode) this.startFollow();

    this.redraw();
  }

  private getTerminalSize(): void {
    this.width = process.stdout.columns || 80;
    this.height = process.stdout.rows || 24;
  }

  // ── Filtering ──────────────────────────────────────────────────────────────

  applyFilters(): void {
    this.filteredEntries = this.allEntries.filter((entry) => {
      const lvl = normalizeLevel(entry.level);
      if (!this.levelFilters.has(lvl)) return false;
      if (this.searchQuery) {
        const haystack = JSON.stringify(entry).toLowerCase();
        if (!haystack.includes(this.searchQuery.toLowerCase())) return false;
      }
      return true;
    });
    if (this.selectedIndex >= this.filteredEntries.length) {
      this.selectedIndex = Math.max(0, this.filteredEntries.length - 1);
    }
    this.clampScroll();
  }

  private clampScroll(): void {
    const lr = this.LIST_ROWS;
    if (this.selectedIndex < this.listScrollOffset) {
      this.listScrollOffset = this.selectedIndex;
    }
    if (this.selectedIndex >= this.listScrollOffset + lr) {
      this.listScrollOffset = this.selectedIndex - lr + 1;
    }
    this.listScrollOffset = Math.max(0, this.listScrollOffset);
  }

  // ── Rendering ──────────────────────────────────────────────────────────────

  private redraw(): void {
    write(clearScreen + moveTo(1, 1));
    this.drawHeader();
    this.drawFilterBar();
    this.drawColHeader();
    this.drawList();
    this.drawDetailPanel();
    this.drawStatusBar();
  }

  private pad(s: string, len: number): string {
    if (s.length >= len) return s.slice(0, len);
    return s + ' '.repeat(len - s.length);
  }

  private truncate(s: string, len: number): string {
    if (len <= 0) return '';
    if (s.length <= len) return s;
    return s.slice(0, len - 1) + '…';
  }

  private drawHeader(): void {
    const w = this.width;
    const title = chalk.bgWhite.black.bold(' LOGIXIA EXPLORE ');
    const fname = chalk.cyan(` ${path.basename(this.filePath)} `);
    const count = chalk.dim(`[${this.filteredEntries.length}/${this.allEntries.length}]`);
    const follow = this.followMode ? chalk.green(' ⟳ FOLLOW') : '';
    const search = this.searchQuery ? chalk.yellow(` /${this.searchQuery}`) : '';

    const left = ` ${title}${fname}`;
    const right = count + follow + search + ' ';
    const leftLen = stripAnsi(left).length;
    const rightLen = stripAnsi(right).length;
    const gap = Math.max(1, w - leftLen - rightLen);

    write(moveTo(1, 1) + chalk.bgBlack(left + ' '.repeat(gap) + right) + clearLine + '\n');
  }

  private drawFilterBar(): void {
    const LEVELS: Array<[string, string]> = [
      ['error', 'E'],
      ['warn', 'W'],
      ['info', 'I'],
      ['debug', 'D'],
      ['trace', 'T'],
      ['verbose', 'V'],
    ];

    const badges = LEVELS.map(([lvl, key]) => {
      const active = this.levelFilters.has(lvl);
      return active ? levelColor(lvl)(` ${key} `) : chalk.dim.strikethrough(` ${key} `);
    }).join(' ');

    const searchPart = this.searchMode
      ? chalk.bgYellow.black(` /${this.searchBuffer}█ `)
      : chalk.dim('  /: search ');

    const w = this.width;
    const left = '  ' + badges;
    const right = searchPart + ' ';
    const gap = Math.max(1, w - stripAnsi(left).length - stripAnsi(right).length);
    write(moveTo(2, 1) + chalk.bgBlack(left + ' '.repeat(gap) + right) + clearLine + '\n');
  }

  private drawColHeader(): void {
    const w = this.width;
    const timeCol = ' TIME         ';
    const levelCol = ' LVL ';
    const msgWidth = Math.max(20, w - timeCol.length - levelCol.length - 2);
    write(
      moveTo(3, 1) +
        chalk.bold.bgBlack.dim(timeCol + levelCol + ' ' + this.pad('MESSAGE', msgWidth)) +
        clearLine +
        '\n'
    );
  }

  private drawList(): void {
    const lr = this.LIST_ROWS;
    const w = this.width;
    const timeW = 13;
    const levelW = 5;
    const msgWidth = Math.max(10, w - timeW - levelW - 3);

    for (let row = 0; row < lr; row++) {
      const entryIdx = this.listScrollOffset + row;
      const screenRow = this.HEADER_ROWS + row + 1;
      write(moveTo(screenRow, 1));

      if (entryIdx >= this.filteredEntries.length) {
        write(chalk.bgBlack(' '.repeat(w)) + clearLine);
        continue;
      }

      const entry = this.filteredEntries[entryIdx]!;
      const isSelected = entryIdx === this.selectedIndex;
      const level = normalizeLevel(entry.level);
      const time = formatTime(entry.timestamp);
      const msg = String(entry.message ?? '');

      // Compact summary of extra fields
      const extraFields = Object.entries(entry)
        .filter(([k]) => !['timestamp', 'level', 'message', 'stack'].includes(k))
        .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
        .join(' ');

      const msgSlot = Math.floor(msgWidth * 0.65);
      const msgPart = this.truncate(msg, msgSlot);
      const extraPart = this.truncate(extraFields, msgWidth - msgPart.length - 2);
      const msgDisplay = msgPart + (extraPart ? chalk.dim('  ' + extraPart) : '');

      const line = ` ${time} ` + levelBadge(level) + ' ' + this.pad(msgDisplay, msgWidth);

      if (isSelected) {
        const plain = this.pad(stripAnsi(line), w);
        write(chalk.bgWhite.black(plain));
      } else if (this.searchQuery) {
        write(this.highlightSearch(this.truncate(line, w)));
      } else {
        write(this.truncate(line, w));
      }
      write(clearLine);
    }
  }

  private drawDetailPanel(): void {
    const w = this.width;
    const sepRow = this.HEADER_ROWS + this.LIST_ROWS + 1;
    const selected = this.filteredEntries[this.selectedIndex];

    // Separator with label
    const label = selected
      ? ` ▼ DETAIL  (${this.selectedIndex + 1}/${this.filteredEntries.length}) `
      : ' ▼ DETAIL ';
    const labelLen = stripAnsi(label).length;
    const sepLine =
      chalk.bgBlack.cyan.bold(label) + chalk.dim('─'.repeat(Math.max(0, w - labelLen)));
    write(moveTo(sepRow, 1) + sepLine + clearLine + '\n');

    // 8 detail content lines
    const lines = buildDetailLines(selected);
    for (let row = 0; row < 8; row++) {
      const screenRow = sepRow + 1 + row;
      write(moveTo(screenRow, 1));
      const lineIdx = this.detailScrollOffset + row;
      if (lineIdx < lines.length) {
        write(this.truncate(lines[lineIdx]!, w) + clearLine);
      } else {
        write(chalk.bgBlack(' '.repeat(w)) + clearLine);
      }
    }
  }

  private drawStatusBar(): void {
    const statusRow = this.height;
    const keys = [
      chalk.bold('j/k') + ' move',
      chalk.bold('/') + ' search',
      chalk.bold('x') + ' export',
      chalk.bold('E/W/I/D/T/V') + ' filter',
      chalk.bold('J/K') + ' detail↕',
      chalk.bold('f') + ' follow',
      chalk.bold('g/G') + ' top/bot',
      chalk.bold('q') + ' quit',
    ];
    const bar = '  ' + keys.join(chalk.dim('  │  '));
    write(moveTo(statusRow, 1) + chalk.bgBlack.dim(this.truncate(bar, this.width)) + clearLine);

    // Export prompt overlay
    if (this.exportMode) {
      const promptRow = this.height - 1;
      const prompt = chalk.bgYellow.black(
        ` Export path (.json/.csv/.ndjson, blank=cancel): ${this.exportBuffer}█ `
      );
      write(moveTo(promptRow, 1) + prompt + clearLine);
    }
  }

  // ── Key handling ───────────────────────────────────────────────────────────

  private handleKey(buf: Buffer): void {
    const key = buf.toString('utf8');

    // Ctrl+C always quits
    if (key === '\x03') {
      this.cleanup();
      return;
    }

    if (this.exportMode) {
      this.handleExportKey(key);
      return;
    }
    if (this.searchMode) {
      this.handleSearchKey(key);
      return;
    }

    switch (key) {
      // Navigation
      case 'j':
      case '\x1b[B': {
        this.moveSelection(1);
        break;
      }
      case 'k':
      case '\x1b[A': {
        this.moveSelection(-1);
        break;
      }
      case 'g':
      case '\x1b[1~': {
        this.selectedIndex = 0;
        this.listScrollOffset = 0;
        this.detailScrollOffset = 0;
        break;
      }
      case 'G':
      case '\x1b[4~': {
        this.selectedIndex = Math.max(0, this.filteredEntries.length - 1);
        this.clampScroll();
        this.detailScrollOffset = 0;
        break;
      }
      case '\x1b[5~': {
        this.moveSelection(-this.LIST_ROWS);
        break;
      } // PgUp
      case '\x1b[6~': {
        this.moveSelection(this.LIST_ROWS);
        break;
      } // PgDn

      // Detail scroll
      case 'J': {
        this.detailScrollOffset++;
        break;
      }
      case 'K': {
        this.detailScrollOffset = Math.max(0, this.detailScrollOffset - 1);
        break;
      }

      // Search
      case '/': {
        this.searchMode = true;
        this.searchBuffer = this.searchQuery;
        break;
      }

      // Level filters
      case 'E': {
        this.toggleLevel('error');
        break;
      }
      case 'W': {
        this.toggleLevel('warn');
        break;
      }
      case 'I': {
        this.toggleLevel('info');
        break;
      }
      case 'D': {
        this.toggleLevel('debug');
        break;
      }
      case 'T': {
        this.toggleLevel('trace');
        break;
      }
      case 'V': {
        this.toggleLevel('verbose');
        break;
      }

      // Follow mode
      case 'f': {
        this.followMode = !this.followMode;
        if (this.followMode) {
          this.startFollow();
        } else {
          fs.unwatchFile(this.filePath);
          this.fileWatcher = undefined;
        }
        break;
      }

      // Export
      case 'x': {
        this.exportMode = true;
        this.exportBuffer = '';
        break;
      }

      // Quit
      case 'q': {
        this.cleanup();
        return;
      }

      default:
        break;
    }
    this.redraw();
  }

  private handleSearchKey(key: string): void {
    if (key === '\r' || key === '\n') {
      this.searchQuery = this.searchBuffer;
      this.searchMode = false;
      this.applyFilters();
    } else if (key === '\x1b' || key === '\x1b\x1b') {
      this.searchMode = false;
      this.searchBuffer = '';
      this.searchQuery = '';
      this.applyFilters();
    } else if (key === '\x7f' || key === '\b') {
      this.searchBuffer = this.searchBuffer.slice(0, -1);
    } else if (key.length === 1 && key >= ' ') {
      this.searchBuffer += key;
    }
    this.redraw();
  }

  private handleExportKey(key: string): void {
    if (key === '\r' || key === '\n') {
      this.exportMode = false;
      if (this.exportBuffer.trim()) this.doExport(this.exportBuffer.trim());
      this.redraw();
    } else if (key === '\x1b') {
      this.exportMode = false;
      this.exportBuffer = '';
      this.redraw();
    } else if (key === '\x7f' || key === '\b') {
      this.exportBuffer = this.exportBuffer.slice(0, -1);
      this.redraw();
    } else if (key.length === 1 && key >= ' ') {
      this.exportBuffer += key;
      this.redraw();
    }
  }

  // ── Export ─────────────────────────────────────────────────────────────────

  private doExport(outPath: string): void {
    const resolved = path.resolve(process.cwd(), outPath);
    const ext = path.extname(outPath).toLowerCase();
    try {
      if (ext === '.csv') {
        const entries = this.filteredEntries;
        const allKeys = [...new Set(entries.flatMap((e) => Object.keys(e)))];
        const header = allKeys.join(',');
        const rows = entries.map((e) =>
          allKeys
            .map((k) => {
              const v = e[k];
              const s = typeof v === 'string' ? v : JSON.stringify(v ?? '');
              return `"${s.replace(/"/g, '""')}"`;
            })
            .join(',')
        );
        fs.writeFileSync(resolved, [header, ...rows].join('\n'), 'utf8');
      } else if (ext === '.ndjson' || ext === '.jsonl') {
        fs.writeFileSync(
          resolved,
          this.filteredEntries.map((e) => JSON.stringify(e)).join('\n'),
          'utf8'
        );
      } else {
        // Default: JSON array
        fs.writeFileSync(resolved, JSON.stringify(this.filteredEntries, null, 2), 'utf8');
      }

      const confirmRow = this.height - 1;
      write(
        moveTo(confirmRow, 1) +
          chalk.bgGreen.black(` ✓ Exported ${this.filteredEntries.length} entries → ${resolved} `) +
          clearLine
      );
      setTimeout(() => {
        this.redraw();
      }, 2000);
    } catch (err: any) {
      const errRow = this.height - 1;
      write(
        moveTo(errRow, 1) +
          chalk.bgRed.white(` ✗ Export failed: ${String(err.message)} `) +
          clearLine
      );
      setTimeout(() => {
        this.redraw();
      }, 2000);
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private moveSelection(delta: number): void {
    const max = Math.max(0, this.filteredEntries.length - 1);
    this.selectedIndex = Math.max(0, Math.min(max, this.selectedIndex + delta));
    this.detailScrollOffset = 0;
    this.clampScroll();
  }

  private toggleLevel(level: string): void {
    if (this.levelFilters.has(level)) {
      if (this.levelFilters.size > 1) this.levelFilters.delete(level);
    } else {
      this.levelFilters.add(level);
    }
    this.applyFilters();
  }

  private startFollow(): void {
    this.fileWatcher = fs.watchFile(this.filePath, { interval: 500 }, (curr) => {
      if (curr.size <= this.filePos) return;
      try {
        const rs = fs.createReadStream(this.filePath, {
          start: this.filePos,
          end: curr.size,
          encoding: 'utf8',
        });
        let buf = '';
        rs.on('data', (chunk: string | Buffer) => {
          buf += String(chunk);
        });
        rs.on('end', () => {
          this.filePos = curr.size;
          const newEntries = safeParseLogs(buf) as LogEntry[];
          this.allEntries.push(...newEntries);
          this.applyFilters();
          this.selectedIndex = Math.max(0, this.filteredEntries.length - 1);
          this.clampScroll();
          this.redraw();
        });
      } catch {
        /* ignore fs errors during follow */
      }
    });
  }

  private highlightSearch(line: string): string {
    if (!this.searchQuery) return line;
    const plain = stripAnsi(line);
    const lower = plain.toLowerCase();
    const needle = this.searchQuery.toLowerCase();
    let result = '';
    let i = 0;
    while (i < plain.length) {
      const idx = lower.indexOf(needle, i);
      if (idx === -1) {
        result += plain.slice(i);
        break;
      }
      result += plain.slice(i, idx) + chalk.bgYellow.black(plain.slice(idx, idx + needle.length));
      i = idx + needle.length;
    }
    return result;
  }

  cleanup(): void {
    if (this.fileWatcher) fs.unwatchFile(this.filePath);
    write(showCursor + mainScreen);
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
    process.stdin.pause();
    process.exit(0);
  }
}

// ── Commander command ──────────────────────────────────────────────────────────

export const exploreCommand = new Command('explore')
  .description('Interactive TUI log explorer with real-time search, level filters, and export')
  .argument('<file>', 'Path to log file (NDJSON / JSON-lines)')
  .option('--follow', 'Follow file changes in real-time', false)
  .option('--levels <levels>', 'Comma-separated levels to show (e.g. error,warn,info)', '')
  .option('--search <query>', 'Pre-populate the search field', '')
  .action((file: string, opts: any) => {
    const explorer = new TUIExplorer(file, {
      follow: Boolean(opts.follow),
      levels: String(opts.levels ?? ''),
      search: String(opts.search ?? ''),
    });
    explorer.run();
  });
