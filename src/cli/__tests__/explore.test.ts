import {
  buildDetailLines,
  coloriseStackFrame,
  formatTime,
  normalizeLevel,
  syntaxColorJson,
  TUIExplorer,
} from '../commands/explore';

// Strip ANSI colour codes so we can assert on plain text
// eslint-disable-next-line no-control-regex
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

// ── normalizeLevel ─────────────────────────────────────────────────────────────

describe('normalizeLevel', () => {
  test('returns string levels as-is (lowercased)', () => {
    expect(normalizeLevel('INFO')).toBe('info');
    expect(normalizeLevel('Error')).toBe('error');
    expect(normalizeLevel('warn')).toBe('warn');
  });

  test('maps numeric pino-style levels', () => {
    expect(normalizeLevel(50)).toBe('error');
    expect(normalizeLevel(40)).toBe('warn');
    expect(normalizeLevel(30)).toBe('info');
    expect(normalizeLevel(20)).toBe('debug');
    expect(normalizeLevel(10)).toBe('trace');
  });

  test('falls back to info for null/undefined', () => {
    expect(normalizeLevel()).toBe('info');
    expect(normalizeLevel(null)).toBe('info');
  });
});

// ── formatTime ────────────────────────────────────────────────────────────────

describe('formatTime', () => {
  test('formats a valid ISO timestamp to HH:MM:SS.mmm', () => {
    const result = formatTime('2025-10-15T08:05:03.042Z');
    expect(result).toMatch(/^\d{2}:\d{2}:\d{2}\.\d{3}$/);
  });

  test('returns padded empty string for missing timestamp', () => {
    expect(formatTime()).toBe('            ');
    expect(formatTime(null)).toBe('            ');
  });

  test('truncates and pads non-ISO strings', () => {
    const result = formatTime('not-a-date');
    expect(result.length).toBe(12);
  });
});

// ── syntaxColorJson ───────────────────────────────────────────────────────────

describe('syntaxColorJson', () => {
  test('strips ANSI and leaves structure intact', () => {
    const line = '  "level": "error",';
    const result = syntaxColorJson(line);
    expect(strip(result)).toBe(line);
  });

  test('preserves numeric values in output', () => {
    const line = '  "duration": 142,';
    const result = syntaxColorJson(line);
    // The plain-text content must be unchanged after stripping ANSI
    expect(strip(result)).toBe(line);
  });

  test('preserves boolean values in output', () => {
    const line = '  "active": true';
    const result = syntaxColorJson(line);
    expect(strip(result)).toBe(line);
  });

  test('handles null values', () => {
    const line = '  "value": null';
    const result = syntaxColorJson(line);
    expect(strip(result)).toBe(line);
  });
});

// ── coloriseStackFrame ────────────────────────────────────────────────────────

describe('coloriseStackFrame', () => {
  test('colourises a standard named-function frame', () => {
    const frame = '    at Object.<anonymous> (/app/server.ts:42:10)';
    const result = coloriseStackFrame(frame);
    expect(strip(result)).toContain('Object.<anonymous>');
    expect(strip(result)).toContain('/app/server.ts:42:10');
  });

  test('colourises a frame without parentheses', () => {
    const frame = '    at async bootstrap (/app/main.ts:5:3)';
    const result = coloriseStackFrame(frame);
    expect(strip(result)).toContain('bootstrap');
  });

  test('handles non-at lines gracefully', () => {
    const result = coloriseStackFrame('Error: something went wrong');
    expect(strip(result)).toContain('Error: something went wrong');
  });
});

// ── buildDetailLines ──────────────────────────────────────────────────────────

describe('buildDetailLines', () => {
  test('returns placeholder for undefined entry', () => {
    const lines = buildDetailLines();
    expect(lines).toHaveLength(1);
    expect(strip(lines[0]!)).toContain('No entry selected');
  });

  test('renders JSON fields of a basic entry', () => {
    const entry = { timestamp: '2025-10-15T08:00:00.000Z', level: 'info', message: 'hello' };
    const lines = buildDetailLines(entry);
    const plain = lines.map(strip).join('\n');
    expect(plain).toContain('"timestamp"');
    expect(plain).toContain('"level"');
    expect(plain).toContain('"message"');
    expect(plain).not.toContain('"stack"'); // stack not in rest fields
  });

  test('renders a STACK TRACE section for error entries with stack', () => {
    const entry = {
      level: 'error',
      message: 'boom',
      stack: 'Error: boom\n    at doThing (/app/index.ts:10:5)',
    };
    const lines = buildDetailLines(entry);
    const plain = lines.map(strip).join('\n');
    expect(plain).toContain('STACK TRACE');
    expect(plain).toContain('doThing');
  });

  test('does not render stack section when no stack field', () => {
    const entry = { level: 'info', message: 'ok' };
    const lines = buildDetailLines(entry);
    const plain = lines.map(strip).join('\n');
    expect(plain).not.toContain('STACK TRACE');
  });
});

// ── TUIExplorer.applyFilters ──────────────────────────────────────────────────
// These tests exercise the pure filtering logic without touching the TTY.

describe('TUIExplorer filter logic', () => {
  const ENTRIES = [
    {
      timestamp: '2025-10-15T08:00:00.000Z',
      level: 'error',
      message: 'Request failed',
      status: 500,
    },
    {
      timestamp: '2025-10-15T08:00:01.000Z',
      level: 'info',
      message: 'Request completed',
      status: 200,
    },
    { timestamp: '2025-10-15T08:00:02.000Z', level: 'warn', message: 'Slow query', duration: 1200 },
    { timestamp: '2025-10-15T08:00:03.000Z', level: 'debug', message: 'Cache hit', key: 'orders' },
  ];

  function makeExplorer(levels?: string, search?: string): TUIExplorer {
    // We use a dummy file path — applyFilters doesn't hit the FS
    const explorer = new TUIExplorer('/dev/null', { follow: false, levels, search });
    // Inject entries directly (bypasses fs.readFileSync in run())
    (explorer as any).allEntries = ENTRIES;
    explorer.applyFilters();
    return explorer;
  }

  test('shows all entries when no filter or search is set', () => {
    const e = makeExplorer();
    expect((e as any).filteredEntries).toHaveLength(4);
  });

  test('filters by level', () => {
    const e = makeExplorer('error,warn');
    const filtered = (e as any).filteredEntries as typeof ENTRIES;
    expect(filtered).toHaveLength(2);
    expect(filtered.every((x) => ['error', 'warn'].includes(x.level))).toBe(true);
  });

  test('filters by search query (message field)', () => {
    const e = makeExplorer(undefined, 'Slow');
    const filtered = (e as any).filteredEntries as typeof ENTRIES;
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.message).toBe('Slow query');
  });

  test('combines level filter + search', () => {
    const e = makeExplorer('warn,debug', 'query');
    const filtered = (e as any).filteredEntries as typeof ENTRIES;
    // 'Slow query' is warn, 'Cache hit' (key:orders) is debug — only warn matches 'query'
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.level).toBe('warn');
  });

  test('returns empty array when nothing matches', () => {
    const e = makeExplorer('error', 'completed');
    expect((e as any).filteredEntries).toHaveLength(0);
  });

  test('clamps selectedIndex when filteredEntries shrinks', () => {
    const e = makeExplorer();
    (e as any).selectedIndex = 3;
    (e as any).searchQuery = 'failed';
    e.applyFilters();
    expect((e as any).selectedIndex).toBe(0); // only 1 result, clamped to 0
  });
});
