// Test the core logic without chalk/UI dependencies
import { safeParseLogs, formatAsTable } from '../utils';

describe('CLI Utils', () => {
  const sampleLogs = `
{"timestamp":"2025-10-15T08:00:00.000Z","level":"info","message":"Test 1","user_id":"123"}
{"timestamp":"2025-10-15T08:01:00.000Z","level":"error","message":"Test 2","user_id":"456"}
{"timestamp":"2025-10-15T08:02:00.000Z","level":"warn","message":"Test 3","user_id":"123"}
`.trim();

  describe('safeParseLogs', () => {
    test('parses JSON-lines correctly', () => {
      const logs = safeParseLogs(sampleLogs);
      
      expect(logs).toHaveLength(3);
      expect(logs[0]).toHaveProperty('level', 'info');
      expect(logs[1]).toHaveProperty('level', 'error');
      expect(logs[2]).toHaveProperty('level', 'warn');
    });

    test('handles empty input', () => {
      const logs = safeParseLogs('');
      expect(logs).toHaveLength(0);
    });

    test('handles mixed JSON and plain text', () => {
      const mixed = '{"level":"info"}\nplain text\n{"level":"error"}';
      const logs = safeParseLogs(mixed);
      
      expect(logs).toHaveLength(3);
      expect(logs[0]).toHaveProperty('level', 'info');
      expect(logs[1]).toHaveProperty('message', 'plain text');
      expect(logs[2]).toHaveProperty('level', 'error');
    });
  });

  describe('formatAsTable', () => {
    test('formats data as table', () => {
      const data = [
        { name: 'Alice', age: 30 },
        { name: 'Bob', age: 25 }
      ];
      const table = formatAsTable(data, ['name', 'age']);
      
      expect(table).toContain('Alice');
      expect(table).toContain('Bob');
      expect(table).toContain('30');
      expect(table).toContain('25');
    });

    test('handles empty data', () => {
      const table = formatAsTable([], ['name', 'age']);
      expect(table).toBeTruthy();
    });
  });

  describe('log filtering', () => {
    test('filters by level', () => {
      const logs = safeParseLogs(sampleLogs);
      const errors = logs.filter((l: any) => l.level === 'error');
      
      expect(errors).toHaveLength(1);
      expect(errors[0].message).toBe('Test 2');
    });

    test('filters by user_id', () => {
      const logs = safeParseLogs(sampleLogs);
      const user123Logs = logs.filter((l: any) => l.user_id === '123');
      
      expect(user123Logs).toHaveLength(2);
    });

    test('searches across fields', () => {
      const logs = safeParseLogs(sampleLogs);
      const searchResults = logs.filter((l: any) => 
        JSON.stringify(l).toLowerCase().includes('test')
      );
      
      expect(searchResults).toHaveLength(3);
    });
  });

  describe('CSV export logic', () => {
    test('generates CSV header', () => {
      const logs = safeParseLogs(sampleLogs);
      const columns = Object.keys(logs[0] || {});
      
      expect(columns).toContain('timestamp');
      expect(columns).toContain('level');
      expect(columns).toContain('message');
    });

    test('extracts specific fields', () => {
      const logs = safeParseLogs(sampleLogs);
      const fields = ['level', 'message'];
      const extracted = logs.map((log: any) => {
        const obj: any = {};
        fields.forEach(f => { if (log[f]) obj[f] = log[f]; });
        return obj;
      });
      
      expect(extracted[0]).toHaveProperty('level');
      expect(extracted[0]).toHaveProperty('message');
      expect(extracted[0]).not.toHaveProperty('timestamp');
    });
  });
});
