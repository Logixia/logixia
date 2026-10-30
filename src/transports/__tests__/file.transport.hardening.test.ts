import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { gunzipSync } from 'node:zlib';

import type { TransportLogEntry } from '../../types/transport.types';
import { FileTransport } from '../file.transport';

function makeEntry(overrides: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'error',
    message: 'real',
    ...overrides,
  };
}

const mode = (p: string): number => fs.statSync(p).mode & 0o777;

describe('FileTransport hardening', () => {
  let dir: string;

  beforeEach(() => {
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    dir = fs.mkdtempSync(path.join(tmpdir(), 'logixia-file-hardening-'));
  });

  afterEach(() => {
    delete process.env.LOGIXIA_SILENT_INTERNAL;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const read = (name: string): string => fs.readFileSync(path.join(dir, name), 'utf8');

  describe('core fields', () => {
    it('keeps level, message and timestamp authoritative in json', async () => {
      const t = new FileTransport({
        filename: 'a.log',
        dirname: dir,
        format: 'json',
        batchSize: 1,
      });
      await t.write(
        makeEntry({
          data: {
            level: 'debug',
            message: 'nothing',
            timestamp: '2020-01-01T00:00:00.000Z',
            user: 'x',
          },
        })
      );
      await t.close();
      expect(JSON.parse(read('a.log'))).toEqual({
        timestamp: '2026-01-01T00:00:00.000Z',
        level: 'error',
        message: 'real',
        data_level: 'debug',
        data_message: 'nothing',
        data_timestamp: '2020-01-01T00:00:00.000Z',
        user: 'x',
      });
    });
  });

  describe('text format', () => {
    it('escapes CR, LF, ESC and other control characters', async () => {
      const t = new FileTransport({
        filename: 't.log',
        dirname: dir,
        format: 'text',
        batchSize: 1,
      });
      await t.write(
        makeEntry({ message: 'ok\n2026-01-01T00:00:00.000Z [ERROR] forged\r\x1b[31m\x00' })
      );
      await t.close();
      const lines = read('t.log').split('\n').filter(Boolean);
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('ok\\n2026-01-01T00:00:00.000Z [ERROR] forged\\r[31m');
      for (const c of ['\r', '\x1b', '\x00']) expect(read('t.log')).not.toContain(c);
    });

    it('escapes control characters in a custom level', async () => {
      const t = new FileTransport({
        filename: 't.log',
        dirname: dir,
        format: 'text',
        batchSize: 1,
      });
      await t.write(makeEntry({ level: 'we\nird' }));
      await t.close();
      expect(read('t.log').split('\n').filter(Boolean)).toHaveLength(1);
    });
  });

  describe('csv format', () => {
    it('quotes every text field and keeps one row per entry', async () => {
      const t = new FileTransport({ filename: 'c.csv', dirname: dir, format: 'csv', batchSize: 1 });
      await t.write(
        makeEntry({
          message: 'a,"b"\r\nc',
          context: 'ctx,1\n2',
          traceId: 'tr\race',
          data: { k: 'v,1' },
        })
      );
      await t.close();
      const content = read('c.csv');
      expect(content.split('\n').filter(Boolean)).toHaveLength(1);
      expect(content).not.toContain('\r');
      expect(content.trimEnd()).toBe(
        '2026-01-01T00:00:00.000Z,"error","a,""b""\\r\\nc","ctx,1\\n2","tr\\race","{""k"":""v,1""}"'
      );
    });

    it('emits empty quoted fields for a missing context and trace id', async () => {
      const t = new FileTransport({ filename: 'c.csv', dirname: dir, format: 'csv', batchSize: 1 });
      await t.write(makeEntry());
      await t.close();
      expect(read('c.csv').trimEnd()).toBe('2026-01-01T00:00:00.000Z,"error","real","","","{}"');
    });
  });

  describe('maxQueue default', () => {
    it('bounds the in-memory queue at 10000 entries by default', async () => {
      const t = new FileTransport({
        filename: 'q.log',
        dirname: dir,
        batchSize: 1_000_000,
        flushInterval: 600_000,
      });
      for (let i = 0; i < 10_050; i += 1) t.addToBatch(makeEntry({ message: `m${i}` }));
      const internals = t as unknown as { batch: TransportLogEntry[]; inFlight: number };
      expect(internals.batch.length + internals.inFlight).toBe(10_000);
      await t.close();
    });

    it('still honours an explicit maxQueue', async () => {
      const t = new FileTransport({
        filename: 'q.log',
        dirname: dir,
        batchSize: 1_000_000,
        flushInterval: 600_000,
        maxQueue: 5,
      });
      for (let i = 0; i < 12; i += 1) t.addToBatch(makeEntry({ message: `m${i}` }));
      const q = t as unknown as { batch: unknown[]; inFlight: number };
      expect(q.batch.length + q.inFlight).toBe(5);
      await t.close();
    });
  });

  describe('permissions', () => {
    it('creates log files as 0600 and new directories as 0700', async () => {
      const sub = path.join(dir, 'nested', 'logs');
      const t = new FileTransport({ filename: 'p.log', dirname: sub, batchSize: 1 });
      await t.write(makeEntry());
      await t.close();
      expect(mode(path.join(sub, 'p.log'))).toBe(0o600);
      expect(mode(sub)).toBe(0o700);
    });

    it('honours fileMode and dirMode', async () => {
      const sub = path.join(dir, 'custom');
      const t = new FileTransport({
        filename: 'p.log',
        dirname: sub,
        batchSize: 1,
        fileMode: 0o640,
        dirMode: 0o750,
      });
      await t.write(makeEntry());
      await t.close();
      expect(mode(path.join(sub, 'p.log'))).toBe(0o640);
      expect(mode(sub)).toBe(0o750);
    });

    it('keeps rotated and gzipped files private', async () => {
      const t = new FileTransport({
        filename: 'r.log',
        dirname: dir,
        batchSize: 1,
        maxSize: 200,
        zippedArchive: true,
      });
      for (let i = 0; i < 6; i += 1)
        await t.write(makeEntry({ message: `rotate-me-${i}-${'x'.repeat(60)}` }));
      await t.close();
      const files = fs.readdirSync(dir);
      const gz = files.filter((f) => f.endsWith('.gz'));
      expect(gz.length).toBeGreaterThan(0);
      for (const f of files) expect(mode(path.join(dir, f))).toBe(0o600);
      expect(gunzipSync(fs.readFileSync(path.join(dir, gz[0] as string))).toString()).toContain(
        'rotate-me-0'
      );
    });
  });
});
