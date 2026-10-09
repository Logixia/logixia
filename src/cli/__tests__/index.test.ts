/**
 * The bin is started through npm's node_modules/.bin symlink, so the
 * "is this file being run directly" check has to compare real paths.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { isDirectRun } from '../index';

describe('isDirectRun', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-cli-'));
    file = path.join(dir, 'index.js');
    fs.writeFileSync(file, '');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('is true when run by its own path', () => {
    expect(isDirectRun(file, file)).toBe(true);
  });

  it('is true when run through a symlink, like node_modules/.bin/logixia', () => {
    const link = path.join(dir, 'logixia');
    fs.symlinkSync(file, link);
    expect(isDirectRun(link, file)).toBe(true);
  });

  it('is false for another script or no argv', () => {
    const other = path.join(dir, 'other.js');
    fs.writeFileSync(other, '');
    expect(isDirectRun(other, file)).toBe(false);
    expect(isDirectRun(undefined, file)).toBe(false);
    expect(isDirectRun(path.join(dir, 'missing.js'), file)).toBe(false);
  });
});
