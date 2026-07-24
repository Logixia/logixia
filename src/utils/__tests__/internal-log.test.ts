/**
 * Tests for the internal logging helpers.
 *
 * Regression: the silence flag was captured once at module import, so setting
 * LOGIXIA_SILENT_INTERNAL after import had no effect. It is now read per call,
 * making the documented test-silencing reliable.
 */

import { internalError, internalLog, internalWarn } from '../internal-log';

describe('internal-log helpers', () => {
  let writeSpy: jest.SpyInstance;
  let savedSilent: string | undefined;

  beforeEach(() => {
    writeSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    savedSilent = process.env['LOGIXIA_SILENT_INTERNAL'];
    delete process.env['LOGIXIA_SILENT_INTERNAL'];
  });

  afterEach(() => {
    writeSpy.mockRestore();
    if (savedSilent === undefined) delete process.env['LOGIXIA_SILENT_INTERNAL'];
    else process.env['LOGIXIA_SILENT_INTERNAL'] = savedSilent;
  });

  it('writes prefixed messages to stderr', () => {
    internalLog('hello');
    internalWarn('careful');
    internalError('broke', new Error('boom'));

    const output = writeSpy.mock.calls.map((c) => String(c[0])).join('');
    expect(output).toContain('[logixia] hello');
    expect(output).toContain('[logixia:warn] careful');
    expect(output).toContain('[logixia:error] broke — boom');
  });

  it('appends a stringified non-Error cause', () => {
    internalError('failed', 'plain reason');
    expect(String(writeSpy.mock.calls[0]![0])).toContain('failed — plain reason');
  });

  it('omits the cause segment when no error is given', () => {
    internalError('just a message');
    expect(String(writeSpy.mock.calls[0]![0])).toBe('[logixia:error] just a message\n');
  });

  it('respects LOGIXIA_SILENT_INTERNAL set AFTER import (read per call)', () => {
    process.env['LOGIXIA_SILENT_INTERNAL'] = '1';
    internalLog('should be silent');
    internalWarn('also silent');
    internalError('silent too', new Error('x'));
    expect(writeSpy).not.toHaveBeenCalled();
  });

  it('resumes writing when the flag is cleared again', () => {
    process.env['LOGIXIA_SILENT_INTERNAL'] = '1';
    internalLog('silent');
    delete process.env['LOGIXIA_SILENT_INTERNAL'];
    internalLog('audible');
    const output = writeSpy.mock.calls.map((c) => String(c[0])).join('');
    expect(output).not.toContain('silent');
    expect(output).toContain('audible');
  });
});
