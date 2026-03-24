/**
 * Comprehensive tests for createMockLogger (testing utility)
 *
 * Covers:
 *  - Recording log calls at every level: error, warn, info, debug, trace, verbose, logLevel
 *  - Error object handling in error()
 *  - getCalls(): all levels, filtered by level
 *  - getLastCall(): last overall, last by level
 *  - expectLog(): string, RegExp, object, function matchers; throws on failure
 *  - expectNoLog(): passes when no match, throws when match found
 *  - reset()
 *  - Timer no-ops: time, timeEnd, timeAsync
 *  - Level management stubs: setLevel, getLevel, setContext, getContext
 *  - Field management stubs: enableField, disableField, isFieldEnabled, getFieldState, resetFieldState
 *  - Transport management stubs
 *  - child() creates a new mock logger with the given context
 *  - Plugin stubs: use, unuse
 *  - context option propagates into entry.context
 *  - silent option (default true)
 */

import { createMockLogger } from '../mock-logger';

describe('createMockLogger', () => {
  // ── Recording log calls ───────────────────────────────────────────────────

  describe('recording log calls', () => {
    it('records info calls', async () => {
      const mock = createMockLogger();
      await mock.logger.info('hello info', { key: 'val' });
      expect(mock.calls).toHaveLength(1);
      expect(mock.calls[0].level).toBe('info');
      expect(mock.calls[0].message).toBe('hello info');
      expect(mock.calls[0].data).toEqual({ key: 'val' });
    });

    it('records warn calls', async () => {
      const mock = createMockLogger();
      await mock.logger.warn('warning');
      expect(mock.calls[0].level).toBe('warn');
    });

    it('records debug calls', async () => {
      const mock = createMockLogger();
      await mock.logger.debug('debug msg');
      expect(mock.calls[0].level).toBe('debug');
    });

    it('records trace calls', async () => {
      const mock = createMockLogger();
      await mock.logger.trace('trace msg');
      expect(mock.calls[0].level).toBe('trace');
    });

    it('records verbose calls', async () => {
      const mock = createMockLogger();
      await mock.logger.verbose('verbose msg');
      expect(mock.calls[0].level).toBe('verbose');
    });

    it('records error with string message', async () => {
      const mock = createMockLogger();
      await mock.logger.error('something broke');
      expect(mock.calls[0].level).toBe('error');
      expect(mock.calls[0].message).toBe('something broke');
    });

    it('records error with Error object — extracts message', async () => {
      const mock = createMockLogger();
      const err = new Error('error object');
      await mock.logger.error(err);
      expect(mock.calls[0].level).toBe('error');
      expect(mock.calls[0].message).toBe('error object');
    });

    it('merges error stack into data when error object is passed', async () => {
      const mock = createMockLogger();
      const err = new Error('err');
      await mock.logger.error(err);
      expect(mock.calls[0].data?.error).toBeDefined();
      expect((mock.calls[0].data?.error as Record<string, unknown>).message).toBe('err');
    });

    it('records logLevel calls with custom level', async () => {
      const mock = createMockLogger();
      await mock.logger.logLevel('kafka', 'kafka message');
      expect(mock.calls[0].level).toBe('kafka');
    });

    it('records calls in insertion order', async () => {
      const mock = createMockLogger();
      await mock.logger.info('first');
      await mock.logger.warn('second');
      await mock.logger.error('third');
      expect(mock.calls[0].message).toBe('first');
      expect(mock.calls[1].message).toBe('second');
      expect(mock.calls[2].message).toBe('third');
    });

    it('records calls without data when data is omitted', async () => {
      const mock = createMockLogger();
      await mock.logger.info('no data');
      expect(mock.calls[0].data).toBeUndefined();
    });

    it('populates entry.level and entry.message', async () => {
      const mock = createMockLogger();
      await mock.logger.info('test entry', { x: 1 });
      expect(mock.calls[0].entry.level).toBe('info');
      expect(mock.calls[0].entry.message).toBe('test entry');
    });
  });

  // ── getCalls ──────────────────────────────────────────────────────────────

  describe('getCalls', () => {
    it('returns all calls when no level is specified', async () => {
      const mock = createMockLogger();
      await mock.logger.info('msg1');
      await mock.logger.error('msg2');
      expect(mock.getCalls()).toHaveLength(2);
    });

    it('returns only matching level calls (case-insensitive)', async () => {
      const mock = createMockLogger();
      await mock.logger.info('info1');
      await mock.logger.info('info2');
      await mock.logger.error('err1');
      const infoCalls = mock.getCalls('info');
      expect(infoCalls).toHaveLength(2);
      expect(infoCalls.every((c) => c.level === 'info')).toBe(true);
    });

    it('returns empty array when no calls match the level', async () => {
      const mock = createMockLogger();
      await mock.logger.info('info msg');
      expect(mock.getCalls('debug')).toHaveLength(0);
    });

    it('returns a copy of the calls array', async () => {
      const mock = createMockLogger();
      await mock.logger.info('msg');
      const calls = mock.getCalls();
      calls.push({ level: 'fake', message: 'fake', entry: { level: 'fake', message: 'fake' } });
      expect(mock.getCalls()).toHaveLength(1);
    });

    it('is case-insensitive: "INFO" matches "info" calls', async () => {
      const mock = createMockLogger();
      await mock.logger.info('test');
      expect(mock.getCalls('INFO')).toHaveLength(1);
    });
  });

  // ── getLastCall ───────────────────────────────────────────────────────────

  describe('getLastCall', () => {
    it('returns the last call overall', async () => {
      const mock = createMockLogger();
      await mock.logger.info('first');
      await mock.logger.warn('last');
      expect(mock.getLastCall()?.message).toBe('last');
    });

    it('returns the last call for a specific level', async () => {
      const mock = createMockLogger();
      await mock.logger.info('info1');
      await mock.logger.warn('warn1');
      await mock.logger.info('info2');
      expect(mock.getLastCall('info')?.message).toBe('info2');
    });

    it('returns undefined when no calls exist', () => {
      const mock = createMockLogger();
      expect(mock.getLastCall()).toBeUndefined();
    });

    it('returns undefined when no calls exist at the specified level', async () => {
      const mock = createMockLogger();
      await mock.logger.info('info msg');
      expect(mock.getLastCall('error')).toBeUndefined();
    });
  });

  // ── expectLog ─────────────────────────────────────────────────────────────

  describe('expectLog', () => {
    it('passes when an exact string message matches', async () => {
      const mock = createMockLogger();
      await mock.logger.info('expected message');
      expect(() => mock.expectLog('info', 'expected message')).not.toThrow();
    });

    it('throws when string message does not match', async () => {
      const mock = createMockLogger();
      await mock.logger.info('actual');
      expect(() => mock.expectLog('info', 'expected')).toThrow();
    });

    it('passes when RegExp matches the message', async () => {
      const mock = createMockLogger();
      await mock.logger.error('Error: connection refused');
      expect(() => mock.expectLog('error', /connection refused/)).not.toThrow();
    });

    it('throws when RegExp does not match', async () => {
      const mock = createMockLogger();
      await mock.logger.error('some error');
      expect(() => mock.expectLog('error', /timeout/)).toThrow();
    });

    it('passes when object matcher has all matching keys', async () => {
      const mock = createMockLogger();
      await mock.logger.info('user created', { userId: 'u-1', role: 'admin' });
      expect(() =>
        mock.expectLog('info', { message: 'user created', userId: 'u-1' })
      ).not.toThrow();
    });

    it('throws when object matcher has a non-matching value', async () => {
      const mock = createMockLogger();
      await mock.logger.info('msg', { userId: 'u-1' });
      expect(() => mock.expectLog('info', { userId: 'u-2' })).toThrow();
    });

    it('passes when object matcher uses RegExp values', async () => {
      const mock = createMockLogger();
      await mock.logger.error('DB error: timeout');
      expect(() => mock.expectLog('error', { message: /DB error/ })).not.toThrow();
    });

    it('passes when function matcher returns true', async () => {
      const mock = createMockLogger();
      await mock.logger.info('special msg', { code: 42 });
      expect(() => mock.expectLog('info', (call) => call.data?.code === 42)).not.toThrow();
    });

    it('throws when function matcher returns false', async () => {
      const mock = createMockLogger();
      await mock.logger.info('msg', { code: 1 });
      expect(() => mock.expectLog('info', (call) => call.data?.code === 999)).toThrow();
    });

    it('passes with no matcher — checks only that level was logged', async () => {
      const mock = createMockLogger();
      await mock.logger.warn('any warning');
      expect(() => mock.expectLog('warn')).not.toThrow();
    });

    it('throws with no matcher when level was never logged', () => {
      const mock = createMockLogger();
      expect(() => mock.expectLog('error')).toThrow();
    });

    it('includes all recorded calls in the error message', async () => {
      const mock = createMockLogger();
      await mock.logger.info('something');
      let errorMessage = '';
      try {
        mock.expectLog('error', 'missing');
      } catch (e) {
        errorMessage = (e as Error).message;
      }
      expect(errorMessage).toContain('something');
    });
  });

  // ── expectNoLog ───────────────────────────────────────────────────────────

  describe('expectNoLog', () => {
    it('passes when no calls were made at the level', () => {
      const mock = createMockLogger();
      expect(() => mock.expectNoLog('error')).not.toThrow();
    });

    it('passes when calls exist at the level but none match the matcher', async () => {
      const mock = createMockLogger();
      await mock.logger.info('some info');
      expect(() => mock.expectNoLog('info', 'different message')).not.toThrow();
    });

    it('throws when a matching call is found', async () => {
      const mock = createMockLogger();
      await mock.logger.error('bad thing happened');
      expect(() => mock.expectNoLog('error', 'bad thing happened')).toThrow();
    });

    it('throws when a RegExp match is found', async () => {
      const mock = createMockLogger();
      await mock.logger.warn('deprecation warning');
      expect(() => mock.expectNoLog('warn', /deprecation/)).toThrow();
    });

    it('passes after reset clears matching calls', async () => {
      const mock = createMockLogger();
      await mock.logger.error('bad error');
      mock.reset();
      expect(() => mock.expectNoLog('error', 'bad error')).not.toThrow();
    });
  });

  // ── reset ─────────────────────────────────────────────────────────────────

  describe('reset', () => {
    it('clears all recorded calls', async () => {
      const mock = createMockLogger();
      await mock.logger.info('msg1');
      await mock.logger.error('msg2');
      mock.reset();
      expect(mock.calls).toHaveLength(0);
    });

    it('allows new calls to be recorded after reset', async () => {
      const mock = createMockLogger();
      await mock.logger.info('before');
      mock.reset();
      await mock.logger.warn('after');
      expect(mock.calls).toHaveLength(1);
      expect(mock.calls[0].level).toBe('warn');
    });
  });

  // ── Timer stubs ───────────────────────────────────────────────────────────

  describe('timer stubs', () => {
    it('time() is a no-op', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.time('timer')).not.toThrow();
    });

    it('timeEnd() returns 0', async () => {
      const mock = createMockLogger();
      const result = await mock.logger.timeEnd('timer');
      expect(result).toBe(0);
    });

    it('timeAsync() executes the function and returns its result', async () => {
      const mock = createMockLogger();
      const result = await mock.logger.timeAsync('op', async () => 'done');
      expect(result).toBe('done');
    });

    it('timeAsync() propagates errors from the function', async () => {
      const mock = createMockLogger();
      await expect(
        mock.logger.timeAsync('op', async () => {
          throw new Error('async error');
        })
      ).rejects.toThrow('async error');
    });
  });

  // ── Level and context stubs ───────────────────────────────────────────────

  describe('level and context stubs', () => {
    it('setLevel() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.setLevel('debug')).not.toThrow();
    });

    it('getLevel() returns "info"', () => {
      const mock = createMockLogger();
      expect(mock.logger.getLevel()).toBe('info');
    });

    it('setContext() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.setContext('my-context')).not.toThrow();
    });

    it('getContext() returns the context option', () => {
      const mock = createMockLogger({ context: 'test-service' });
      expect(mock.logger.getContext()).toBe('test-service');
    });

    it('getContext() returns undefined when no context option', () => {
      const mock = createMockLogger();
      expect(mock.logger.getContext()).toBeUndefined();
    });
  });

  // ── Field management stubs ────────────────────────────────────────────────

  describe('field management stubs', () => {
    it('enableField() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.enableField('timestamp')).not.toThrow();
    });

    it('disableField() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.disableField('timestamp')).not.toThrow();
    });

    it('isFieldEnabled() always returns true', () => {
      const mock = createMockLogger();
      expect(mock.logger.isFieldEnabled('any-field')).toBe(true);
    });

    it('getFieldState() returns an empty object', () => {
      const mock = createMockLogger();
      expect(mock.logger.getFieldState()).toEqual({});
    });

    it('resetFieldState() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.resetFieldState()).not.toThrow();
    });
  });

  // ── Transport management stubs ────────────────────────────────────────────

  describe('transport management stubs', () => {
    it('enableTransportLevelPrompting() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.enableTransportLevelPrompting()).not.toThrow();
    });

    it('disableTransportLevelPrompting() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.disableTransportLevelPrompting()).not.toThrow();
    });

    it('setTransportLevels() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.setTransportLevels('console', ['info'])).not.toThrow();
    });

    it('getTransportLevels() returns undefined', () => {
      const mock = createMockLogger();
      expect(mock.logger.getTransportLevels('console')).toBeUndefined();
    });

    it('clearTransportLevelPreferences() does not throw', () => {
      const mock = createMockLogger();
      expect(() => mock.logger.clearTransportLevelPreferences()).not.toThrow();
    });

    it('getAvailableTransports() returns an empty array', () => {
      const mock = createMockLogger();
      expect(mock.logger.getAvailableTransports()).toEqual([]);
    });
  });

  // ── child() ───────────────────────────────────────────────────────────────

  describe('child()', () => {
    it('creates a new logger', () => {
      const mock = createMockLogger();
      const child = mock.logger.child('child-context');
      expect(child).toBeDefined();
      expect(typeof child.info).toBe('function');
    });

    it('the child logger records its own calls independently', async () => {
      const mock = createMockLogger();
      const child = mock.logger.child('sub');
      await child.info('child message');
      // Parent mock's calls are unaffected
      expect(mock.calls).toHaveLength(0);
    });

    it('child logger has the given context', () => {
      const mock = createMockLogger();
      const child = mock.logger.child('my-service');
      expect(child.getContext()).toBe('my-service');
    });
  });

  // ── Plugin stubs ──────────────────────────────────────────────────────────

  describe('plugin stubs', () => {
    it('use() returns this (logger)', () => {
      const mock = createMockLogger();
      const result = mock.logger.use({ name: 'plugin' });
      expect(result).toBe(mock.logger);
    });

    it('unuse() returns this (logger)', () => {
      const mock = createMockLogger();
      const result = mock.logger.unuse('plugin');
      expect(result).toBe(mock.logger);
    });
  });

  // ── close() ───────────────────────────────────────────────────────────────

  describe('close()', () => {
    it('resolves without error', async () => {
      const mock = createMockLogger();
      await expect(mock.logger.close()).resolves.toBeUndefined();
    });
  });

  // ── context option ────────────────────────────────────────────────────────

  describe('context option', () => {
    it('writes context into entry.context', async () => {
      const mock = createMockLogger({ context: 'svc-a' });
      await mock.logger.info('message');
      expect(mock.calls[0].entry.context).toBe('svc-a');
    });

    it('entry.context is undefined when no context option', async () => {
      const mock = createMockLogger();
      await mock.logger.info('message');
      expect(mock.calls[0].entry.context).toBeUndefined();
    });
  });

  // ── silent option ─────────────────────────────────────────────────────────

  describe('silent option', () => {
    it('defaults to true', () => {
      const mock = createMockLogger();
      expect(mock.silent).toBe(true);
    });

    it('can be set to false', () => {
      const mock = createMockLogger({ silent: false });
      expect(mock.silent).toBe(false);
    });
  });

  // ── calls property ────────────────────────────────────────────────────────

  describe('calls property', () => {
    it('is a live reference to the internal array', async () => {
      const mock = createMockLogger();
      const ref = mock.calls;
      await mock.logger.info('live');
      expect(ref).toHaveLength(1);
    });
  });
});
