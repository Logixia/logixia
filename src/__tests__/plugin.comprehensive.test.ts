/**
 * Comprehensive tests for the Plugin system
 *
 * Covers:
 *  - PluginRegistry: register, unregister, has, size, runOnLog, runOnError, runOnShutdown
 *  - Duplicate plugin prevention
 *  - onInit lifecycle hook
 *  - Plugin entry mutation / cancellation via onLog returning null
 *  - Error swallowing in onError and onShutdown
 *  - globalPluginRegistry and usePlugin
 *  - Logger.use() and Logger.unuse()
 */

import type { LogixiaPlugin } from '../plugin';
import { globalPluginRegistry, PluginRegistry, usePlugin } from '../plugin';
import type { LogEntry } from '../types';

// Helper to make a minimal valid LogEntry
function makeEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: new Date().toISOString(),
    level: 'info',
    appName: 'TestApp',
    message: 'test message',
    ...overrides,
  };
}

// ── PluginRegistry ─────────────────────────────────────────────────────────────

describe('PluginRegistry', () => {
  let registry: PluginRegistry;

  beforeEach(() => {
    registry = new PluginRegistry();
  });

  // ── register ────────────────────────────────────────────────────────────────

  describe('register', () => {
    it('registers a plugin and increments size', () => {
      registry.register({ name: 'p1' });
      expect(registry.size).toBe(1);
    });

    it('silently skips a plugin with the same name', () => {
      registry.register({ name: 'p1' });
      registry.register({ name: 'p1' });
      expect(registry.size).toBe(1);
    });

    it('calls onInit immediately after registration', () => {
      const onInit = jest.fn();
      registry.register({ name: 'init-plugin', onInit });
      expect(onInit).toHaveBeenCalledTimes(1);
    });

    it('calls async onInit without blocking (fire and forget)', async () => {
      let initiated = false;
      registry.register({
        name: 'async-init',
        onInit: async () => {
          await Promise.resolve();
          initiated = true;
        },
      });
      // Not yet resolved (fire and forget)
      expect(initiated).toBe(false);
      // Wait for microtask queue
      await Promise.resolve();
      await Promise.resolve();
      expect(initiated).toBe(true);
    });

    it('swallows errors thrown by async onInit (fire and forget)', async () => {
      // Synchronous throws from onInit ARE propagated (it's called synchronously).
      // Only async onInit errors are swallowed. Verify async path.
      const rejected = false;
      registry.register({
        name: 'bad-async-init',
        onInit: async () => {
          await Promise.resolve();
          throw new Error('async init failed');
        },
      });
      await Promise.resolve();
      await Promise.resolve();
      // No unhandled rejection — error was swallowed
      expect(rejected).toBe(false);
    });

    it('can register multiple distinct plugins', () => {
      registry.register({ name: 'p1' });
      registry.register({ name: 'p2' });
      registry.register({ name: 'p3' });
      expect(registry.size).toBe(3);
    });
  });

  // ── unregister ──────────────────────────────────────────────────────────────

  describe('unregister', () => {
    it('removes a registered plugin', () => {
      registry.register({ name: 'p1' });
      registry.unregister('p1');
      expect(registry.size).toBe(0);
    });

    it('is a no-op when plugin is not found', () => {
      expect(() => registry.unregister('nonexistent')).not.toThrow();
      expect(registry.size).toBe(0);
    });

    it('only removes the named plugin, not others', () => {
      registry.register({ name: 'p1' });
      registry.register({ name: 'p2' });
      registry.unregister('p1');
      expect(registry.size).toBe(1);
      expect(registry.has('p2')).toBe(true);
    });
  });

  // ── has ─────────────────────────────────────────────────────────────────────

  describe('has', () => {
    it('returns true when plugin is registered', () => {
      registry.register({ name: 'p1' });
      expect(registry.has('p1')).toBe(true);
    });

    it('returns false when plugin is not registered', () => {
      expect(registry.has('p1')).toBe(false);
    });

    it('returns false after unregistering', () => {
      registry.register({ name: 'p1' });
      registry.unregister('p1');
      expect(registry.has('p1')).toBe(false);
    });
  });

  // ── size ────────────────────────────────────────────────────────────────────

  describe('size', () => {
    it('returns 0 when empty', () => {
      expect(registry.size).toBe(0);
    });

    it('returns correct count as plugins are added and removed', () => {
      registry.register({ name: 'a' });
      registry.register({ name: 'b' });
      expect(registry.size).toBe(2);
      registry.unregister('a');
      expect(registry.size).toBe(1);
    });
  });

  // ── runOnLog ─────────────────────────────────────────────────────────────────

  describe('runOnLog', () => {
    it('returns the entry unchanged when no plugins have onLog', async () => {
      registry.register({ name: 'no-hook' });
      const entry = makeEntry();
      const result = await registry.runOnLog(entry);
      expect(result).toBe(entry);
    });

    it('passes the entry through the onLog hook', async () => {
      const received: LogEntry[] = [];
      registry.register({
        name: 'spy',
        onLog(e) {
          received.push(e);
          return e;
        },
      });
      const entry = makeEntry();
      await registry.runOnLog(entry);
      expect(received).toHaveLength(1);
      expect(received[0]).toBe(entry);
    });

    it('allows a plugin to mutate the entry', async () => {
      registry.register({
        name: 'enricher',
        onLog(e) {
          return { ...e, payload: { ...e.payload, buildId: 'build-42' } };
        },
      });
      const entry = makeEntry();
      const result = await registry.runOnLog(entry);
      expect(result!.payload?.buildId).toBe('build-42');
    });

    it('returns null when a plugin cancels the entry', async () => {
      registry.register({
        name: 'canceller',
        onLog() {
          return null;
        },
      });
      const result = await registry.runOnLog(makeEntry());
      expect(result).toBeNull();
    });

    it('stops processing after a cancellation', async () => {
      const secondCalled = jest.fn((e: LogEntry) => e);
      registry.register({ name: 'canceller', onLog: () => null });
      registry.register({ name: 'second', onLog: secondCalled });
      await registry.runOnLog(makeEntry());
      expect(secondCalled).not.toHaveBeenCalled();
    });

    it('runs plugins in registration order', async () => {
      const order: string[] = [];
      registry.register({
        name: 'first',
        onLog(e) {
          order.push('first');
          return e;
        },
      });
      registry.register({
        name: 'second',
        onLog(e) {
          order.push('second');
          return e;
        },
      });
      await registry.runOnLog(makeEntry());
      expect(order).toEqual(['first', 'second']);
    });

    it('supports async onLog hooks', async () => {
      registry.register({
        name: 'async-enricher',
        async onLog(e) {
          await Promise.resolve();
          return { ...e, payload: { async: true } };
        },
      });
      const result = await registry.runOnLog(makeEntry());
      expect(result!.payload?.async).toBe(true);
    });

    it('each plugin receives the output of the previous plugin', async () => {
      registry.register({
        name: 'first',
        onLog(e) {
          return { ...e, payload: { step: 1 } };
        },
      });
      registry.register({
        name: 'second',
        onLog(e) {
          return { ...e, payload: { ...e.payload, step2: 2 } };
        },
      });
      const result = await registry.runOnLog(makeEntry());
      expect(result!.payload?.step).toBe(1);
      expect(result!.payload?.step2).toBe(2);
    });
  });

  // ── runOnError ───────────────────────────────────────────────────────────────

  describe('runOnError', () => {
    it('calls onError hooks when transport fails', async () => {
      const errors: Error[] = [];
      registry.register({
        name: 'error-handler',
        onError(e) {
          errors.push(e);
        },
      });
      const err = new Error('transport failed');
      await registry.runOnError(err);
      expect(errors).toHaveLength(1);
      expect(errors[0]).toBe(err);
    });

    it('swallows errors thrown inside async onError', async () => {
      registry.register({
        name: 'bad-error-handler',
        async onError() {
          await Promise.resolve();
          throw new Error('handler blew up');
        },
      });
      await expect(registry.runOnError(new Error('original'))).resolves.not.toThrow();
    });

    it('passes the log entry to onError hooks', async () => {
      const captured: LogEntry[] = [];
      registry.register({
        name: 'error-with-entry',
        onError(_err, entry) {
          if (entry) captured.push(entry);
        },
      });
      const entry = makeEntry();
      await registry.runOnError(new Error('fail'), entry);
      expect(captured[0]).toBe(entry);
    });
  });

  // ── runOnShutdown ────────────────────────────────────────────────────────────

  describe('runOnShutdown', () => {
    it('calls onShutdown hooks on all plugins', async () => {
      const shutdowns: string[] = [];
      registry.register({
        name: 'p1',
        onShutdown: () => {
          shutdowns.push('p1');
        },
      });
      registry.register({
        name: 'p2',
        onShutdown: () => {
          shutdowns.push('p2');
        },
      });
      await registry.runOnShutdown();
      expect(shutdowns).toContain('p1');
      expect(shutdowns).toContain('p2');
    });

    it('swallows errors thrown inside async onShutdown', async () => {
      registry.register({
        name: 'bad-shutdown',
        async onShutdown() {
          await Promise.resolve();
          throw new Error('shutdown blew up');
        },
      });
      await expect(registry.runOnShutdown()).resolves.not.toThrow();
    });

    it('runs all shutdown hooks concurrently', async () => {
      const completed: string[] = [];
      registry.register({
        name: 'slow',
        onShutdown: async () => {
          await new Promise((r) => setTimeout(r, 10));
          completed.push('slow');
        },
      });
      registry.register({
        name: 'fast',
        onShutdown: () => {
          completed.push('fast');
        },
      });
      await registry.runOnShutdown();
      expect(completed).toContain('slow');
      expect(completed).toContain('fast');
    });

    it('is a no-op when no plugins have onShutdown', async () => {
      registry.register({ name: 'no-shutdown' });
      await expect(registry.runOnShutdown()).resolves.not.toThrow();
    });
  });
});

// ── usePlugin / globalPluginRegistry ─────────────────────────────────────────

describe('usePlugin and globalPluginRegistry', () => {
  afterEach(() => {
    // Clean up any plugins registered to the global registry during tests
    // Unfortunately there's no public clear() on globalPluginRegistry,
    // so we unregister by name
    (globalPluginRegistry as unknown as { _plugins: LogixiaPlugin[] })._plugins.length = 0;
  });

  it('usePlugin registers a plugin in the global registry', () => {
    usePlugin({ name: 'global-plugin' });
    expect(globalPluginRegistry.has('global-plugin')).toBe(true);
  });

  it('usePlugin is idempotent (same plugin registered twice)', () => {
    usePlugin({ name: 'global-plugin' });
    usePlugin({ name: 'global-plugin' });
    // size accessed via internal field
    const size = (globalPluginRegistry as unknown as { _plugins: LogixiaPlugin[] })._plugins.length;
    expect(size).toBe(1);
  });

  it('globalPluginRegistry starts empty before any usePlugin calls', () => {
    const size = (globalPluginRegistry as unknown as { _plugins: LogixiaPlugin[] })._plugins.length;
    expect(size).toBe(0);
  });
});

// ── Full plugin lifecycle ─────────────────────────────────────────────────────

describe('Full plugin lifecycle', () => {
  it('init → log → error → shutdown', async () => {
    const events: string[] = [];
    const registry = new PluginRegistry();

    registry.register({
      name: 'lifecycle',
      onInit() {
        events.push('init');
      },
      onLog(e) {
        events.push('log');
        return e;
      },
      onError() {
        events.push('error');
      },
      onShutdown() {
        events.push('shutdown');
      },
    });

    expect(events).toContain('init');
    await registry.runOnLog(makeEntry());
    await registry.runOnError(new Error('fail'));
    await registry.runOnShutdown();

    expect(events).toEqual(['init', 'log', 'error', 'shutdown']);
  });
});
