/**
 * A log call must not reject, and so must not crash an un-awaited caller, because an
 * Error could not be serialized.
 */

import * as internalLog from '../../utils/internal-log';
import { createLogger } from '../logixia-logger';

function hostileError(): Error {
  const error = new Error('lazy');
  Object.defineProperty(error, 'stack', {
    get() {
      throw new Error('stack getter failed');
    },
  });
  return error;
}

describe('logger.error() with an Error that cannot be serialized', () => {
  it('resolves, logs the marker and reports the failure', async () => {
    const entries: { message: string; data?: Record<string, unknown> }[] = [];
    const spy = jest.spyOn(internalLog, 'internalError').mockImplementation(() => {});
    try {
      const logger = createLogger({
        appName: 'a',
        traceId: false,
        transports: { custom: [{ name: 'c', write: (e: never) => void entries.push(e) }] },
      });
      await expect(logger.error(hostileError())).resolves.toBeUndefined();
      expect(entries[0]?.message).toBe('lazy');
      expect(entries[0]?.data?.['error']).toBe('[Unserializable]');
      expect(spy).toHaveBeenCalledWith('Error serialization failed', expect.any(Error));
    } finally {
      spy.mockRestore();
    }
  });

  it('survives a message getter that throws', async () => {
    const spy = jest.spyOn(internalLog, 'internalError').mockImplementation(() => {});
    try {
      const error = hostileError();
      Object.defineProperty(error, 'message', {
        get() {
          throw new Error('message getter failed');
        },
      });
      const logger = createLogger({
        appName: 'a',
        silent: false,
        transports: { custom: [{ name: 'c', write: () => {} }] },
      });
      await expect(logger.error(error)).resolves.toBeUndefined();
    } finally {
      spy.mockRestore();
    }
  });

  it('still returns the shared resolved promise on the fast path', () => {
    const spy = jest.spyOn(internalLog, 'internalError').mockImplementation(() => {});
    try {
      const logger = createLogger({
        appName: 'a',
        transports: { custom: [{ name: 'c', write: () => {} }] },
      });
      expect(logger.error(hostileError())).toBe(logger.error(hostileError()));
    } finally {
      spy.mockRestore();
    }
  });

  it('accepts a null-prototype message from a JS caller', async () => {
    const logger = createLogger({
      appName: 'a',
      transports: { custom: [{ name: 'c', write: () => {} }] },
    });
    const message = Object.create(null) as Record<string, unknown>;
    message['message'] = 'from JS caller';
    await expect(logger.info(message as never)).resolves.toBeUndefined();
    await expect(logger.error(message as never)).resolves.toBeUndefined();
  });
});
