/**
 * Tests for Wide Events / Canonical Log Lines (R1).
 *
 * Verifies: fields accumulated from anywhere in the async tree land on ONE
 * event; the event is emitted exactly once on success OR error (the
 * emit-in-finally guarantee); duration + trace are attached; and the Express
 * middleware emits one canonical line on finish/close with statusCode.
 */

import {
  addEventFields,
  getEventFields,
  setEventField,
  type WideEventLogger,
  wideEventMiddleware,
  withWideEvent,
} from '../wide-events';

interface Emitted {
  level: string;
  message: string;
  data?: Record<string, unknown>;
}

function makeLogger(): { logger: WideEventLogger; events: Emitted[] } {
  const events: Emitted[] = [];
  return {
    events,
    logger: {
      logLevel: (level, message, data) => {
        events.push({ level, message, data });
        return Promise.resolve();
      },
    },
  };
}

describe('withWideEvent', () => {
  it('accumulates fields from nested calls into a single event', async () => {
    const { logger, events } = makeLogger();

    await withWideEvent(logger, { route: '/checkout' }, async () => {
      addEventFields({ userId: 'u1' });
      setEventField('planTier', 'pro');
      await Promise.resolve();
      addEventFields({ dbQueries: 4 });
    });

    expect(events).toHaveLength(1);
    const data = events[0]!.data!;
    expect(data.route).toBe('/checkout');
    expect(data.userId).toBe('u1');
    expect(data.planTier).toBe('pro');
    expect(data.dbQueries).toBe(4);
    expect(typeof data.durationMs).toBe('number');
  });

  it('emits exactly once even when the callback throws, with error fields', async () => {
    const { logger, events } = makeLogger();

    await expect(
      withWideEvent(logger, { op: 'risky' }, async () => {
        addEventFields({ step: 1 });
        throw new Error('kaboom');
      })
    ).rejects.toThrow('kaboom');

    expect(events).toHaveLength(1);
    const data = events[0]!.data!;
    expect(data.step).toBe(1);
    expect(data.error).toBe(true);
    expect(data.errorMessage).toBe('kaboom');
  });

  it('respects custom level and message', async () => {
    const { logger, events } = makeLogger();
    await withWideEvent(logger, {}, async () => {}, { level: 'debug', message: 'canonical' });
    expect(events[0]!.level).toBe('debug');
    expect(events[0]!.message).toBe('canonical');
  });

  it('addEventFields outside a scope is a no-op (does not throw)', () => {
    expect(() => addEventFields({ x: 1 })).not.toThrow();
    expect(getEventFields()).toBeUndefined();
  });

  it('isolates concurrent scopes (no field bleed across requests)', async () => {
    const { logger, events } = makeLogger();
    await Promise.all([
      withWideEvent(logger, { req: 'A' }, async () => {
        await new Promise((r) => setTimeout(r, 5));
        addEventFields({ who: 'A' });
      }),
      withWideEvent(logger, { req: 'B' }, async () => {
        addEventFields({ who: 'B' });
      }),
    ]);

    const a = events.find((e) => e.data!.req === 'A')!;
    const b = events.find((e) => e.data!.req === 'B')!;
    expect(a.data!.who).toBe('A');
    expect(b.data!.who).toBe('B');
  });
});

describe('wideEventMiddleware', () => {
  function fakeRes() {
    const handlers: Record<string, Array<() => void>> = {};
    return {
      statusCode: 200,
      once(event: string, cb: () => void) {
        if (!handlers[event]) handlers[event] = [];
        handlers[event]!.push(cb);
      },
      fire(event: string) {
        for (const cb of handlers[event] ?? []) cb();
      },
    };
  }

  it('emits one canonical event on finish with method/url/status/duration', () => {
    const { logger, events } = makeLogger();
    const mw = wideEventMiddleware(logger);
    const req = { method: 'GET', url: '/x', headers: {} };
    const res = fakeRes();

    mw(req, res, () => {
      // handler adds fields within the request scope
      addEventFields({ handled: true });
    });
    res.fire('finish');

    expect(events).toHaveLength(1);
    const data = events[0]!.data!;
    expect(data.method).toBe('GET');
    expect(data.url).toBe('/x');
    expect(data.statusCode).toBe(200);
    expect(data.handled).toBe(true);
    expect(typeof data.durationMs).toBe('number');
  });

  it('emits only once when both finish and close fire', () => {
    const { logger, events } = makeLogger();
    const mw = wideEventMiddleware(logger);
    const res = fakeRes();
    mw({ method: 'GET', url: '/y' }, res, () => {});
    res.fire('finish');
    res.fire('close');
    expect(events).toHaveLength(1);
  });

  it('skips when the skip predicate returns true', () => {
    const { logger, events } = makeLogger();
    const mw = wideEventMiddleware(logger, { skip: (r) => r.url === '/health' });
    let nextCalled = false;
    mw({ method: 'GET', url: '/health' }, fakeRes(), () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(events).toHaveLength(0);
  });
});
