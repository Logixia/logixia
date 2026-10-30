import 'reflect-metadata';

import type { CallHandler, ExecutionContext } from '@nestjs/common';
import { firstValueFrom, Observable, of, Subject } from 'rxjs';

import { TraceContext } from '../../utils/trace.utils';
import { WebSocketTraceInterceptor } from '../websocket-trace.interceptor';

function makeContext(data: unknown, client: unknown = {}): ExecutionContext {
  return {
    switchToWs: () => ({ getData: () => data, getClient: () => client }),
    getType: () => 'ws',
  } as unknown as ExecutionContext;
}

function makeHandler<T>(produce: () => Observable<T>): {
  handler: CallHandler;
  calls: () => number;
} {
  let calls = 0;
  return {
    handler: {
      handle: () => {
        calls++;
        return produce();
      },
    },
    calls: () => calls,
  };
}

function emptyAls<T>(fn: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    TraceContext.instance.storage.run({}, () => {
      fn().then(resolve, reject);
    });
  });
}

const currentId = () => TraceContext.instance.getCurrentTraceId();

describe('WebSocketTraceInterceptor', () => {
  it('passes the handler result through untouched when disabled', async () => {
    const result$ = of('raw');
    const { handler } = makeHandler(() => result$);
    const interceptor = new WebSocketTraceInterceptor({ enabled: false });

    const out = interceptor.intercept(makeContext({ traceId: 'abc' }), handler);

    expect(out).toBe(result$);
  });

  it('takes the trace ID from the message body (traceId and trace_id)', async () => {
    await emptyAls(async () => {
      for (const key of ['traceId', 'trace_id']) {
        let seen: string | undefined;
        const { handler } = makeHandler(() => {
          seen = currentId();
          return of('ok');
        });
        const out = new WebSocketTraceInterceptor().intercept(
          makeContext({ [key]: `id-from-${key}` }),
          handler
        );
        expect(await firstValueFrom(out)).toBe('ok');
        expect(seen).toBe(`id-from-${key}`);
      }
    });
  });

  it('takes the trace ID from client.handshake.headers', async () => {
    await emptyAls(async () => {
      let seen: string | undefined;
      const { handler } = makeHandler(() => {
        seen = currentId();
        return of('ok');
      });
      const client = { handshake: { headers: { 'x-trace-id': 'hdr-1' }, query: {} } };

      await firstValueFrom(
        new WebSocketTraceInterceptor().intercept(makeContext({}, client), handler)
      );

      expect(seen).toBe('hdr-1');
    });
  });

  it('takes the trace ID from client.handshake.query', async () => {
    await emptyAls(async () => {
      let seen: string | undefined;
      const { handler } = makeHandler(() => {
        seen = currentId();
        return of('ok');
      });
      const client = { handshake: { headers: {}, query: { traceId: 'q-1' } } };

      await firstValueFrom(
        new WebSocketTraceInterceptor().intercept(makeContext({}, client), handler)
      );

      expect(seen).toBe('q-1');
    });
  });

  it('rejects unsafe incoming IDs instead of propagating them', async () => {
    await emptyAls(async () => {
      let seen: string | undefined = 'sentinel';
      const { handler } = makeHandler(() => {
        seen = currentId();
        return of('ok');
      });

      await firstValueFrom(
        new WebSocketTraceInterceptor().intercept(makeContext({ traceId: 'bad id\nline' }), handler)
      );

      expect(seen).toBeUndefined();
    });
  });

  it('falls back to the current TraceContext ID', async () => {
    await emptyAls(async () => {
      let seen: string | undefined;
      const { handler } = makeHandler(() => {
        seen = currentId();
        return of('ok');
      });
      const interceptor = new WebSocketTraceInterceptor();

      await new Promise<void>((resolve, reject) => {
        TraceContext.instance.run('ambient-1', () => {
          firstValueFrom(interceptor.intercept(makeContext({}), handler)).then(
            () => resolve(),
            reject
          );
        });
      });

      expect(seen).toBe('ambient-1');
    });
  });

  it('runs the handler without generating an ID when none exists anywhere', async () => {
    await emptyAls(async () => {
      let seen: string | undefined = 'sentinel';
      const result$ = of('ok');
      const { handler, calls } = makeHandler(() => {
        seen = currentId();
        return result$;
      });

      const out = new WebSocketTraceInterceptor().intercept(
        makeContext({ event: 'ping' }),
        handler
      );

      expect(out).toBe(result$);
      expect(await firstValueFrom(out)).toBe('ok');
      expect(calls()).toBe(1);
      expect(seen).toBeUndefined();
    });
  });

  it('exposes websocket metadata in the trace context', async () => {
    await emptyAls(async () => {
      let meta: unknown;
      const { handler } = makeHandler(() => {
        meta = TraceContext.instance.storage.getStore();
        return of('ok');
      });
      const client = {
        id: 'sock-1',
        rooms: new Set(['room-a']),
        handshake: { headers: { 'x-trace-id': 'meta-1' }, query: {}, address: 'client-host' },
      };

      await firstValueFrom(
        new WebSocketTraceInterceptor().intercept(makeContext({ event: 'chat' }, client), handler)
      );

      expect(JSON.stringify(meta)).toContain('sock-1');
      expect(JSON.stringify(meta)).toContain('room-a');
      expect(JSON.stringify(meta)).toContain('chat');
    });
  });

  it('forwards values, errors and completion from the inner stream', async () => {
    await emptyAls(async () => {
      const boom = new Error('boom');
      const { handler } = makeHandler(
        () =>
          new Observable<string>((o) => {
            o.error(boom);
          })
      );
      const out = new WebSocketTraceInterceptor().intercept(
        makeContext({ traceId: 'e-1' }),
        handler
      );

      await expect(firstValueFrom(out)).rejects.toBe(boom);
    });
  });

  it('unsubscribes the inner subscription when the outer one is torn down', async () => {
    await emptyAls(async () => {
      const inner$ = new Subject<string>();
      let teardown = 0;
      const { handler } = makeHandler(
        () =>
          new Observable<string>((o) => {
            const sub = inner$.subscribe(o);
            return () => {
              teardown++;
              sub.unsubscribe();
            };
          })
      );
      const received: string[] = [];

      const sub = new WebSocketTraceInterceptor()
        .intercept(makeContext({ traceId: 'u-1' }), handler)
        .subscribe((v) => received.push(v));

      inner$.next('a');
      expect(inner$.observed).toBe(true);

      sub.unsubscribe();

      expect(teardown).toBe(1);
      expect(inner$.observed).toBe(false);
      inner$.next('b');
      expect(received).toEqual(['a']);
    });
  });
});
