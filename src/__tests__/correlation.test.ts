import { LogixiaContext } from '../context/async-context';
import {
  buildKafkaCorrelationHeaders,
  childFromRequest,
  correlationFastifyHook,
  correlationMiddleware,
  createCorrelationAxiosInterceptor,
  extractMessageCorrelationId,
  generateCorrelationId,
  getCurrentCorrelationId,
  withCorrelationId,
} from '../correlation';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe('correlation helpers', () => {
  describe('getCurrentCorrelationId and withCorrelationId', () => {
    it('returns the scoped ID only while the callback is running', () => {
      expect(getCurrentCorrelationId()).toBeUndefined();
      const seen = withCorrelationId('abc', () => getCurrentCorrelationId());
      expect(seen).toBe('abc');
      expect(getCurrentCorrelationId()).toBeUndefined();
    });

    it('generates an ID when the supplied ID is undefined', () => {
      const seen = withCorrelationId(undefined, () => getCurrentCorrelationId());
      expect(seen).toMatch(UUID_V4);
      expect(getCurrentCorrelationId()).toBeUndefined();
    });
  });

  describe('correlationMiddleware', () => {
    it('reuses a valid incoming ID and exposes it in next', () => {
      const generate = jest.fn(() => 'generated-id');
      const setHeader = jest.fn();
      const next = jest.fn(() => expect(getCurrentCorrelationId()).toBe('incoming-id'));

      correlationMiddleware({ generate })(
        { headers: { 'x-correlation-id': 'incoming-id' } },
        { setHeader },
        next
      );

      expect(generate).not.toHaveBeenCalled();
      expect(setHeader).toHaveBeenCalledWith('x-correlation-id', 'incoming-id');
      expect(next).toHaveBeenCalledTimes(1);
      expect(getCurrentCorrelationId()).toBeUndefined();
    });

    it('uses generate and writes the response header when the request has no ID', () => {
      const generate = jest.fn(() => 'new-id');
      const setHeader = jest.fn();
      const next = jest.fn(() => expect(getCurrentCorrelationId()).toBe('new-id'));

      correlationMiddleware({ generate })({ headers: {} }, { setHeader }, next);

      expect(generate).toHaveBeenCalledTimes(1);
      expect(setHeader).toHaveBeenCalledWith('x-correlation-id', 'new-id');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('can omit the response header when setResponseHeader is false', () => {
      const setHeader = jest.fn();
      const next = jest.fn();

      correlationMiddleware({ generate: () => 'new-id', setResponseHeader: false })(
        { headers: {} },
        { setHeader },
        next
      );

      expect(setHeader).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  describe('correlationFastifyHook', () => {
    it('reuses a valid incoming ID and exposes it in done', () => {
      const generate = jest.fn(() => 'generated-id');
      const header = jest.fn();
      const done = jest.fn(() => expect(getCurrentCorrelationId()).toBe('incoming-id'));

      correlationFastifyHook({ generate })(
        { headers: { 'x-correlation-id': 'incoming-id' } },
        { header },
        done
      );

      expect(generate).not.toHaveBeenCalled();
      expect(header).toHaveBeenCalledWith('x-correlation-id', 'incoming-id');
      expect(done).toHaveBeenCalledTimes(1);
      expect(getCurrentCorrelationId()).toBeUndefined();
    });

    it('uses generate and writes the reply header when the request has no ID', () => {
      const generate = jest.fn(() => 'fastify-id');
      const header = jest.fn();
      const done = jest.fn(() => expect(getCurrentCorrelationId()).toBe('fastify-id'));

      correlationFastifyHook({ generate })({ headers: {} }, { header }, done);

      expect(generate).toHaveBeenCalledTimes(1);
      expect(header).toHaveBeenCalledWith('x-correlation-id', 'fastify-id');
      expect(done).toHaveBeenCalledTimes(1);
    });

    it('can omit the reply header when setResponseHeader is false', () => {
      const header = jest.fn();
      const done = jest.fn();

      correlationFastifyHook({ generate: () => 'fastify-id', setResponseHeader: false })(
        { headers: {} },
        { header },
        done
      );

      expect(header).not.toHaveBeenCalled();
      expect(done).toHaveBeenCalledTimes(1);
    });
  });

  describe('createCorrelationAxiosInterceptor', () => {
    it('adds the active correlation ID to request headers', () => {
      const intercept = createCorrelationAxiosInterceptor();
      const original = { headers: { authorization: 'Bearer token' } };

      const result = withCorrelationId('axios-id', () => intercept(original));

      expect(result).toEqual({
        headers: { authorization: 'Bearer token', 'x-correlation-id': 'axios-id' },
      });
      expect(original.headers).toEqual({
        authorization: 'Bearer token',
        'x-correlation-id': 'axios-id',
      });
    });

    it('leaves config alone outside a correlation scope', () => {
      const intercept = createCorrelationAxiosInterceptor();
      const config = { headers: { authorization: 'Bearer token' } };

      expect(intercept(config)).toBe(config);
      expect(config.headers).toEqual({ authorization: 'Bearer token' });
    });

    it('does not overwrite a caller-supplied correlation header', () => {
      const intercept = createCorrelationAxiosInterceptor();
      const config = { headers: { 'x-correlation-id': 'caller-id' } };

      const result = withCorrelationId('axios-id', () => intercept(config));

      expect(result.headers).toEqual({ 'x-correlation-id': 'caller-id' });
    });
  });

  describe('childFromRequest', () => {
    it('passes request metadata to logger.child and ignores X-Forwarded-For by default', () => {
      const child = { child: jest.fn() };
      child.child.mockReturnValue(child);

      const result = childFromRequest(
        {
          headers: {
            'x-correlation-id': 'request-id',
            'user-agent': 'test-agent',
            'x-forwarded-for': ' 203.0.113.7, 10.0.0.2',
          },
          method: 'POST',
          url: '/orders',
          socket: { remoteAddress: '203.0.113.9' },
        },
        child
      );

      expect(result).toBe(child);
      expect(child.child).toHaveBeenCalledWith({
        correlationId: 'request-id',
        method: 'POST',
        url: '/orders',
        userAgent: 'test-agent',
        ip: '203.0.113.9',
      });
    });

    it('uses the first forwarded IP only with trustProxy', () => {
      const child = { child: jest.fn() };
      child.child.mockReturnValue(child);
      childFromRequest(
        { headers: { 'x-forwarded-for': ' 203.0.113.7, 10.0.0.2' }, ip: '203.0.113.9' },
        child,
        { trustProxy: true }
      );
      expect(child.child.mock.calls[0]![0]).toMatchObject({ ip: '203.0.113.7' });
    });

    it('caps the user agent length', () => {
      const child = { child: jest.fn() };
      childFromRequest({ headers: { 'user-agent': 'a'.repeat(5000) } }, child);
      expect(child.child.mock.calls[0]![0].userAgent).toHaveLength(512);
    });

    it('passes a bindings object to pino-like loggers and does not swallow their errors', () => {
      const pinoLike = { child: jest.fn((b: unknown) => ({ child: jest.fn(), b }) as never) };
      childFromRequest({ headers: {}, method: 'GET' }, pinoLike as never);
      expect(pinoLike.child.mock.calls[0]![0]).toMatchObject({ method: 'GET' });

      const broken = {
        child: jest.fn(() => {
          throw new TypeError('pino internal');
        }),
      };
      expect(() => childFromRequest({ headers: {} }, broken as never)).toThrow('pino internal');
      expect(broken.child).toHaveBeenCalledTimes(1);
    });

    it('uses child(context, data) for the mock logger', async () => {
      const { createMockLogger } = await import('../testing/mock-logger');
      const mock = createMockLogger().logger;
      const spy = jest.spyOn(mock, 'child');
      childFromRequest({ headers: {}, method: 'GET' }, mock as never);
      expect(spy.mock.calls[0]![0]).toBe('request');
      expect(spy.mock.calls[0]![1]).toMatchObject({ method: 'GET' });
    });

    it('uses child(context, data) for LogixiaLoggerService', async () => {
      const { LogixiaLoggerService } = await import('../core/logitron-nestjs.service');
      const svc = new LogixiaLoggerService({
        appName: 'a',
        format: { json: false, colorize: false },
      } as never);
      const spy = jest.spyOn(svc, 'child');
      expect(() => childFromRequest({ headers: {}, method: 'GET' }, svc as never)).not.toThrow();
      expect(spy.mock.calls[0]![0]).toBe('request');
    });

    it('works with a real LogixiaLogger', async () => {
      const { createLogger } = await import('../index');
      const logger = createLogger({ appName: 'a', format: { json: false, colorize: false } });
      expect(() => childFromRequest({ headers: {}, method: 'GET' }, logger as never)).not.toThrow();
    });
  });

  describe('incoming id validation', () => {
    it('drops unsafe message ids and origin service values', () => {
      expect(
        extractMessageCorrelationId({ headers: { 'x-correlation-id': 'a\r\nb' } })
      ).toBeUndefined();
      expect(
        extractMessageCorrelationId({
          MessageAttributes: { correlationId: { StringValue: 'x'.repeat(200) } },
        })
      ).toBeUndefined();
      expect(extractMessageCorrelationId({ correlationId: '\u001b[2J' })).toBeUndefined();
    });

    it('ignores an invalid x-origin-service header', () => {
      const mw = correlationMiddleware();
      let seen: Record<string, unknown> | undefined;
      mw({ headers: { 'x-origin-service': 'evil\u001b[2J' } }, {}, () => {
        seen = LogixiaContext.get();
      });
      expect(seen?.originService).toBeUndefined();
    });
  });

  describe('extractMessageCorrelationId', () => {
    it('reads Kafka correlation headers as a Buffer or string', () => {
      expect(
        extractMessageCorrelationId({ headers: { 'x-correlation-id': Buffer.from('kafka-id') } })
      ).toBe('kafka-id');
      expect(extractMessageCorrelationId({ headers: { correlation_id: 'string-id' } })).toBe(
        'string-id'
      );
    });

    it('reads SQS message attributes', () => {
      expect(
        extractMessageCorrelationId({
          MessageAttributes: { 'x-correlation-id': { StringValue: 'sqs-id' } },
        })
      ).toBe('sqs-id');
    });

    it('reads a plain correlationId envelope', () => {
      expect(extractMessageCorrelationId({ correlationId: 'envelope-id' })).toBe('envelope-id');
    });

    it('returns undefined when the message has no supported ID', () => {
      expect(extractMessageCorrelationId({ value: 'no-id' })).toBeUndefined();
    });
  });

  describe('buildKafkaCorrelationHeaders', () => {
    it('maps correlationId and traceId from the active context', () => {
      const headers = LogixiaContext.run(
        { correlationId: 'correlation-id', traceId: 'trace-id' },
        buildKafkaCorrelationHeaders
      );

      expect(headers).toEqual({
        'x-correlation-id': 'correlation-id',
        'x-trace-id': 'trace-id',
      });
    });

    it('returns an empty object outside a context', () => {
      expect(buildKafkaCorrelationHeaders()).toEqual({});
    });
  });

  describe('generateCorrelationId', () => {
    it('returns a UUID-shaped string', () => {
      expect(generateCorrelationId()).toMatch(UUID_V4);
    });

    it('returns a different ID for separate calls', () => {
      expect(generateCorrelationId()).not.toBe(generateCorrelationId());
    });
  });
});
