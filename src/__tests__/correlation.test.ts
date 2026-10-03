import { LogixiaContext } from '../context/async-context';
import {
  buildKafkaCorrelationHeaders,
  childFromRequest,
  correlationFastifyHook,
  correlationFetch,
  correlationMiddleware,
  createCorrelationAxiosInterceptor,
  extractMessageCorrelationId,
  generateCorrelationId,
  getCurrentCorrelationId,
  withCorrelationId,
} from '../correlation';

describe('generateCorrelationId', () => {
  it('returns a UUID shaped string', () => {
    const id = generateCorrelationId();
    expect(typeof id).toBe('string');
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it('generates distinct values across consecutive invocations', () => {
    const first = generateCorrelationId();
    const second = generateCorrelationId();
    expect(first).not.toBe(second);
  });
});

describe('getCurrentCorrelationId and withCorrelationId', () => {
  it('returns undefined outside any context scope', () => {
    expect(getCurrentCorrelationId()).toBeUndefined();
  });

  it('provides the correlation ID within the callback and undefined outside', () => {
    const specifiedId = 'test-correlation-abc';
    let observedInside: string | undefined;

    const returnValue = withCorrelationId(specifiedId, () => {
      observedInside = getCurrentCorrelationId();
      return 123;
    });

    expect(returnValue).toBe(123);
    expect(observedInside).toBe(specifiedId);
    expect(getCurrentCorrelationId()).toBeUndefined();
  });

  it('generates a new correlation ID when none is provided', () => {
    let observedInside: string | undefined;

    withCorrelationId(undefined, () => {
      observedInside = getCurrentCorrelationId();
    });

    expect(typeof observedInside).toBe('string');
    expect(observedInside).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it('supports async callbacks within withCorrelationId', async () => {
    const specifiedId = 'async-correlation-xyz';
    const result = await withCorrelationId(specifiedId, async () => {
      await Promise.resolve();
      return getCurrentCorrelationId();
    });

    expect(result).toBe(specifiedId);
    expect(getCurrentCorrelationId()).toBeUndefined();
  });
});

describe('correlationMiddleware', () => {
  it('reuses the incoming correlation header when present', () => {
    const middleware = correlationMiddleware();
    const req = {
      headers: {
        'x-correlation-id': 'incoming-id-123',
      },
    };
    const setHeaderMock = jest.fn();
    const res = { setHeader: setHeaderMock };
    const nextMock = jest.fn(() => {
      expect(getCurrentCorrelationId()).toBe('incoming-id-123');
    });

    middleware(req, res, nextMock);

    expect(nextMock).toHaveBeenCalledTimes(1);
    expect(setHeaderMock).toHaveBeenCalledWith('x-correlation-id', 'incoming-id-123');
  });

  it('invokes the generate option when the correlation header is absent', () => {
    const customGenerator = jest.fn(() => 'custom-generated-id');
    const middleware = correlationMiddleware({ generate: customGenerator });
    const req = { headers: {} };
    const setHeaderMock = jest.fn();
    const res = { setHeader: setHeaderMock };
    let capturedId: string | undefined;

    middleware(req, res, () => {
      capturedId = getCurrentCorrelationId();
    });

    expect(customGenerator).toHaveBeenCalledTimes(1);
    expect(capturedId).toBe('custom-generated-id');
    expect(setHeaderMock).toHaveBeenCalledWith('x-correlation-id', 'custom-generated-id');
  });

  it('skips setting the response header when setResponseHeader is false', () => {
    const middleware = correlationMiddleware({ setResponseHeader: false });
    const req = {
      headers: {
        'x-correlation-id': 'no-response-header-id',
      },
    };
    const setHeaderMock = jest.fn();
    const res = { setHeader: setHeaderMock };

    middleware(req, res, () => {});

    expect(setHeaderMock).not.toHaveBeenCalled();
  });

  it('captures origin service header when present', () => {
    const middleware = correlationMiddleware();
    const req = {
      headers: {
        'x-correlation-id': 'origin-test-id',
        'x-origin-service': 'billing-service',
      },
    };
    const res = { setHeader: jest.fn() };
    let contextOriginService: unknown;

    middleware(req, res, () => {
      contextOriginService = LogixiaContext.get()?.originService;
    });

    expect(contextOriginService).toBe('billing-service');
  });

  it('respects custom header configuration', () => {
    const middleware = correlationMiddleware({
      header: 'x-request-id',
      originServiceHeader: 'x-source-app',
    });
    const req = {
      headers: {
        'x-request-id': 'custom-req-header-id',
        'x-source-app': 'gateway-app',
      },
    };
    const setHeaderMock = jest.fn();
    const res = { setHeader: setHeaderMock };
    let capturedContext: ReturnType<typeof LogixiaContext.get>;

    middleware(req, res, () => {
      capturedContext = LogixiaContext.get();
    });

    expect(setHeaderMock).toHaveBeenCalledWith('x-request-id', 'custom-req-header-id');
    expect(capturedContext?.correlationId).toBe('custom-req-header-id');
    expect(capturedContext?.originService).toBe('gateway-app');
  });
});

describe('correlationFastifyHook', () => {
  it('reuses the incoming correlation header when present', () => {
    const hook = correlationFastifyHook();
    const request = {
      headers: {
        'x-correlation-id': 'fastify-incoming-id',
      },
    };
    const headerMock = jest.fn();
    const reply = { header: headerMock };
    const doneMock = jest.fn(() => {
      expect(getCurrentCorrelationId()).toBe('fastify-incoming-id');
    });

    hook(request, reply, doneMock);

    expect(doneMock).toHaveBeenCalledTimes(1);
    expect(headerMock).toHaveBeenCalledWith('x-correlation-id', 'fastify-incoming-id');
  });

  it('invokes the generate option when the header is absent', () => {
    const customGenerator = jest.fn(() => 'fastify-generated-id');
    const hook = correlationFastifyHook({ generate: customGenerator });
    const request = { headers: {} };
    const headerMock = jest.fn();
    const reply = { header: headerMock };
    let capturedId: string | undefined;

    hook(request, reply, () => {
      capturedId = getCurrentCorrelationId();
    });

    expect(customGenerator).toHaveBeenCalledTimes(1);
    expect(capturedId).toBe('fastify-generated-id');
    expect(headerMock).toHaveBeenCalledWith('x-correlation-id', 'fastify-generated-id');
  });

  it('skips setting reply header when setResponseHeader is false', () => {
    const hook = correlationFastifyHook({ setResponseHeader: false });
    const request = {
      headers: {
        'x-correlation-id': 'suppressed-reply-id',
      },
    };
    const headerMock = jest.fn();
    const reply = { header: headerMock };

    hook(request, reply, () => {});

    expect(headerMock).not.toHaveBeenCalled();
  });

  it('captures origin service header in fastify context', () => {
    const hook = correlationFastifyHook();
    const request = {
      headers: {
        'x-correlation-id': 'fastify-origin-id',
        'x-origin-service': 'auth-service',
      },
    };
    const reply = { header: jest.fn() };
    let contextOriginService: unknown;

    hook(request, reply, () => {
      contextOriginService = LogixiaContext.get()?.originService;
    });

    expect(contextOriginService).toBe('auth-service');
  });
});

describe('createCorrelationAxiosInterceptor', () => {
  it('adds correlation header within withCorrelationId scope', () => {
    const interceptor = createCorrelationAxiosInterceptor();
    const config = { headers: {} };

    const modified = withCorrelationId('axios-scope-id', () => interceptor(config));

    expect((modified['headers'] as Record<string, unknown>)['x-correlation-id']).toBe(
      'axios-scope-id'
    );
  });

  it('leaves configuration untouched when outside correlation scope', () => {
    const interceptor = createCorrelationAxiosInterceptor();
    const config = { headers: { Authorization: 'Bearer token123' } };

    const result = interceptor(config);

    expect(result).toBe(config);
    expect((result['headers'] as Record<string, unknown>)['x-correlation-id']).toBeUndefined();
  });

  it('does not overwrite header already present on config', () => {
    const interceptor = createCorrelationAxiosInterceptor();
    const config = {
      headers: {
        'x-correlation-id': 'existing-axios-header',
      },
    };

    const result = withCorrelationId('scoped-id', () => interceptor(config));

    expect((result['headers'] as Record<string, unknown>)['x-correlation-id']).toBe(
      'existing-axios-header'
    );
  });

  it('respects custom header option in axios interceptor', () => {
    const interceptor = createCorrelationAxiosInterceptor({ header: 'x-custom-trace' });
    const config = { headers: {} };

    const result = withCorrelationId('custom-trace-id', () => interceptor(config));

    expect((result['headers'] as Record<string, unknown>)['x-custom-trace']).toBe(
      'custom-trace-id'
    );
  });
});

describe('childFromRequest', () => {
  it('passes correlationId, method, url, userAgent and ip to logger.child', () => {
    const childMock = jest.fn((ctx: Record<string, unknown>) => ({ ...ctx, isChild: true }));
    const fakeLogger = { child: childMock };

    const req = {
      method: 'POST',
      url: '/api/v1/orders',
      headers: {
        'x-correlation-id': 'req-corr-id',
        'user-agent': 'JestTestClient/1.0',
        'x-forwarded-for': '203.0.113.195, 70.41.3.18',
      },
    };

    childFromRequest(req, fakeLogger);

    expect(childMock).toHaveBeenCalledTimes(1);
    expect(childMock).toHaveBeenCalledWith({
      correlationId: 'req-corr-id',
      method: 'POST',
      url: '/api/v1/orders',
      userAgent: 'JestTestClient/1.0',
      ip: '203.0.113.195',
    });
  });

  it('falls back to socket remoteAddress when x-forwarded-for is missing', () => {
    const childMock = jest.fn((ctx: Record<string, unknown>) => ({ ...ctx }));
    const fakeLogger = { child: childMock };

    const req = {
      method: 'GET',
      originalUrl: '/fallback-url',
      headers: {},
      socket: { remoteAddress: '198.51.100.50' },
    };

    childFromRequest(req, fakeLogger);

    expect(childMock).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'GET',
        url: '/fallback-url',
        ip: '198.51.100.50',
      })
    );
  });

  it('inherits correlation ID from active context when request header is absent', () => {
    const childMock = jest.fn((ctx: Record<string, unknown>) => ({ ...ctx }));
    const fakeLogger = { child: childMock };

    const req = {
      method: 'GET',
      url: '/test',
      headers: {},
    };

    withCorrelationId('context-inherited-id', () => {
      childFromRequest(req, fakeLogger);
    });

    expect(childMock).toHaveBeenCalledWith(
      expect.objectContaining({
        correlationId: 'context-inherited-id',
      })
    );
  });
});

describe('extractMessageCorrelationId', () => {
  it('extracts correlation ID from Kafka headers as Buffer', () => {
    const message = {
      headers: {
        'x-correlation-id': Buffer.from('kafka-buffer-id-1', 'utf8'),
      },
    };
    expect(extractMessageCorrelationId(message)).toBe('kafka-buffer-id-1');
  });

  it('extracts correlation ID from Kafka headers as string', () => {
    const message1 = { headers: { 'x-correlation-id': 'kafka-string-id-1' } };
    const message2 = { headers: { correlationId: 'kafka-string-id-2' } };
    const message3 = { headers: { correlation_id: 'kafka-string-id-3' } };

    expect(extractMessageCorrelationId(message1)).toBe('kafka-string-id-1');
    expect(extractMessageCorrelationId(message2)).toBe('kafka-string-id-2');
    expect(extractMessageCorrelationId(message3)).toBe('kafka-string-id-3');
  });

  it('extracts correlation ID from SQS MessageAttributes', () => {
    const message1 = {
      MessageAttributes: {
        'x-correlation-id': { StringValue: 'sqs-id-1' },
      },
    };
    const message2 = {
      MessageAttributes: {
        correlationId: { StringValue: 'sqs-id-2' },
      },
    };
    const message3 = {
      MessageAttributes: {
        correlation_id: { StringValue: 'sqs-id-3' },
      },
    };

    expect(extractMessageCorrelationId(message1)).toBe('sqs-id-1');
    expect(extractMessageCorrelationId(message2)).toBe('sqs-id-2');
    expect(extractMessageCorrelationId(message3)).toBe('sqs-id-3');
  });

  it('extracts correlation ID from plain envelope properties', () => {
    expect(extractMessageCorrelationId({ correlationId: 'envelope-id-1' })).toBe('envelope-id-1');
    expect(extractMessageCorrelationId({ correlation_id: 'envelope-id-2' })).toBe('envelope-id-2');
  });

  it('returns undefined when no correlation ID can be found', () => {
    expect(extractMessageCorrelationId({})).toBeUndefined();
    expect(extractMessageCorrelationId({ headers: {} })).toBeUndefined();
    expect(extractMessageCorrelationId({ MessageAttributes: {} })).toBeUndefined();
  });
});

describe('buildKafkaCorrelationHeaders', () => {
  it('returns correlation and trace headers when context is active', () => {
    let headers: Record<string, string> | undefined;

    LogixiaContext.run({ correlationId: 'kafka-corr-id', traceId: 'kafka-trace-id' }, () => {
      headers = buildKafkaCorrelationHeaders();
    });

    expect(headers).toEqual({
      'x-correlation-id': 'kafka-corr-id',
      'x-trace-id': 'kafka-trace-id',
    });
  });

  it('returns empty object when outside any context', () => {
    const headers = buildKafkaCorrelationHeaders();
    expect(headers).toEqual({});
  });
});

describe('correlationFetch', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('injects correlation header when context is active', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await withCorrelationId('fetch-corr-id', async () => {
      await correlationFetch('https://example.com/api', { method: 'GET' });
    });

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/api', {
      method: 'GET',
      headers: {
        'x-correlation-id': 'fetch-corr-id',
      },
    });
  });

  it('preserves existing header when caller already provided it', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await withCorrelationId('fetch-corr-id', async () => {
      await correlationFetch('https://example.com/api', {
        headers: { 'x-correlation-id': 'pre-existing-id' },
      });
    });

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/api', {
      headers: {
        'x-correlation-id': 'pre-existing-id',
      },
    });
  });
});
