import { ErrorResponseBuilder, generateTraceId } from '../builder';
import { LogixiaException } from '../exception';

// ── generateTraceId ───────────────────────────────────────────────────────────

describe('generateTraceId', () => {
  it('returns a UUID v4 string', () => {
    expect(generateTraceId()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 20 }, () => generateTraceId()));
    expect(ids.size).toBe(20);
  });
});

// ── ErrorResponseBuilder — LogixiaException path ──────────────────────────────

describe('ErrorResponseBuilder.build — LogixiaException', () => {
  const baseOpts = {
    code: 'PE-AUTH-001',
    type: 'authentication_error',
    httpStatus: 401,
    message: 'Invalid email or password.',
  } as const;

  it('returns success: false', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api/auth' });
    expect(response.success).toBe(false);
  });

  it('maps errorCode → error.code', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api/auth' });
    expect(response.error.code).toBe('PE-AUTH-001');
  });

  it('maps errorType → error.type', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api/auth' });
    expect(response.error.type).toBe('authentication_error');
  });

  it('maps message → error.message', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api/auth' });
    expect(response.error.message).toBe('Invalid email or password.');
  });

  it('returns the correct httpStatus', () => {
    const ex = new LogixiaException(baseOpts);
    const { httpStatus } = ErrorResponseBuilder.build({ exception: ex, path: '/api/auth' });
    expect(httpStatus).toBe(401);
  });

  it('echoes meta.path', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api/v1/auth/login' });
    expect(response.meta.path).toBe('/api/v1/auth/login');
  });

  it('echoes meta.status equal to httpStatus', () => {
    const ex = new LogixiaException(baseOpts);
    const { response, httpStatus } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(response.meta.status).toBe(httpStatus);
  });

  it('sets meta.timestamp to a valid ISO string', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(() => new Date(response.meta.timestamp).toISOString()).not.toThrow();
  });

  it('uses the provided traceId', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({
      exception: ex,
      path: '/p',
      traceId: 'custom-trace-123',
    });
    expect(response.meta.trace_id).toBe('custom-trace-123');
  });

  it('auto-generates a traceId when not provided', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(response.meta.trace_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it('includes param when set', () => {
    const ex = new LogixiaException({ ...baseOpts, param: 'email' });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(response.error.param).toBe('email');
  });

  it('omits param when not set', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect('param' in response.error).toBe(false);
  });

  it('includes details when set and non-empty', () => {
    const details = [{ field: 'email', message: 'invalid', code: 'invalid_format' }];
    const ex = new LogixiaException({ ...baseOpts, details });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(response.error.details).toEqual(details);
  });

  it('omits details when empty array', () => {
    const ex = new LogixiaException({ ...baseOpts, details: [] });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect('details' in response.error).toBe(false);
  });

  it('includes doc_url when docUrl is set', () => {
    const ex = new LogixiaException({
      ...baseOpts,
      docUrl: 'https://docs.example.com/errors/PE-AUTH-001',
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(response.error.doc_url).toBe('https://docs.example.com/errors/PE-AUTH-001');
  });

  it('populates debug.service when service is provided', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({
      exception: ex,
      path: '/p',
      service: 'gatekeeper',
    });
    expect(response.debug?.service).toBe('gatekeeper');
  });

  it('populates debug.duration_ms when startTime is provided', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({
      exception: ex,
      path: '/p',
      startTime: Date.now() - 50,
    });
    expect(typeof response.debug?.duration_ms).toBe('number');
    expect(response.debug?.duration_ms ?? 0).toBeGreaterThanOrEqual(0);
  });

  it('populates debug.stack for exceptions with a stack', () => {
    const ex = new LogixiaException(baseOpts);
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(response.debug?.stack).toBeDefined();
  });

  it('populates debug.cause when exception has a cause', () => {
    const root = new Error('root cause message');
    const ex = new LogixiaException({ ...baseOpts, cause: root });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/p' });
    expect(response.debug?.cause).toBe('root cause message');
  });
});

// ── ErrorResponseBuilder — NestJS HttpException duck-type path ────────────────

describe('ErrorResponseBuilder.build — HttpException (duck-typed)', () => {
  function makeHttpEx(status: number, exResponse: unknown) {
    return {
      getStatus: () => status,
      getResponse: () => exResponse,
      message: 'Fallback message',
      stack: 'Error\n  at test',
    };
  }

  it('extracts status correctly', () => {
    const { httpStatus } = ErrorResponseBuilder.build({
      exception: makeHttpEx(403, 'Forbidden'),
      path: '/p',
    });
    expect(httpStatus).toBe(403);
  });

  it('maps status 400 → api_error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(400, 'Bad Request'),
      path: '/p',
    });
    expect(response.error.type).toBe('api_error');
  });

  it('maps status 401 → authentication_error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(401, 'Unauthorized'),
      path: '/p',
    });
    expect(response.error.type).toBe('authentication_error');
  });

  it('maps status 404 → not_found_error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(404, 'Not Found'),
      path: '/p',
    });
    expect(response.error.type).toBe('not_found_error');
  });

  it('maps status 429 → rate_limit_error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(429, 'Too Many Requests'),
      path: '/p',
    });
    expect(response.error.type).toBe('rate_limit_error');
  });

  it('maps status 500 → server_error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(500, 'Internal Server Error'),
      path: '/p',
    });
    expect(response.error.type).toBe('server_error');
  });

  it('uses HTTP_<status> as error code', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(403, 'Forbidden'),
      path: '/p',
    });
    expect(response.error.code).toBe('HTTP_403');
  });

  it('extracts message from string getResponse', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(403, 'Custom forbidden message'),
      path: '/p',
    });
    expect(response.error.message).toBe('Custom forbidden message');
  });

  it('extracts message from object getResponse { message }', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(400, { statusCode: 400, message: 'Nested message' }),
      path: '/p',
    });
    expect(response.error.message).toBe('Nested message');
  });

  it('joins array message from NestJS ValidationPipe', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(400, { message: ['email must be valid', 'password required'] }),
      path: '/p',
    });
    expect(response.error.message).toBe('email must be valid, password required');
  });

  it('returns success: false', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: makeHttpEx(404, 'not found'),
      path: '/p',
    });
    expect(response.success).toBe(false);
  });
});

// ── ErrorResponseBuilder — Unknown / plain Error path ────────────────────────

describe('ErrorResponseBuilder.build — unknown exception', () => {
  it('returns 500 for a plain Error', () => {
    const { httpStatus } = ErrorResponseBuilder.build({
      exception: new Error('boom'),
      path: '/p',
    });
    expect(httpStatus).toBe(500);
  });

  it('returns server_error type', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('boom'),
      path: '/p',
    });
    expect(response.error.type).toBe('server_error');
  });

  it('returns INTERNAL_SERVER_ERROR code', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('boom'),
      path: '/p',
    });
    expect(response.error.code).toBe('INTERNAL_SERVER_ERROR');
  });

  it('hides original error message (safe generic message)', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('sensitive db password in message'),
      path: '/p',
    });
    expect(response.error.message).toBe('An unexpected error occurred.');
  });

  it('handles thrown strings', () => {
    const { httpStatus, response } = ErrorResponseBuilder.build({
      exception: 'something went wrong',
      path: '/p',
    });
    expect(httpStatus).toBe(500);
    expect(response.error.type).toBe('server_error');
  });

  it('handles thrown null', () => {
    const { httpStatus } = ErrorResponseBuilder.build({ exception: null, path: '/p' });
    expect(httpStatus).toBe(500);
  });

  it('populates debug.stack for plain Error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('boom'),
      path: '/p',
    });
    expect(response.debug?.stack).toBeDefined();
  });
});
