import { isLogixiaException, LogixiaException } from '../exception';

describe('LogixiaException', () => {
  // ── Construction ───────────────────────────────────────────────────────────

  it('stores all required fields', () => {
    const err = new LogixiaException({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Invalid email or password.',
    });

    expect(err.errorCode).toBe('PE-AUTH-001');
    expect(err.errorType).toBe('authentication_error');
    expect(err.httpStatus).toBe(401);
    expect(err.message).toBe('Invalid email or password.');
    expect(err.name).toBe('LogixiaException');
  });

  it('stores optional param', () => {
    const err = new LogixiaException({
      code: 'PE-USR-002',
      type: 'conflict_error',
      httpStatus: 409,
      message: 'Email already in use.',
      param: 'email',
    });

    expect(err.param).toBe('email');
  });

  it('stores optional details array', () => {
    const details = [
      { field: 'email', message: 'must be a valid email', code: 'invalid_format' },
      { field: 'password', message: 'required', code: 'required' },
    ];
    const err = new LogixiaException({
      code: 'PE-VAL-001',
      type: 'validation_error',
      httpStatus: 400,
      message: 'Validation failed.',
      details,
    });

    expect(err.details).toEqual(details);
  });

  it('stores optional docUrl', () => {
    const err = new LogixiaException({
      code: 'PE-AUTH-002',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Session expired.',
      docUrl: 'https://docs.example.com/errors/PE-AUTH-002',
    });

    expect(err.docUrl).toBe('https://docs.example.com/errors/PE-AUTH-002');
  });

  it('stores metadata (not for response, only logging)', () => {
    const err = new LogixiaException({
      code: 'PE-AUTH-005',
      type: 'authentication_error',
      httpStatus: 423,
      message: 'Account locked.',
      metadata: { userId: 'u_abc', attemptCount: 5 },
    });

    expect(err.metadata).toEqual({ userId: 'u_abc', attemptCount: 5 });
  });

  it('chains cause via ES 2022 Error options', () => {
    const root = new Error('DB timeout');
    const err = new LogixiaException({
      code: 'PE-DB-006',
      type: 'server_error',
      httpStatus: 503,
      message: 'Database connection error.',
      cause: root,
    });

    // ES 2022 cause is set on the standard Error
    expect((err as Error & { cause?: unknown }).cause).toBe(root);
  });

  it('has correct prototype chain (instanceof works after transpilation)', () => {
    const err = new LogixiaException({
      code: 'PE-INT-001',
      type: 'server_error',
      httpStatus: 500,
      message: 'Unexpected error.',
    });

    expect(err).toBeInstanceOf(LogixiaException);
    expect(err).toBeInstanceOf(Error);
  });

  it('has undefined optional fields when not set', () => {
    const err = new LogixiaException({
      code: 'PE-INT-001',
      type: 'server_error',
      httpStatus: 500,
      message: 'Unexpected error.',
    });

    expect(err.param).toBeUndefined();
    expect(err.details).toBeUndefined();
    expect(err.docUrl).toBeUndefined();
    expect(err.metadata).toBeUndefined();
  });

  // ── Type-level generics (compile-time only; run-time smoke tests) ──────────

  it('accepts typed code and type generics', () => {
    type AppCode = 'PE-AUTH-001' | 'PE-VAL-001';
    type AppType = 'authentication_error' | 'validation_error';

    const err = new LogixiaException<AppCode, AppType>({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Invalid credentials.',
    });

    // These should be narrowed to the union types at compile time
    const code: AppCode = err.errorCode;
    const type: AppType = err.errorType;

    expect(code).toBe('PE-AUTH-001');
    expect(type).toBe('authentication_error');
  });
});

// ── isLogixiaException ────────────────────────────────────────────────────────

describe('isLogixiaException', () => {
  it('returns true for a LogixiaException', () => {
    const err = new LogixiaException({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Invalid credentials.',
    });

    expect(isLogixiaException(err)).toBe(true);
  });

  it('returns false for a plain Error', () => {
    expect(isLogixiaException(new Error('oops'))).toBe(false);
  });

  it('returns false for null', () => {
    expect(isLogixiaException(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isLogixiaException()).toBe(false);
  });

  it('returns false for a plain object', () => {
    expect(isLogixiaException({ code: 'PE-AUTH-001', message: 'x' })).toBe(false);
  });

  it('returns false for a string', () => {
    expect(isLogixiaException('PE-AUTH-001')).toBe(false);
  });
});
