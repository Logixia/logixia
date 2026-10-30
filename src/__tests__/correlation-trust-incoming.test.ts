/**
 * `trustIncoming: false` makes the correlation middleware and Fastify hook
 * ignore the incoming correlation header and always generate a new ID.
 * The default (`true`) keeps reading a valid incoming ID.
 */

import { LogixiaContext } from '../context/async-context';
import { correlationFastifyHook, correlationMiddleware } from '../correlation';

type Options = Parameters<typeof correlationMiddleware>[0];

function runMiddleware(options: Options, headers: Record<string, string>) {
  const setHeader = jest.fn();
  let seen: unknown;

  correlationMiddleware(options)({ headers }, { setHeader }, () => {
    seen = LogixiaContext.get()?.correlationId;
  });

  return { seen, setHeader };
}

function runFastifyHook(options: Options, headers: Record<string, string>) {
  const header = jest.fn();
  let seen: unknown;

  correlationFastifyHook(options)({ headers }, { header }, () => {
    seen = LogixiaContext.get()?.correlationId;
  });

  return { seen, header };
}

const incoming = { 'x-correlation-id': 'incoming-abc-123' };

describe('correlationMiddleware trustIncoming', () => {
  it('reads a valid incoming ID by default', () => {
    expect(runMiddleware({}, incoming).seen).toBe('incoming-abc-123');
  });

  it('reads a valid incoming ID when trustIncoming is true', () => {
    expect(runMiddleware({ trustIncoming: true }, incoming).seen).toBe('incoming-abc-123');
  });

  it('ignores the incoming ID and generates one when trustIncoming is false', () => {
    const generate = jest.fn(() => 'generated-id');
    const { seen, setHeader } = runMiddleware(
      { header: 'X-Correlation-ID', trustIncoming: false, generate },
      incoming
    );

    expect(seen).toBe('generated-id');
    expect(generate).toHaveBeenCalledTimes(1);
    expect(setHeader).toHaveBeenCalledWith('X-Correlation-ID', 'generated-id');
  });
});

describe('correlationFastifyHook trustIncoming', () => {
  it('reads a valid incoming ID by default, with a mixed-case header option', () => {
    expect(runFastifyHook({ header: 'X-Correlation-ID' }, incoming).seen).toBe('incoming-abc-123');
  });

  it('ignores the incoming ID and generates one when trustIncoming is false', () => {
    const generate = jest.fn(() => 'generated-id');
    const { seen, header } = runFastifyHook({ trustIncoming: false, generate }, incoming);

    expect(seen).toBe('generated-id');
    expect(header).toHaveBeenCalledWith('x-correlation-id', 'generated-id');
  });

  it('replaces an over-long or newline-containing incoming ID', () => {
    const generate = (): string => 'generated-id';

    expect(runFastifyHook({ generate }, { 'x-correlation-id': 'a'.repeat(129) }).seen).toBe(
      'generated-id'
    );
    expect(runFastifyHook({ generate }, { 'x-correlation-id': 'abc\ndef' }).seen).toBe(
      'generated-id'
    );
  });
});
