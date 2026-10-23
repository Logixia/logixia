import { LogixiaLogger } from '../logitron-logger';

function makeLogger(sampling: object) {
  const logger = new LogixiaLogger({
    appName: 'TestApp',
    environment: 'development',
    format: { timestamp: false, colorize: false, json: false },
    traceId: true,
    silent: false,
    sampling,
  } as never);
  const sampler = (logger as unknown as { _sampler: { shouldEmit: jest.Mock } })._sampler;
  jest.spyOn(sampler, 'shouldEmit');
  return { logger, sampler };
}

describe('logger sampling with traceConsistent and no active trace', () => {
  it('does not pass the shared fallback trace id to the sampler', async () => {
    const { logger, sampler } = makeLogger({ rate: 0.5, traceConsistent: true });
    jest.spyOn(console, 'log').mockImplementation(() => {});
    await logger.info('no trace');
    expect(sampler.shouldEmit).toHaveBeenCalledWith('info', undefined);
    await logger.close();
    jest.restoreAllMocks();
  });
});
