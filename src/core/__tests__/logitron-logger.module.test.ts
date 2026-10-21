import { LogixiaLoggerModule } from '../logitron-logger.module';

describe('LogixiaLoggerModule internal warnings', () => {
  afterEach(() => {
    LogixiaLoggerModule._resetGlobalLogger();
    delete process.env.LOGIXIA_SILENT_INTERNAL;
    jest.restoreAllMocks();
  });

  it('silences the duplicate forRoot warning when internal logs are disabled', () => {
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    const stderrWrite = jest.spyOn(process.stderr, 'write').mockReturnValue(true);
    const logger = {} as never;

    LogixiaLoggerModule._setGlobalLogger(logger);
    LogixiaLoggerModule._setGlobalLogger(logger);

    expect(stderrWrite).not.toHaveBeenCalled();
  });
});
