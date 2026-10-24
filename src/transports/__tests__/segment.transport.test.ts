/**
 * Guards issue #35: Segment payloads must carry the 'logixia' library name and
 * the real package version, not the legacy 'logitron' name or a hardcoded
 * '1.0.0'. `context.library` is user-visible data on every Segment event.
 *
 * The payload builder is exercised directly on a prototype instance: the
 * transport's own constructor kicks off an async initialize() that needs a live
 * provider, which is not what this unit test is about.
 */
import type { SegmentTransportConfig } from '../../types/transport.types';
import { LOGIXIA_VERSION } from '../../version';
import { SegmentTransport } from '../segment.transport';

interface SegmentLibraryPayload {
  context: { library: { name: string; version: string } };
}

interface SegmentInternals {
  segmentConfig: SegmentTransportConfig;
  identify: (user: { id: string }) => Promise<void>;
  makeRequest: (endpoint: string, data: unknown) => Promise<void>;
}

function makeTransport(): { transport: SegmentInternals; sent: unknown[] } {
  const sent: unknown[] = [];
  const transport = Object.create(SegmentTransport.prototype) as unknown as SegmentInternals;
  transport.segmentConfig = { writeKey: 'test-key' };
  transport.makeRequest = (_endpoint, data) => {
    sent.push(data);
    return Promise.resolve();
  };
  return { transport, sent };
}

describe('SegmentTransport — outgoing payload branding', () => {
  it('stamps the logixia library name and the real package version', async () => {
    const { transport, sent } = makeTransport();

    await transport.identify({ id: 'user-1' });

    expect(sent).toHaveLength(1);
    const payload = sent[0] as SegmentLibraryPayload;
    expect(payload.context.library.name).toBe('logixia');
    expect(payload.context.library.version).toBe(LOGIXIA_VERSION);
    expect(JSON.stringify(payload)).not.toContain('logitron');
  });
});
