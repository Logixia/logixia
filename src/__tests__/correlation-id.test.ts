/**
 * Tests for `generateCorrelationId` (issue #138).
 *
 * The function promises a UUID v4. On runtimes without a Web Crypto global
 * (Node 18 without `--experimental-global-webcrypto`), the old fallback
 * returned a non-UUID string like `murwq4c9-phj8qghqy`. The fallback now uses
 * `node:crypto`'s `randomUUID`, so the shape holds on every Node version.
 */

import { generateCorrelationId } from '../correlation';

/** UUID v4: 8-4-4-4-12 hex with version 4 and a variant nibble in 8/9/a/b. */
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe('generateCorrelationId', () => {
  it('returns a UUID v4', () => {
    expect(generateCorrelationId()).toMatch(UUID_V4);
  });

  it('produces distinct ids', () => {
    const a = generateCorrelationId();
    const b = generateCorrelationId();
    expect(a).not.toBe(b);
  });

  it('still returns a UUID v4 when the Web Crypto global is unavailable', () => {
    const g = globalThis as unknown as { crypto?: unknown };
    const original = g.crypto;
    try {
      delete g.crypto;
      expect(generateCorrelationId()).toMatch(UUID_V4);
    } finally {
      g.crypto = original;
    }
  });
});
