const PAYLOAD_PREFIX = 'data_';
const UNSAFE_KEYS = new Set(['__proto__']);

/**
 * Copies `core` and then the user payload into one object. The core fields stay
 * authoritative: a payload key that matches a core key (even one whose value is
 * undefined) or a reserved name is kept under a `data_` prefix instead. The
 * prefix is repeated until the name is free of core keys and of every other
 * payload key, so the result does not depend on key order and a payload's own
 * `data_level` stays where it is.
 */
export function mergeCoreFields(
  core: Record<string, unknown>,
  data: Record<string, unknown> | undefined,
  extraReserved: readonly string[] = []
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...core };
  if (!data) return merged;
  const reserved = new Set([...Object.keys(core), ...extraReserved]);
  const payloadKeys = new Set(Object.keys(data));
  for (const key of payloadKeys) {
    if (UNSAFE_KEYS.has(key)) continue;
    let target = key;
    if (reserved.has(target)) {
      do {
        target = `${PAYLOAD_PREFIX}${target}`;
      } while (reserved.has(target) || payloadKeys.has(target));
    }
    merged[target] = data[key];
  }
  return merged;
}
