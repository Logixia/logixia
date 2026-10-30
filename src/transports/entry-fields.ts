const PAYLOAD_PREFIX = 'data_';
const UNSAFE_KEYS = new Set(['__proto__']);

/**
 * Copies `core` and then the user payload into one object. The core fields stay
 * authoritative: a payload key that matches a core key (even one whose value is
 * undefined) is kept under a `data_` prefix instead of replacing it.
 */
export function mergeCoreFields(
  core: Record<string, unknown>,
  data: Record<string, unknown> | undefined,
  extraReserved: readonly string[] = []
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...core };
  if (!data) return merged;
  const reserved = new Set(extraReserved);
  for (const key of Object.keys(data)) {
    if (UNSAFE_KEYS.has(key)) continue;
    let target = key;
    while (target in core || reserved.has(target) || target in merged) {
      target = `${PAYLOAD_PREFIX}${target}`;
    }
    merged[target] = data[key];
  }
  return merged;
}
