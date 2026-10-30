import type { ReservedLevelName } from '../types';

/** Logger members that a custom level name must not collide with. */
const RESERVED_LEVEL_NAMES = [
  'logLevel',
  'time',
  'timeEnd',
  'timeAsync',
  'setLevel',
  'getLevel',
  'setNamespaceLevels',
  'patchNamespaceLevels',
  'getNamespaceLevels',
  'setContext',
  'getContext',
  'enableField',
  'disableField',
  'isFieldEnabled',
  'getFieldState',
  'resetFieldState',
  'enableTransportLevelPrompting',
  'disableTransportLevelPrompting',
  'setTransportLevels',
  'getTransportLevels',
  'clearTransportLevelPreferences',
  'getAvailableTransports',
  'child',
  'flush',
  'healthCheck',
  'close',
  'use',
  'unuse',
] as const satisfies readonly ReservedLevelName[];

// Fails to compile when a member is added to the logger interfaces but not listed above.
type MissingReservedNames = Exclude<ReservedLevelName, (typeof RESERVED_LEVEL_NAMES)[number]>;
export const reservedLevelNamesAreExhaustive: [MissingReservedNames] extends [never]
  ? true
  : never = true;

const RESERVED = new Set<string>(RESERVED_LEVEL_NAMES);

/** Throw when `levels` defines a level named like a logger method (e.g. `flush`, `child`). */
export function assertNoReservedLevelNames(levels: Record<string, number> | undefined): void {
  if (!levels) return;
  const clashes = Object.keys(levels).filter((name) => RESERVED.has(name));
  if (clashes.length > 0) {
    throw new Error(
      `logixia: levelOptions.levels cannot use reserved logger method name(s): ${clashes.join(', ')}. ` +
        'Pick a different level name.'
    );
  }
}
