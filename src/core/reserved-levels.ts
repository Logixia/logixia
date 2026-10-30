import type { ReservedLevelName } from '../types';
import { internalWarn } from '../utils/internal-log';

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

/**
 * Warn when `levels` defines a level named like a logger method (e.g. `flush`, `child`).
 * The method keeps its normal behaviour and no level shortcut is installed for that
 * name; log at it with `logger.logLevel(name, ...)` or pick a different level name.
 * Returns the clashing names.
 */
export function warnOnReservedLevelNames(levels: Record<string, number> | undefined): string[] {
  if (!levels) return [];
  const clashes = Object.keys(levels).filter((name) => RESERVED.has(name));
  if (clashes.length > 0) {
    internalWarn(
      `levelOptions.levels uses reserved logger method name(s): ${clashes.join(', ')}. ` +
        'No level shortcut is created for them; use logger.logLevel(name, ...) or rename the level.'
    );
  }
  return clashes;
}
