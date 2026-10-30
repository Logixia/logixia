/** Severity values of the built-in levels; lower is more severe (same scale as the logger). */
const BUILTIN_LEVEL_VALUES: Readonly<Record<string, number>> = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
  trace: 4,
  verbose: 5,
};

export type LevelValues = ReadonlyMap<string, number>;

/** Built-in levels plus the logger's custom `levelOptions.levels`. */
export function buildLevelValues(custom?: Readonly<Record<string, number>>): LevelValues {
  return new Map<string, number>([
    ...Object.entries(BUILTIN_LEVEL_VALUES),
    ...Object.entries(custom ?? {}),
  ]);
}

function lookup(values: LevelValues, level: string): number | undefined {
  return values.get(level) ?? values.get(level.toLowerCase());
}

/**
 * Whether an entry at `level` passes a transport's minimum `threshold`, using the
 * logger's scale (an entry passes when its value is <= the threshold's value).
 * The logger has already rejected unknown entry levels, so an unknown entry level
 * or threshold here does not filter.
 */
export function meetsTransportLevel(
  threshold: string | undefined,
  level: string,
  values: LevelValues
): boolean {
  if (!threshold) return true;
  const min = lookup(values, threshold);
  const actual = lookup(values, level);
  if (min === undefined || actual === undefined) return true;
  return actual <= min;
}
