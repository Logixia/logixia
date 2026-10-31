/**
 * True for the one key that must never be assigned with `target[key] = value`.
 *
 * Assigning `constructor` or `prototype` on a fresh plain object only creates an
 * own property, which is harmless. Only `__proto__` invokes the prototype setter.
 */
export function isProtoKey(key: string): boolean {
  return key === '__proto__';
}

/**
 * Copy `value` onto `target[key]` as an own, enumerable data property.
 *
 * Normal keys use a plain assignment, which is the fast path. `__proto__` goes
 * through `Object.defineProperty` so that a key taken from logged or parsed data
 * becomes an own property instead of replacing the object's prototype.
 */
export function assignOwn(target: object, key: string, value: unknown): void {
  if (key === '__proto__') {
    Object.defineProperty(target, key, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  } else {
    (target as Record<string, unknown>)[key] = value;
  }
}
