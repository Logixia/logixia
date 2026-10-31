/**
 * Define `key` as an own, enumerable data property of `target`.
 *
 * Unlike `target[key] = value`, this never invokes setters on the prototype chain,
 * so a key such as `__proto__` taken from logged data becomes a plain own property
 * instead of replacing the object's prototype.
 */
export function setOwnProperty(target: object, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}
