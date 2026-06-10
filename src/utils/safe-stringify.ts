/**
 * logixia — robust JSON serialization for log payloads.
 *
 * Modern Winston/Pino already neutralize circular refs to `[Circular]` (via
 * safe-stable-stringify / fast-safe-stringify), so merely "surviving cycles" is
 * not a differentiator. This goes one notch further:
 *
 *  - **BigInt** → serialized (as a string by default; JSON.stringify throws on
 *    BigInt, which silently breaks logging of e.g. DB bigint ids).
 *  - **Deterministic key order** (optional) so identical objects hash/diff equal.
 *  - **True decycle** (optional) — replace repeated references with JSONPath
 *    `$ref` pointers that round-trip back to the original object graph, instead
 *    of the lossy `[Circular]` tag. Useful when you need to reconstruct shared
 *    structure downstream.
 *
 * @example
 * ```ts
 * safeStringify({ id: 10n, self: obj });          // → BigInt + cycle safe
 * safeStringify(graph, { decycle: true });         // → round-trippable $ref pointers
 * const back = retrocycle(JSON.parse(json));       // → reconstruct shared refs
 * ```
 */

export interface SafeStringifyOptions {
  /** Indentation passed to JSON.stringify (number of spaces or a string). */
  indent?: number | string;
  /** Sort object keys for deterministic output. Default: false. */
  deterministic?: boolean;
  /**
   * Use round-trippable `$ref` JSONPath pointers for repeated references instead
   * of the lossy "[Circular]" tag. Default: false.
   */
  decycle?: boolean;
  /** How to render BigInt: 'string' (default) or 'number' (may lose precision). */
  bigint?: 'string' | 'number';
}

/** Build a JSONPath like `$["a"][0]["b"]` for a decycle pointer. */
function jsonPath(parts: Array<string | number>): string {
  let path = '$';
  for (const p of parts) {
    path += typeof p === 'number' ? `[${p}]` : `[${JSON.stringify(p)}]`;
  }
  return path;
}

/**
 * Serialize any value to JSON without throwing on circular references or BigInt.
 * Circular refs become `"[Circular]"` (or `{ $ref }` pointers when `decycle`).
 */
export function safeStringify(value: unknown, options: SafeStringifyOptions = {}): string {
  const { indent, deterministic = false, decycle = false, bigint = 'string' } = options;

  if (decycle) {
    return JSON.stringify(decycleValue(value, bigint), undefined, indent);
  }

  const seen = new WeakSet<object>();

  const transform = (val: unknown): unknown => {
    if (typeof val === 'bigint') return bigint === 'number' ? Number(val) : val.toString();
    if (typeof val === 'function') return `[Function: ${val.name || 'anonymous'}]`;
    if (typeof val === 'symbol') return val.toString();
    if (val === null || typeof val !== 'object') return val;

    if (seen.has(val)) return '[Circular]';
    seen.add(val);

    let out: unknown;
    if (Array.isArray(val)) {
      out = val.map((item) => transform(item));
    } else if (val instanceof Date) {
      out = val.toISOString();
    } else {
      const rec = val as Record<string, unknown>;
      const keys = deterministic ? Object.keys(rec).sort() : Object.keys(rec);
      const obj: Record<string, unknown> = {};
      for (const k of keys) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
        obj[k] = transform(rec[k]);
      }
      out = obj;
    }
    // Allow the same object to appear in sibling branches (not a true cycle):
    // remove from `seen` after we finish its subtree.
    seen.delete(val);
    return out;
  };

  return JSON.stringify(transform(value), undefined, indent);
}

/**
 * Replace repeated object references with round-trippable `{ "$ref": "$..." }`
 * JSONPath pointers (the classic Crockford decycle). Pair with {@link retrocycle}
 * to reconstruct the original shared/circular graph.
 */
export function decycleValue(value: unknown, bigint: 'string' | 'number' = 'string'): unknown {
  const paths = new WeakMap<object, string>();

  const walk = (val: unknown, path: Array<string | number>): unknown => {
    if (typeof val === 'bigint') return bigint === 'number' ? Number(val) : val.toString();
    if (val === null || typeof val !== 'object') return val;
    if (val instanceof Date) return val.toISOString();

    const existing = paths.get(val);
    if (existing !== undefined) return { $ref: existing };
    paths.set(val, jsonPath(path));

    if (Array.isArray(val)) {
      return val.map((item, i) => walk(item, [...path, i]));
    }
    const rec = val as Record<string, unknown>;
    const obj: Record<string, unknown> = {};
    for (const k of Object.keys(rec)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      obj[k] = walk(rec[k], [...path, k]);
    }
    return obj;
  };

  return walk(value, []);
}

/**
 * Inverse of {@link decycleValue}: resolve `{ "$ref": "$..." }` pointers back
 * into the live object graph (mutates and returns the parsed input).
 */
export function retrocycle<T>(root: T): T {
  const refRe = /^\$(?:\[(?:\d+|"(?:[^"\\]|\\.)*")\])*$/;

  const resolve = (path: string): unknown => {
    // Parse the JSONPath segments back out.
    const segs: Array<string | number> = [];
    const partRe = /\[(\d+|"(?:[^"\\]|\\.)*")\]/g;
    let m: RegExpExecArray | null;
    while ((m = partRe.exec(path)) !== null) {
      const raw = m[1]!;
      segs.push(raw.startsWith('"') ? (JSON.parse(raw) as string) : Number(raw));
    }
    let node: unknown = root;
    for (const s of segs) {
      node = (node as Record<string | number, unknown>)[s];
    }
    return node;
  };

  const walk = (val: unknown): void => {
    if (val === null || typeof val !== 'object') return;
    const rec = val as Record<string, unknown>;
    for (const k of Object.keys(rec)) {
      const child = rec[k];
      if (
        child !== null &&
        typeof child === 'object' &&
        typeof (child as { $ref?: unknown }).$ref === 'string' &&
        refRe.test((child as { $ref: string }).$ref)
      ) {
        rec[k] = resolve((child as { $ref: string }).$ref);
      } else {
        walk(child);
      }
    }
  };

  walk(root);
  return root;
}
