/**
 * Error serialization utilities for Logitron
 */

import type { ErrorSerializationOptions } from "../types";

/**
 * Serialize error object to JSON-safe format
 */
export function serializeError(
  error: Error,
  options: ErrorSerializationOptions = {},
): Record<string, unknown> {
  const { includeStack = true, maxDepth = 3, excludeFields = [] } = options;

  const serialized: Record<string, unknown> = {
    name: error.name,
    message: error.message,
  };

  // Add stack trace if requested
  if (includeStack && error.stack) {
    serialized.stack = error.stack;
  }

  // Add custom properties
  const errorKeys = Object.getOwnPropertyNames(error);
  for (const key of errorKeys) {
    if (
      key !== "name" &&
      key !== "message" &&
      key !== "stack" &&
      !excludeFields.includes(key)
    ) {
      try {
        const value = (error as unknown as Record<string, unknown>)[key];
        serialized[key] = serializeValue(value, maxDepth);
      } catch {
        // Ignore properties that can't be serialized
      }
    }
  }

  return serialized;
}

/**
 * Recursively serialize values with depth limit
 */
function serializeValue(value: unknown, maxDepth: number, currentDepth = 0): unknown {
  if (currentDepth >= maxDepth) {
    return "[Max Depth Reached]";
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (value instanceof Error) {
    return serializeError(value, { maxDepth: maxDepth - currentDepth });
  }

  if (Array.isArray(value)) {
    return value.map((item) =>
      serializeValue(item, maxDepth, currentDepth + 1),
    );
  }

  if (typeof value === "object") {
    const serialized: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      try {
        serialized[key] = serializeValue(val, maxDepth, currentDepth + 1);
      } catch {
        serialized[key] = "[Unserializable]";
      }
    }
    return serialized;
  }

  return String(value);
}

/**
 * Check if value is an Error instance
 */
export function isError(value: unknown): value is Error {
  return (
    value instanceof Error ||
    (Boolean(value) &&
      typeof value === "object" &&
      "name" in (value as object) &&
      "message" in (value as object))
  );
}

/**
 * Create error from various input types
 */
export function normalizeError(error: unknown): Error {
  if (isError(error)) {
    return error;
  }

  if (typeof error === "string") {
    return new Error(error);
  }

  if (typeof error === "object" && error !== null) {
    const e = error as Record<string, unknown>;
    const err = new Error(typeof e['message'] === 'string' ? e['message'] : "Unknown error");
    Object.assign(err, error);
    return err;
  }

  return new Error(String(error));
}
