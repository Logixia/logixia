/**
 * Error serialization utilities for Logitron
 */

import { ErrorSerializationOptions } from "../types";

/**
 * Serialize error object to JSON-safe format
 */
export function serializeError(
  error: Error,
  options: ErrorSerializationOptions = {},
): Record<string, any> {
  const { includeStack = true, maxDepth = 3, excludeFields = [] } = options;

  const serialized: Record<string, any> = {
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
        const value = (error as any)[key];
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
function serializeValue(value: any, maxDepth: number, currentDepth = 0): any {
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
    const serialized: Record<string, any> = {};
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
export function isError(value: any): value is Error {
  return (
    value instanceof Error ||
    (value &&
      typeof value === "object" &&
      "name" in value &&
      "message" in value)
  );
}

/**
 * Create error from various input types
 */
export function normalizeError(error: any): Error {
  if (isError(error)) {
    return error;
  }

  if (typeof error === "string") {
    return new Error(error);
  }

  if (typeof error === "object" && error !== null) {
    const err = new Error(error.message || "Unknown error");
    Object.assign(err, error);
    return err;
  }

  return new Error(String(error));
}
