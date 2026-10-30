// Minimal stand-ins so the repo can typecheck this example without Node types or
// @cloudflare/workers-types. In a real project, install @cloudflare/workers-types
// and delete this file.
interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

// The logixia/browser re-exports (typed-logger, otel, internal-log) still reference
// Node's `process` and `require` in their source. These declarations only keep that
// library code compiling; the example itself must not use them.
declare const process: {
  env: Record<string, string | undefined>;
  stderr: { write(chunk: string): void };
};
declare function require(id: string): unknown;
