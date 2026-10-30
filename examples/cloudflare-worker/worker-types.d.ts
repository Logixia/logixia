// Minimal stand-in for the Workers runtime type used by the example, so the repo
// can typecheck it without @cloudflare/workers-types. In a real project, install
// that package and delete this file.
interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}
