/**
 * Structural request/response shapes shared by every framework helper, so Express,
 * Fastify and Node `http` objects are accepted without importing their types. Every
 * optional member also accepts `undefined`, which keeps `exactOptionalPropertyTypes`
 * consumers compiling against real framework types.
 */

/** Minimal request shape that Express, Fastify and Node `IncomingMessage` satisfy. */
export interface HttpRequestShape {
  method?: string | undefined;
  url?: string | undefined;
  originalUrl?: string | undefined;
  headers?: Record<string, string | string[] | undefined> | undefined;
  body?: unknown;
  ip?: string | undefined;
  id?: unknown;
  socket?: { remoteAddress?: string | undefined } | undefined;
}

/** Minimal response shape that Express, Fastify replies and Node `ServerResponse` satisfy. */
export interface HttpResponseShape {
  statusCode?: number | undefined;
  on?: ((event: string, cb: () => void) => void) | undefined;
  once?: ((event: string, cb: () => void) => void) | undefined;
  getHeader?: ((name: string) => string | number | string[] | undefined) | undefined;
  /** Express / Node `res.setHeader`. */
  setHeader?: ((name: string, value: string) => unknown) | undefined;
  /** Fastify `reply.header`. */
  header?: ((name: string, value: string) => unknown) | undefined;
}
