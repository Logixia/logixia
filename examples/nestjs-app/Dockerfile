# ─────────────────────────────────────────────────────────────────────────────
#  Multi-stage Dockerfile for the Logixia NestJS example app
#  Stage 1 (builder) — compiles TypeScript
#  Stage 2 (runner)  — lean production image
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /build

# Copy root package files first (better layer cache)
COPY package*.json ./

# Install ALL deps (including devDeps — needed for ts-node / typescript)
# --ignore-scripts skips husky install (no git hooks in Docker)
RUN npm ci --legacy-peer-deps --ignore-scripts

# Copy source
COPY tsconfig.json ./
COPY src/ ./src/
COPY examples/nestjs-app/ ./examples/nestjs-app/

# Compile the NestJS app using the app-specific tsconfig
RUN npx tsc \
      --project examples/nestjs-app/tsconfig.json \
      --outDir examples/nestjs-app/dist \
      --rootDir examples/nestjs-app/src \
    || true
# Fallback: if tsc has path issues we still use ts-node at runtime (dev mode)


# ── Stage 2: runner ───────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

# dumb-init: proper PID 1 + signal forwarding (SIGTERM → graceful shutdown)
RUN apk add --no-cache dumb-init

WORKDIR /app

# Install all deps (ts-node is a devDep but needed at runtime in this example app)
COPY package*.json ./
RUN npm ci --legacy-peer-deps --ignore-scripts \
    && npm install --no-save --legacy-peer-deps kafkajs \
    && npm cache clean --force

# Copy compiled source + register helper from builder
COPY --from=builder /build/src/               ./src/
COPY --from=builder /build/examples/nestjs-app/ ./examples/nestjs-app/

# Create log directory for FileTransport
RUN mkdir -p /app/logs && chown node:node /app/logs

# Run as non-root
USER node

EXPOSE 3000

# Use ts-node at runtime so the path aliases / .js stripping work
# (same command as npm run dev:nestjs-app)
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "node_modules/.bin/ts-node", \
     "--project", "examples/nestjs-app/tsconfig.json", \
     "-r", "./examples/nestjs-app/register.js", \
     "examples/nestjs-app/src/main.ts"]
