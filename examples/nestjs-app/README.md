# Logixia NestJS Example App

A complete NestJS application demonstrating every Logixia feature:

| Feature | Where |
|---|---|
| `LogixiaLoggerModule.forRoot` | `app.module.ts` |
| `TraceMiddleware` (auto-registered) | every HTTP request |
| `LogixiaExceptionFilter` | `main.ts` — global |
| `HttpLoggingInterceptor` | `main.ts` — global |
| `@LogMethod` decorator | `users.service.ts` |
| `child()` logger | every service |
| `timeAsync` | `users.service.ts` |
| `RequestContextManager` | `health.controller.ts` |
| `WebSocketTraceInterceptor` | `events.gateway.ts` |
| `KafkaTraceInterceptor` | `kafka.controller.ts` |
| `LogixiaException` | `orders.controller.ts`, `users.service.ts` |
| `DatabaseTransport` (postgres + mongo) | `app.module.ts` (env-driven) |
| `FileTransport` (json rotation) | `app.module.ts` (env-driven) |
| Graceful shutdown | `app.module.ts` — 8 s timeout |

---

## Quick start

### Option A — local (no Docker, no Kafka / DB transports)

```bash
cd ../../          # repo root
npm install
cd examples/nestjs-app
node register.js   # ts-node + .js-extension patch
```

Or via the root npm script:

```bash
npm run dev:nestjs-app
```

### Option B — full Docker stack

```bash
cd examples/nestjs-app
docker compose up -d           # starts postgres + mongo + kafka + zookeeper + kafdrop + app
docker compose logs -f app     # tail app logs
```

Services:

| Service | URL |
|---|---|
| NestJS app | http://localhost:3000 |
| Kafdrop (Kafka UI) | http://localhost:9000 |
| PostgreSQL | localhost:5432 |
| MongoDB | localhost:27017 |

Stop everything:

```bash
docker compose down -v   # -v removes volumes (logs, data)
```

---

## HTTP endpoints

### Health

```bash
# Liveness — returns current traceId
curl http://localhost:3000/health

# RequestContextManager stats
curl http://localhost:3000/health/context

# Fire all log levels at once
curl http://localhost:3000/health/log-levels

# Push a message to WebSocket clients (HTTP→WS traceId propagation demo)
curl -X POST http://localhost:3000/health/broadcast \
  -H 'Content-Type: application/json' \
  -d '{"message":"hello from HTTP"}'
```

### Users

```bash
# List users (triggers @LogMethod + child logger)
curl http://localhost:3000/users

# Get a user (returns 404 LogixiaException when id > 3)
curl http://localhost:3000/users/1
curl http://localhost:3000/users/99   # → 404 WARN log

# Create a user (timeAsync demo; 409 on duplicate email)
curl -X POST http://localhost:3000/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice","email":"alice@example.com"}'

curl -X POST http://localhost:3000/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice","email":"alice@example.com"}'  # → 409 WARN log
```

### Orders

```bash
# List orders
curl http://localhost:3000/orders

# Create order
curl -X POST http://localhost:3000/orders \
  -H 'Content-Type: application/json' \
  -d '{"item":"widget","qty":5}'

# LogixiaException 400 → WARN log
curl http://localhost:3000/orders/boom

# Plain Error 500 → ERROR log
curl http://localhost:3000/orders/crash

# LogixiaException 409 → WARN log
curl http://localhost:3000/orders/conflict

# LogixiaException 429 + Retry-After header → WARN log
curl -i http://localhost:3000/orders/rate-limit
```

### Kafka

```bash
# In-process simulation (no broker needed)
curl -X POST http://localhost:3000/kafka/simulate \
  -H 'Content-Type: application/json' \
  -d '{"topic":"order.created","data":{"orderId":"abc-123","amount":99}}'

curl -X POST http://localhost:3000/kafka/simulate \
  -H 'Content-Type: application/json' \
  -d '{"topic":"user.registered","data":{"userId":"u-42","email":"bob@example.com"}}'

curl -X POST http://localhost:3000/kafka/simulate \
  -H 'Content-Type: application/json' \
  -d '{"topic":"payment.failed","data":{"orderId":"abc-123","reason":"insufficient funds"}}'

# Publish to real Kafka broker (requires Docker stack)
curl -X POST http://localhost:3000/kafka/publish \
  -H 'Content-Type: application/json' \
  -d '{"topic":"order.created","data":{"orderId":"xyz-999","amount":250}}'
```

---

## WebSocket (socket.io)

Install wscat: `npm install -g wscat`

```bash
# Connect
wscat -c "ws://localhost:3000/events"

# Once connected, send JSON frames:

# Ping
{"event":"ping","data":{}}

# Chat message — traceId from the HTTP handshake is propagated into every log
{"event":"chat","data":{"message":"hello","traceId":"my-trace-001"}}
```

> Tip: open two wscat terminals and POST to `/health/broadcast` to see the message arrive on all connected clients with the same traceId.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `development` | |
| `PORT` | `3000` | HTTP listen port |
| `APP_NAME` | `thread-gate` | Shown in every log line |
| `LOG_TO_FILE` | `true` | Enable FileTransport (JSON rotation, `./logs/app.log`) |
| `LOG_TO_POSTGRES` | `true` | Enable DatabaseTransport → PostgreSQL (WARN+ only) |
| `LOG_TO_MONGO` | `true` | Enable DatabaseTransport → MongoDB (INFO+ only) |
| `LOG_FILE_DIR` | `./logs` | Directory for FileTransport |
| `LOG_FILE_NAME` | `app.log` | Log file base name |
| `POSTGRES_HOST` | `localhost` | |
| `POSTGRES_PORT` | `5432` | |
| `POSTGRES_USER` | `logixia` | |
| `POSTGRES_PASSWORD` | `logixia_pass` | |
| `POSTGRES_DB` | `logixia_logs` | |
| `MONGO_HOST` | `localhost` | |
| `MONGO_PORT` | `27017` | |
| `MONGO_USER` | `logixia` | |
| `MONGO_PASSWORD` | `logixia_pass` | |
| `MONGO_DB` | `logixia_logs` | |
| `KAFKA_BROKERS` | `localhost:9092` | Comma-separated. Inside Docker: `kafka:29092` |
| `KAFKA_GROUP_ID` | `logixia-group` | Consumer group |
| `KAFKA_ENABLED` | `false` | Set `true` to connect real Kafka consumer (`@EventPattern` handlers) |

---

## Architecture notes

### TraceId propagation

```
HTTP request
  → TraceMiddleware (sets traceId via AsyncLocalStorage)
    → HttpLoggingInterceptor (logs → and ←)
      → Controller / Service (all logs carry same traceId)
        → LogixiaExceptionFilter (WARN/ERROR with {method,url,status,request_id})

Kafka producer (/kafka/publish)
  → KafkaProducerService.emit() injects getCurrentTraceId() into message body
    → real broker
      → KafkaController @EventPattern handlers
        → KafkaTraceInterceptor extracts traceId → runWithTraceId()
          → handler logs carry same traceId as the HTTP request that triggered publish

WebSocket message
  → EventsGateway manually calls runWithTraceId(extractTraceId(msg))
    → handler logs carry same traceId
```

### Log levels → transports

| Level | Console | File | PostgreSQL | MongoDB |
|---|---|---|---|---|
| ERROR | ✓ | ✓ | ✓ | ✓ |
| WARN | ✓ | ✓ | ✓ | ✓ |
| INFO | ✓ | ✓ | — | ✓ |
| DEBUG | ✓ | ✓ | — | — |
| VERBOSE | ✓ | ✓ | — | — |
