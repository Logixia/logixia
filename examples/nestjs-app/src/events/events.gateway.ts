import { UseInterceptors } from '@nestjs/common';
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  OnGatewayConnection,
  OnGatewayDisconnect,
  OnGatewayInit,
} from '@nestjs/websockets';
import type { Server, Socket } from 'socket.io';
import { WebSocketTraceInterceptor } from '../../../../src/core/websocket-trace.interceptor';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { getCurrentTraceId, generateTraceId, runWithTraceId } from '../../../../src/utils/trace.utils';

/**
 * WebSocket gateway — uses the real WebSocketTraceInterceptor via @UseInterceptors.
 *
 * The interceptor (applied at gateway level) runs before every @SubscribeMessage:
 *   1. Extracts traceId from message body  → { traceId } / { trace_id }
 *   2. Falls back to handshake headers     → x-trace-id
 *   3. Falls back to current AsyncLocalStorage trace
 *
 * After the interceptor runs, getCurrentTraceId() inside any handler returns
 * the extracted value — no manual runWithTraceId() needed per handler.
 *
 * Test with:
 *   wscat -c ws://localhost:3000/events
 *   > {"event":"ping","data":{"traceId":"my-trace-123","payload":"hello"}}
 *   > {"event":"chat","data":{"traceId":"my-trace-456","room":"general","message":"hi"}}
 *   > {"event":"join","data":{"traceId":"my-trace-789","room":"vip"}}
 *
 * Or with x-trace-id header:
 *   wscat -H "x-trace-id: abc-123" -c ws://localhost:3000/events
 */
@UseInterceptors(new WebSocketTraceInterceptor())
@WebSocketGateway({ namespace: '/events', cors: { origin: '*' } })
export class EventsGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server!: Server;

  private readonly log: LogixiaLoggerService;

  constructor(private readonly logger: LogixiaLoggerService) {
    this.log = this.logger.child('EventsGateway');
  }

  afterInit() {
    this.log.info('WebSocket gateway initialised', { namespace: '/events' });
  }

  handleConnection(client: Socket) {
    // Connection-level traceId comes from x-trace-id handshake header (if present)
    const traceId = (client.handshake.headers['x-trace-id'] as string) ?? generateTraceId();
    runWithTraceId(traceId, () => {
      this.log.info('Client connected', {
        socketId: client.id,
        address:  client.handshake.address,
        traceId,
      });
    });
  }

  handleDisconnect(client: Socket) {
    this.log.info('Client disconnected', { socketId: client.id });
  }

  /**
   * ping → pong.
   * WebSocketTraceInterceptor has already set traceId in AsyncLocalStorage
   * before this handler runs — getCurrentTraceId() just reads it.
   */
  @SubscribeMessage('ping')
  async handlePing(
    @MessageBody() data: { traceId?: string; payload?: unknown },
    @ConnectedSocket() client: Socket,
  ) {
    const traceId = getCurrentTraceId(); // set by WebSocketTraceInterceptor
    await this.log.debug('ping received', { socketId: client.id, traceId, payload: data.payload });
    return { event: 'pong', data: { traceId, ts: Date.now(), echo: data.payload } };
  }

  /**
   * chat → broadcasts to a room.
   * traceId is propagated into the broadcast log automatically.
   */
  @SubscribeMessage('chat')
  async handleChat(
    @MessageBody() data: { traceId?: string; room: string; message: string },
    @ConnectedSocket() client: Socket,
  ) {
    const traceId = getCurrentTraceId(); // set by WebSocketTraceInterceptor
    await this.log.info('chat message received', {
      socketId: client.id, traceId, room: data.room, message: data.message,
    });
    void client.join(data.room);
    this.server.to(data.room).emit('chat', {
      from: client.id, traceId, message: data.message, ts: Date.now(),
    });
    return { event: 'chat:ack', data: { traceId, room: data.room } };
  }

  /**
   * join → client joins a named room.
   */
  @SubscribeMessage('join')
  async handleJoin(
    @MessageBody() data: { traceId?: string; room: string },
    @ConnectedSocket() client: Socket,
  ) {
    const traceId = getCurrentTraceId();
    await this.log.info('Client joined room', { socketId: client.id, traceId, room: data.room });
    void client.join(data.room);
    return { event: 'join:ack', data: { traceId, room: data.room } };
  }

  /**
   * broadcast → server-pushed event (called from HTTP trigger route).
   * Shows that traceId from HTTP context is preserved across WS push.
   */
  broadcastToAll(event: string, payload: unknown, traceId?: string) {
    this.log.info('Broadcasting to all clients', { event, traceId });
    this.server.emit(event, { payload, traceId, ts: Date.now() });
  }
}
