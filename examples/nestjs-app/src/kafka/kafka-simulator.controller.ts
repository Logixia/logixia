import { Body, Controller, Post } from '@nestjs/common';
import type { CallHandler } from '@nestjs/common';
import type { KafkaContext } from '@nestjs/microservices';
import { firstValueFrom, of } from 'rxjs';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { KafkaTraceInterceptor } from '../../../../src/core/kafka-trace.interceptor';
import { runWithTraceId, generateTraceId } from '../../../../src/utils/trace.utils';
import { KafkaController } from './kafka.controller';
import { KafkaProducerService } from './kafka-producer.service';

// Minimal stub that satisfies the KafkaContext interface for in-process simulation.
const stubKafkaContext = {
  getTopic: () => 'simulated',
  getPartition: () => 0,
  getMessage: () => ({ offset: '0' }),
// eslint-disable-next-line @typescript-eslint/no-explicit-any
} as any as KafkaContext;

@Controller('kafka')
export class KafkaSimulatorController {
  private readonly log: LogixiaLoggerService;

  constructor(
    private readonly logger: LogixiaLoggerService,
    private readonly kafkaController: KafkaController,
    private readonly kafkaProducer: KafkaProducerService,
  ) {
    this.log = this.logger.child('KafkaSimulator');
  }

  /**
   * POST /kafka/simulate
   * Runs handlers directly in-process (no broker needed).
   * Useful for local dev / unit testing log output.
   *
   * Body: { "topic": "order.created", "traceId": "...", "data": {...} }
   */
  @Post('simulate')
  async simulate(
    @Body() body: {
      topic: 'order.created' | 'user.registered' | 'payment.failed';
      traceId?: string;
      data: Record<string, unknown>;
    },
  ) {
    const traceId = body.traceId ?? generateTraceId();
    const message = { traceId, ...body.data };

    await this.log.info(`Simulating Kafka message on topic '${body.topic}'`, { topic: body.topic, traceId });

    await runWithTraceId(traceId, async () => {
      switch (body.topic) {
        case 'order.created':
          await this.kafkaController.handleOrderCreated(message, stubKafkaContext);
          break;
        case 'user.registered':
          await this.kafkaController.handleUserRegistered(message, stubKafkaContext);
          break;
        case 'payment.failed':
          await this.kafkaController.handlePaymentFailed(message, stubKafkaContext);
          break;
      }
    });

    return { ok: true, mode: 'simulated', topic: body.topic, traceId };
  }

  /**
   * POST /kafka/simulate-no-trace
   *
   * Tests KafkaTraceInterceptor with requireTraceId:true directly.
   * Calls intercept() with a mocked RPC context that has NO traceId in body/headers.
   *
   * Expected: interceptor returns EMPTY → handler never runs → WARN logged.
   *
   * Try:
   *   curl -X POST http://localhost:3000/kafka/simulate-no-trace \
   *     -H "Content-Type: application/json" -d '{"topic":"order.created"}'
   */
  @Post('simulate-no-trace')
  async simulateNoTrace(
    @Body() body: { topic: string; data?: Record<string, unknown> },
  ) {
    const interceptor = new KafkaTraceInterceptor(undefined, true);

    // Mock ExecutionContext — RPC data has no traceId
    const mockContext = {
      switchToRpc: () => ({
        getData: () => body.data ?? {},
        getContext: () => ({ topic: body.topic, headers: {} }),
      }),
      getType: () => 'rpc',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any;

    let handlerCalled = false;
    const mockHandler: CallHandler = {
      handle: () => {
        handlerCalled = true;
        return of('handler ran');
      },
    };

    // Run inside a fresh ALS context with NO traceId — simulates real Kafka consumer
    const { TraceContext } = await import('../../../../src/utils/trace.utils');
    let result$: ReturnType<typeof interceptor.intercept>;
    TraceContext.instance.storage.run({}, () => {
      result$ = interceptor.intercept(mockContext, mockHandler);
    });

    let emitted: unknown = null;
    await firstValueFrom(result$!, { defaultValue: null }).then((v) => { emitted = v; }).catch(() => {});

    return {
      interceptorResult: !handlerCalled ? 'SKIPPED' : 'PASSED_THROUGH',
      handlerCalled,
      emitted,
      note: !handlerCalled
        ? 'Message skipped — check logs for WARN'
        : 'Handler ran — traceId was found somehow',
    };
  }

  /**
   * POST /kafka/publish
   * Publishes to a REAL Kafka broker (requires Docker).
   * traceId from the HTTP request (set by TraceMiddleware) is embedded in the
   * message body → consumer's KafkaTraceInterceptor reads it → logs correlate end-to-end.
   *
   * Body: { "topic": "order.created", "data": {...} }
   */
  @Post('publish')
  async publish(
    @Body() body: {
      topic: string;
      data: Record<string, unknown>;
    },
  ) {
    await this.kafkaProducer.emit(body.topic, body.data);
    return { ok: true, mode: 'kafka', topic: body.topic };
  }
}
