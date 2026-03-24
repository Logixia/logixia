import { Body, Controller, Post } from '@nestjs/common';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { runWithTraceId, generateTraceId } from '../../../../src/utils/trace.utils';
import { KafkaController } from './kafka.controller';
import { KafkaProducerService } from './kafka-producer.service';

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
          await this.kafkaController.handleOrderCreated(message, null);
          break;
        case 'user.registered':
          await this.kafkaController.handleUserRegistered(message);
          break;
        case 'payment.failed':
          await this.kafkaController.handlePaymentFailed(message);
          break;
      }
    });

    return { ok: true, mode: 'simulated', topic: body.topic, traceId };
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
