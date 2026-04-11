import { Controller, UseInterceptors } from '@nestjs/common';
import { EventPattern, Payload, Ctx, KafkaContext } from '@nestjs/microservices';
import { KafkaTraceInterceptor } from '../../../../src/core/kafka-trace.interceptor';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { LogMethod } from '../../../../src/core/nestjs-extras';
import { getCurrentTraceId } from '../../../../src/utils/trace.utils';

/**
 * Kafka consumer — uses the real KafkaTraceInterceptor via @UseInterceptors.
 *
 * The interceptor (applied at controller level) runs for every @EventPattern:
 *   1. Extracts traceId from message body  → { traceId } / { trace_id }
 *   2. Falls back to Kafka headers          → x-trace-id
 *   3. Falls back to current AsyncLocalStorage trace
 *
 * KafkaProducerService.emit() injects the producer's traceId into the message
 * body, so consumer logs automatically correlate with the originating HTTP request.
 *
 * In simulation mode (/kafka/simulate) the handlers are called directly by
 * KafkaSimulatorController inside a runWithTraceId() wrapper, so traceId
 * propagation still works without a real broker.
 */
@UseInterceptors(new KafkaTraceInterceptor(undefined, true))
@Controller()
export class KafkaController {
  private readonly log: LogixiaLoggerService;

  constructor(private readonly logger: LogixiaLoggerService) {
    this.log = this.logger.child('KafkaController');
  }

  @EventPattern('order.created')
  @LogMethod({ level: 'info', logArgs: false })
  async handleOrderCreated(
    @Payload() data: Record<string, unknown>,
    @Ctx() context: KafkaContext,
  ) {
    const traceId = getCurrentTraceId(); // set by KafkaTraceInterceptor
    await this.log.info('Kafka: order.created received', {
      traceId,
      orderId:   data['orderId'],
      userId:    data['userId'],
      amount:    data['amount'],
      topic:     context?.getTopic?.(),
      partition: context?.getPartition?.(),
      offset:    context?.getMessage?.().offset,
    });

    await this.processOrderAsync(data);
  }

  @EventPattern('user.registered')
  @LogMethod({ level: 'info', logArgs: false })
  async handleUserRegistered(@Payload() data: Record<string, unknown>, @Ctx() context: KafkaContext) {
    const traceId = getCurrentTraceId();
    await this.log.info('Kafka: user.registered received', {
      traceId,
      userId:    data['userId'],
      email:     data['email'],
      topic:     context?.getTopic?.(),
      partition: context?.getPartition?.(),
    });
  }

  @EventPattern('payment.failed')
  @LogMethod({ level: 'info', logArgs: false })
  async handlePaymentFailed(@Payload() data: Record<string, unknown>, @Ctx() context: KafkaContext) {
    const traceId = getCurrentTraceId();
    await this.log.warn('Kafka: payment.failed received', {
      traceId,
      orderId:    data['orderId'],
      reason:     data['reason'],
      retryCount: data['retryCount'],
      topic:      context?.getTopic?.(),
      offset:     context?.getMessage?.().offset,
    });
  }

  private async processOrderAsync(data: Record<string, unknown>) {
    // traceId is still in AsyncLocalStorage — no argument threading needed
    await this.log.timeAsync('kafka:processOrder', async () => {
      await new Promise<void>((r) => setTimeout(r, 25));
      await this.log.debug('Order processing complete', { orderId: data['orderId'] });
    });
  }
}
