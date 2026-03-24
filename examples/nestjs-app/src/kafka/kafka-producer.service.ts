import { Injectable, Inject, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ClientKafka } from '@nestjs/microservices';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { getCurrentTraceId } from '../../../../src/utils/trace.utils';

/**
 * Kafka producer — publishes messages to topics with traceId injected
 * into the message body so consumers can extract it via KafkaTraceInterceptor.
 *
 * Used by /kafka/publish route to demonstrate real end-to-end traceId propagation:
 *   HTTP request → TraceMiddleware sets traceId → producer embeds it in message
 *   → consumer KafkaTraceInterceptor reads it → every log in consumer carries same traceId
 */
@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  private readonly log: LogixiaLoggerService;

  constructor(
    @Inject('KAFKA_CLIENT') private readonly kafkaClient: ClientKafka,
    private readonly logger: LogixiaLoggerService,
  ) {
    this.log = this.logger.child('KafkaProducerService');
  }

  async onModuleInit() {
    try {
      await this.kafkaClient.connect();
      await this.log.info('Kafka producer connected', {
        brokers: process.env['KAFKA_BROKERS'] ?? 'localhost:9092',
      });
    } catch (err) {
      // Non-fatal — simulator still works without a real broker
      await this.log.warn('Kafka producer could not connect (no broker?)', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async onModuleDestroy() {
    try {
      await this.kafkaClient.close();
    } catch {
      // ignore on shutdown
    }
  }

  /**
   * Emit a message to a Kafka topic.
   * Automatically injects the current traceId so consumers can correlate logs.
   */
  async emit(topic: string, payload: Record<string, unknown>): Promise<void> {
    const traceId = getCurrentTraceId();
    const message = { traceId, ...payload };

    await this.log.debug(`Emitting to topic '${topic}'`, { topic, traceId, payload });

    try {
      await new Promise<void>((resolve, reject) => {
        this.kafkaClient.emit(topic, message).subscribe({
          error: reject,
          complete: resolve,
        });
      });
      await this.log.info(`Message published to '${topic}'`, { topic, traceId });
    } catch (err) {
      await this.log.error(err instanceof Error ? err : new Error(String(err)), {
        topic, traceId, context: 'KafkaProducerService.emit',
      });
      throw err;
    }
  }
}
