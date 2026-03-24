import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { KafkaController } from './kafka.controller';
import { KafkaSimulatorController } from './kafka-simulator.controller';
import { KafkaProducerService } from './kafka-producer.service';

const KAFKA_BROKERS = (process.env['KAFKA_BROKERS'] ?? 'localhost:9092').split(',');
const KAFKA_GROUP   = process.env['KAFKA_GROUP_ID'] ?? 'logixia-group';

@Module({
  imports: [
    // ── Kafka producer client (used by KafkaProducerService) ──────────────
    ClientsModule.register([
      {
        name: 'KAFKA_CLIENT',
        transport: Transport.KAFKA,
        options: {
          client: {
            clientId: 'logixia-producer',
            brokers:   KAFKA_BROKERS,
          },
          consumer: {
            groupId: KAFKA_GROUP,
          },
        },
      },
    ]),
  ],
  controllers: [KafkaSimulatorController, KafkaController],
  providers:   [KafkaController, KafkaProducerService],
  exports:     [KafkaController, KafkaProducerService],
})
export class KafkaModule {}
