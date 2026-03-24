import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { LogMethod } from '../../../../src/core/nestjs-extras';
import { LogixiaException } from '../../../../src/exceptions/exception';

export interface Order {
  id: string;
  userId: string;
  item: string;
  amount: number;
  status: 'pending' | 'confirmed' | 'shipped';
}

const ORDERS: Order[] = [
  { id: 'ord_001', userId: 'u_001', item: 'MacBook Pro', amount: 199999, status: 'confirmed' },
  { id: 'ord_002', userId: 'u_002', item: 'AirPods Pro',  amount: 24999,  status: 'shipped'   },
];

@Injectable()
export class OrdersService {
  private readonly log: LogixiaLoggerService;

  constructor(private readonly logger: LogixiaLoggerService) {
    this.log = this.logger.child('OrdersService');
  }

  @LogMethod({ level: 'debug', logArgs: false })
  async findAll(): Promise<Order[]> {
    await this.log.info('Fetching all orders', { count: ORDERS.length });
    return ORDERS;
  }

  @LogMethod({ level: 'debug', logArgs: true })
  async create(dto: Omit<Order, 'id' | 'status'>): Promise<Order> {
    if (!dto.amount || dto.amount <= 0) {
      throw new LogixiaException({
        code: 'ORD-002', type: 'validation_error', httpStatus: 400,
        message: 'Order amount must be greater than zero.', param: 'amount',
      });
    }

    // timeAsync — logs duration automatically
    const order = await this.log.timeAsync<Order>('db:orders.insert', async () => {
      await new Promise<void>((r) => setTimeout(r, 30));
      const o: Order = { id: `ord_${Date.now()}`, status: 'pending', ...dto };
      ORDERS.push(o);
      return o;
    });

    await this.log.info('Order created', { orderId: order.id, userId: order.userId, amount: order.amount });
    return order;
  }

  /** Typed 4xx → ExceptionFilter logs WARN with structured meta */
  async throwBusinessError(): Promise<never> {
    throw new LogixiaException({
      code: 'ORD-001', type: 'validation_error', httpStatus: 400,
      message: 'Order amount must be greater than zero.', param: 'amount',
      metadata: { attemptedAmount: 0 },
    });
  }

  /** Plain 5xx → ExceptionFilter logs ERROR with structured meta */
  async throwServerError(): Promise<never> {
    throw new Error('DB connection timed out after 5000ms');
  }

  /** 409 conflict */
  async throwConflict(): Promise<never> {
    throw new LogixiaException({
      code: 'ORD-003', type: 'conflict_error', httpStatus: 409,
      message: 'Duplicate order detected within 60 seconds.',
      metadata: { windowMs: 60000 },
    });
  }

  /** 429 rate-limit — ExceptionFilter adds Retry-After: 60 header */
  async throwRateLimit(): Promise<never> {
    throw new LogixiaException({
      code: 'ORD-429', type: 'rate_limit_error', httpStatus: 429,
      message: 'Too many requests. Please slow down.',
    });
  }
}
