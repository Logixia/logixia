import { Body, Controller, Get, Post } from '@nestjs/common';
import { OrdersService, type Order } from './orders.service';

@Controller('orders')
export class OrdersController {
  constructor(private readonly ordersService: OrdersService) {}

  @Get()
  findAll(): Promise<Order[]> { return this.ordersService.findAll(); }

  @Post()
  create(@Body() dto: Omit<Order, 'id' | 'status'>): Promise<Order> {
    return this.ordersService.create(dto);
  }

  /** LogixiaException 400 → ExceptionFilter WARN */
  @Get('boom')
  boom(): Promise<never> { return this.ordersService.throwBusinessError(); }

  /** Plain Error 500 → ExceptionFilter ERROR */
  @Get('crash')
  crash(): Promise<never> { return this.ordersService.throwServerError(); }

  /** LogixiaException 409 */
  @Get('conflict')
  conflict(): Promise<never> { return this.ordersService.throwConflict(); }

  /** LogixiaException 429 → ExceptionFilter adds Retry-After header */
  @Get('rate-limit')
  rateLimit(): Promise<never> { return this.ordersService.throwRateLimit(); }
}
