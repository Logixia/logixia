import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { TraceIdGuard } from '../guards/trace-id.guard';
import { getCurrentTraceId } from '../../../../src/utils/trace.utils';
import { UsersService, type User } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  findAll(): Promise<User[]> {
    return this.usersService.findAll();
  }

  // ── Specific routes BEFORE :id to avoid param conflict ─────────────────────

  // TraceMiddleware (wired in LogixiaLoggerModule) already extracts traceId from:
  //   header  → x-trace-id / x-request-id / x-correlation-id / traceparent
  //   query   → ?traceId= / ?trace_id=
  //   body    → { traceId } / { trace_id }
  //
  // TraceIdGuard's job: just verify it's present in ALS, throw 403 if missing.
  @Get('trace-check')
  @UseGuards(TraceIdGuard)
  traceCheck() {
    return {
      message: 'TraceIdGuard: traceId is present',
      traceId: getCurrentTraceId(),
    };
  }

  @Post('trace-check')
  @UseGuards(TraceIdGuard)
  traceCheckPost(@Body() body: Record<string, unknown>) {
    return {
      message: 'TraceIdGuard: traceId is present (POST)',
      traceId: getCurrentTraceId(),
      receivedBody: body,
    };
  }

  // ── Generic param route LAST ────────────────────────────────────────────────
  @Get(':id')
  findOne(@Param('id') id: string): Promise<User> {
    return this.usersService.findOne(id);
  }

  @Post()
  create(@Body() dto: Omit<User, 'id'>): Promise<User> {
    return this.usersService.create(dto);
  }
}
