import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { LogMethod } from '../../../../src/core/nestjs-extras';
import { RequestContextManager, createHttpRequest } from '../../../../src/core/request-context';
import { LogixiaException } from '../../../../src/exceptions/exception';

export interface User {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user';
}

const DB: User[] = [
  { id: 'u_001', name: 'Sanjeev Sharma', email: 'sanjeev@example.com', role: 'admin' },
  { id: 'u_002', name: 'Priya Kapoor',   email: 'priya@example.com',   role: 'user'  },
];

@Injectable()
export class UsersService {
  // child logger scoped to this service
  private readonly log: LogixiaLoggerService;

  constructor(private readonly logger: LogixiaLoggerService) {
    // child() creates a logger whose [context] is always 'UsersService'
    this.log = this.logger.child('UsersService');
  }

  @LogMethod({ level: 'debug', logArgs: false })
  async findAll(): Promise<User[]> {
    // RequestContextManager — track this "operation" for stats
    const reqCtx = RequestContextManager.createContext(
      createHttpRequest('GET', '/users', {})
    );

    await this.log.info('Fetching all users', { count: DB.length });

    RequestContextManager.updateContext(reqCtx.requestId, { statusCode: 200, headers: {}, timestamp: Date.now() });
    return DB;
  }

  @LogMethod({ level: 'debug', logArgs: true })
  async findOne(id: string): Promise<User> {
    const user = DB.find((u) => u.id === id);
    if (!user) {
      // typed LogixiaException → ExceptionFilter logs WARN
      throw new LogixiaException({
        code:       'USR-001',
        type:       'not_found',
        httpStatus: 404,
        message:    `User '${id}' not found.`,
        param:      'id',
        metadata:   { attemptedId: id },
      });
    }

    // child logger with extra bound data
    const userLog = this.log.child('UsersService.findOne', { userId: id });
    await userLog.debug('User record fetched', { role: user.role });
    return user;
  }

  @LogMethod({ level: 'debug', logArgs: false })
  async create(dto: Omit<User, 'id'>): Promise<User> {
    const existing = DB.find((u) => u.email === dto.email);
    if (existing) {
      throw new LogixiaException({
        code:       'USR-002',
        type:       'conflict_error',
        httpStatus: 409,
        message:    'Email already registered.',
        param:      'email',
      });
    }

    // timing a "DB write"
    const user = await this.log.timeAsync<User>('db:users.insert', async () => {
      await new Promise<void>((r) => setTimeout(r, 20)); // simulate latency
      const newUser: User = { id: `u_${Date.now()}`, ...dto };
      DB.push(newUser);
      return newUser;
    });

    await this.log.info('User created', { userId: user.id, email: user.email, role: user.role });
    return user;
  }

  /** Used by the health endpoint to expose RequestContextManager stats */
  getContextStats() {
    return RequestContextManager.getStats();
  }
}
