import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UserStatus } from '@prisma/client';
import { addSeconds } from 'date-fns';
import { HashService } from '../crypto/hash.service';
import { SessionRepository } from '../oidc/repositories/session.repository';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  private readonly sessionTtlSeconds: number;

  constructor(
    private readonly usersService: UsersService,
    private readonly hashService: HashService,
    private readonly sessions: SessionRepository,
    configService: ConfigService,
  ) {
    this.sessionTtlSeconds = Number(configService.get('SESSION_TTL') ?? 3600);
  }

  async register(dto: RegisterDto) {
    const existing = await this.usersService.findByEmail(dto.email);
    if (existing) {
      throw new BadRequestException('Email already registered');
    }

    const passwordHash = await this.hashService.hashPassword(dto.password);

    return this.usersService.create({
      email: dto.email.toLowerCase(),
      passwordHash,
      displayName: dto.displayName,
    });
  }

  async login(dto: LoginDto) {
    const user = await this.usersService.findByEmail(dto.email.toLowerCase());
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException('User is not active');
    }

    const passwordMatches = await this.hashService.verifyPassword(user.passwordHash, dto.password);
    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const scopes = dto.scope
      ? dto.scope
        .split(/[\s+]+/)  // Split by spaces, plus signs, and newlines
        .map((scope) => scope.trim())
        .filter(Boolean)
      : ['openid'];

    const expiresAt = addSeconds(new Date(), this.sessionTtlSeconds); // 3600 seconds = 1 hour

    const session = await this.sessions.create({
      userId: user.id,
      clientId: dto.client_id,
      scopes,
      expiresAt,
      ipAddress: dto.ip_address,
      userAgent: dto.user_agent,
    });

    return { user, session };
  }
}
