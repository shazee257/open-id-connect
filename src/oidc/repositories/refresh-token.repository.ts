import { Injectable } from '@nestjs/common';
import { Prisma, RefreshToken } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export interface CreateRefreshTokenParams {
  tokenHash: string;
  userId: string;
  clientId: string;
  sessionId?: string;
  scopes: string[];
  expiresAt: Date;
}

@Injectable()
export class RefreshTokenRepository {
  constructor(private readonly prisma: PrismaService) {}

  create(params: CreateRefreshTokenParams): Promise<RefreshToken> {
    const data: Prisma.RefreshTokenCreateInput = {
      tokenHash: params.tokenHash,
      expiresAt: params.expiresAt,
      scopes: params.scopes,
      user: { connect: { id: params.userId } },
      client: { connect: { id: params.clientId } },
      session: params.sessionId ? { connect: { id: params.sessionId } } : undefined,
    };

    return this.prisma.refreshToken.create({ data });
  }

  findByHash(tokenHash: string) {
    return this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: {
        user: true,
        client: true,
        session: true,
      },
    });
  }

  revoke(id: string, revokedAt: Date = new Date()) {
    return this.prisma.refreshToken.update({
      where: { id },
      data: { revokedAt },
    });
  }

  deleteExpired(now: Date) {
    return this.prisma.refreshToken.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: now } },
          { revokedAt: { lt: now } },
        ],
      },
    });
  }
}
