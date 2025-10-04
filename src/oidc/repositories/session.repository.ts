import { Injectable } from '@nestjs/common';
import { Prisma, UserSession } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export interface CreateSessionParams {
  userId: string;
  clientId?: string;
  scopes: string[];
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class SessionRepository {
  constructor(private readonly prisma: PrismaService) {}

  create(params: CreateSessionParams): Promise<UserSession> {
    const data: Prisma.UserSessionCreateInput = {
      expiresAt: params.expiresAt,
      scopes: params.scopes,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      user: { connect: { id: params.userId } },
      client: params.clientId ? { connect: { id: params.clientId } } : undefined,
    };

    return this.prisma.userSession.create({ data });
  }

  findById(id: string): Promise<UserSession | null> {
    return this.prisma.userSession.findUnique({ where: { id } });
  }

  touch(id: string): Promise<UserSession> {
    return this.prisma.userSession.update({
      where: { id },
      data: { updatedAt: new Date() },
    });
  }

  terminate(id: string, terminatedAt: Date = new Date()): Promise<UserSession> {
    return this.prisma.userSession.update({
      where: { id },
      data: { terminatedAt },
    });
  }
}
