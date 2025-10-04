import { Injectable } from '@nestjs/common';
import { AuthorizationCode, CodeChallengeMethod, OidcClient, Prisma, User, UserSession } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export interface CreateAuthorizationCodeParams {
  codeHash: string;
  userId: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: CodeChallengeMethod;
  sessionId?: string;
  expiresAt: Date;
}

export type AuthorizationCodeWithRelations = AuthorizationCode & {
  user: User;
  client: OidcClient;
  session: UserSession | null;
};

@Injectable()
export class AuthorizationCodeRepository {
  constructor(private readonly prisma: PrismaService) {}

  create(params: CreateAuthorizationCodeParams): Promise<AuthorizationCode> {
    const data: Prisma.AuthorizationCodeCreateInput = {
      codeHash: params.codeHash,
      expiresAt: params.expiresAt,
      redirectUri: params.redirectUri,
      scopes: params.scopes,
      nonce: params.nonce,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: params.codeChallengeMethod,
      user: { connect: { id: params.userId } },
      client: { connect: { id: params.clientId } },
      session: params.sessionId ? { connect: { id: params.sessionId } } : undefined,
    };

    return this.prisma.authorizationCode.create({ data });
  }

  findByCodeHash(codeHash: string): Promise<AuthorizationCodeWithRelations | null> {
    return this.prisma.authorizationCode.findUnique({
      where: { codeHash },
      include: {
        user: true,
        client: true,
        session: true,
      },
    });
  }

  async consume(id: string): Promise<AuthorizationCode> {
    return this.prisma.authorizationCode.update({
      where: { id },
      data: { consumedAt: new Date() },
    });
  }

  async deleteExpired(now: Date): Promise<number> {
    const result = await this.prisma.authorizationCode.deleteMany({
      where: {
        expiresAt: { lt: now },
      },
    });

    return result.count;
  }
}
