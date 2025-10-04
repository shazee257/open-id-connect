import { Injectable } from '@nestjs/common';
import { JsonWebKey as PrismaJsonWebKey, Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export interface CreateJwkParams {
  kid: string;
  publicJwk: Prisma.InputJsonValue;
  privateJwk: Prisma.InputJsonValue;
  algorithm: string;
  use?: string;
  isCurrent?: boolean;
  notBefore?: Date;
  notAfter?: Date | null;
}

@Injectable()
export class JwkRepository {
  constructor(private readonly prisma: PrismaService) {}

  findCurrent(): Promise<PrismaJsonWebKey | null> {
    return this.prisma.jsonWebKey.findFirst({
      where: { isCurrent: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  findByKid(kid: string): Promise<PrismaJsonWebKey | null> {
    return this.prisma.jsonWebKey.findUnique({ where: { kid } });
  }

  listActive(reference?: Date): Promise<PrismaJsonWebKey[]> {
    const now = reference ?? new Date();
    return this.prisma.jsonWebKey.findMany({
      where: {
        notBefore: { lte: now },
        OR: [
          { notAfter: null },
          { notAfter: { gt: now } },
        ],
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async create(params: CreateJwkParams): Promise<PrismaJsonWebKey> {
    if (params.isCurrent) {
      await this.prisma.jsonWebKey.updateMany({
        where: { isCurrent: true },
        data: { isCurrent: false, rotatedAt: new Date() },
      });
    }

    return this.prisma.jsonWebKey.create({
      data: {
        kid: params.kid,
        publicJwk: params.publicJwk,
        privateJwk: params.privateJwk,
        algorithm: params.algorithm,
        use: params.use ?? 'sig',
        isCurrent: params.isCurrent ?? false,
        notBefore: params.notBefore,
        notAfter: params.notAfter,
      },
    });
  }
}
