import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Prisma } from '@prisma/client';
import { JsonWebKey as PrismaJsonWebKey } from '@prisma/client';
import { addDays } from 'date-fns';
import { exportJWK, generateKeyPair, JWK } from 'jose';
import { randomUUID } from 'node:crypto';
import { JwkRepository } from '../repositories/jwk.repository';

@Injectable()
export class SigningKeysService {
  private readonly rotationDays: number;

  constructor(
    private readonly repo: JwkRepository,
    configService: ConfigService,
  ) {
    this.rotationDays = Number(configService.get('JWK_ROTATION_DAYS') ?? 30);
  }

  async currentKey(): Promise<PrismaJsonWebKey> {
    const now = new Date();
    const existing = await this.repo.findCurrent();
    if (existing && (!existing.notAfter || existing.notAfter > now)) {
      return existing;
    }

    return this.rotate();
  }

  async rotate(): Promise<PrismaJsonWebKey> {
    const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    const kid = randomUUID();

    const notBefore = new Date();
    const notAfter = this.rotationDays > 0 ? addDays(notBefore, this.rotationDays) : null;

    const jwkPublic: JWK = { ...publicJwk, kid, use: 'sig', alg: 'RS256' };
    const jwkPrivate: JWK = { ...privateJwk, kid, use: 'sig', alg: 'RS256' };
    const jwkPublicJson = jwkPublic as unknown as Prisma.JsonObject;
    const jwkPrivateJson = jwkPrivate as unknown as Prisma.JsonObject;

    return this.repo.create({
      kid,
      publicJwk: jwkPublicJson,
      privateJwk: jwkPrivateJson,
      algorithm: 'RS256',
      use: 'sig',
      isCurrent: true,
      notBefore,
      notAfter,
    });
  }

  async jwks(): Promise<{ keys: JWK[] }> {
    const keys = await this.repo.listActive();
    return {
      keys: keys.map((entry) => ({
        ...(entry.publicJwk as JWK),
        kid: entry.kid,
        use: entry.use ?? 'sig',
        alg: entry.algorithm,
      })),
    };
  }
}
