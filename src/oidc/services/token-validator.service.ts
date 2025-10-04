import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JsonWebKey as PrismaJsonWebKey } from '@prisma/client';
import { decodeProtectedHeader, importJWK, JWK, JWTPayload, jwtVerify } from 'jose';
import { JwkRepository } from '../repositories/jwk.repository';

@Injectable()
export class TokenValidatorService {
  private readonly issuer: string;

  constructor(
    private readonly repo: JwkRepository,
    configService: ConfigService,
  ) {
    this.issuer = configService.get<string>('OIDC_ISSUER') ?? 'http://localhost:3000';
  }

  async verifyAccessToken(token: string): Promise<JWTPayload> {
    try {
      const { kid } = decodeProtectedHeader(token);
      if (!kid) {
        throw new UnauthorizedException('invalid_token');
      }

      const jwk = await this.ensureKey(kid);
      const keyLike = await importJWK(jwk.publicJwk as JWK, jwk.algorithm);

      const { payload } = await jwtVerify(token, keyLike, {
        issuer: this.issuer,
      });

      return payload;
    } catch (error) {
      throw new UnauthorizedException('invalid_token');
    }
  }

  private async ensureKey(kid: string): Promise<PrismaJsonWebKey> {
    const existing = await this.repo.findByKid(kid);
    if (!existing) {
      throw new UnauthorizedException('invalid_token');
    }

    return existing;
  }
}
