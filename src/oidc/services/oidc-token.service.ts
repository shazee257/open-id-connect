import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  AuthorizationCode,
  JsonWebKey as PrismaJsonWebKey,
  OidcClient,
  SubjectClaim,
  User,
  UserSession,
} from '@prisma/client';
import { addSeconds } from 'date-fns';
import { importJWK, JWK, SignJWT } from 'jose';
import { createHash, randomUUID } from 'node:crypto';
import { HashService } from '../../crypto/hash.service';
import { RefreshTokenRepository } from '../repositories/refresh-token.repository';
import { SessionRepository } from '../repositories/session.repository';
import { SubjectClaimRepository } from '../repositories/subject-claim.repository';
import { ClaimsService } from './claims.service';
import { SigningKeysService } from './signing-keys.service';

type AuthorizationCodeWithRelations = AuthorizationCode & {
  user: User;
  client: OidcClient;
  session?: UserSession | null;
};

type ImportedKey = Awaited<ReturnType<typeof importJWK>>;

export interface TokenResponse {
  token_type: 'Bearer';
  expires_in: number;
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
}

@Injectable()
export class OidcTokenService {
  private readonly issuer: string;
  private readonly accessTtlSeconds: number;
  private readonly refreshTtlSeconds: number;
  private signingKey?: PrismaJsonWebKey;
  private keyLike?: ImportedKey;

  constructor(
    private readonly signingKeys: SigningKeysService,
    private readonly sessions: SessionRepository,
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly claimsService: ClaimsService,
    private readonly subjectClaims: SubjectClaimRepository,
    private readonly hashService: HashService,
    configService: ConfigService,
  ) {
    this.issuer = configService.get<string>('OIDC_ISSUER') ?? 'http://localhost:3000';
    this.accessTtlSeconds = Number(configService.get('JWT_ACCESS_TTL') ?? 300);
    this.refreshTtlSeconds = Number(configService.get('JWT_REFRESH_TTL') ?? 60 * 60 * 24 * 14);
  }

  async issueForAuthorizationCode(authCode: AuthorizationCodeWithRelations): Promise<TokenResponse> {
    const { user, client } = authCode;
    const session = await this.ensureSession(authCode, client, user);
    const scopes = authCode.scopes ?? ['openid'];

    const key = await this.ensureKey();
    const accessToken = await this.createAccessToken(key, client, user, session, scopes);

    let idToken: string | undefined;
    if (scopes.includes('openid')) {
      idToken = await this.createIdToken(key, client, user, session, scopes, authCode.nonce ?? undefined, accessToken);
    }

    const refreshTokenPlain = await this.createRefreshToken(user, client, session, scopes);

    return {
      token_type: 'Bearer',
      expires_in: this.accessTtlSeconds,
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshTokenPlain,
      scope: scopes.join(' '),
    };
  }

  async issueForClientCredentials(client: OidcClient, scopes: string[]): Promise<TokenResponse> {
    const key = await this.ensureKey();

    const payload = {
      iss: this.issuer,
      sub: client.id,
      aud: client.id,
      scope: scopes.join(' '),
      client_id: client.id,
      jti: randomUUID(),
    };

    const access = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setAudience(client.id)
      .setExpirationTime(`${this.accessTtlSeconds}s`)
      .sign(await this.getKeyLike(key));

    return {
      token_type: 'Bearer',
      expires_in: this.accessTtlSeconds,
      access_token: access,
      scope: scopes.join(' '),
    };
  }

  async issueFromRefreshToken(refreshToken: string, client: OidcClient): Promise<TokenResponse | null> {
    const tokenHash = this.hashService.hashToken(refreshToken);
    const existing = await this.refreshTokens.findByHash(tokenHash);
    if (!existing || existing.revokedAt || existing.clientId !== client.id) {
      return null;
    }

    if (existing.expiresAt < new Date()) {
      return null;
    }

    const user = existing.user;
    if (!user) {
      return null;
    }

    const session = existing.sessionId ? await this.sessions.findById(existing.sessionId) : null;
    if (!session || (session.expiresAt && session.expiresAt < new Date())) {
      return null;
    }

    const scopes = existing.scopes ?? ['openid'];
    const key = await this.ensureKey();
    const accessToken = await this.createAccessToken(key, client, user, session, scopes);

    let idToken: string | undefined;
    if (scopes.includes('openid')) {
      idToken = await this.createIdToken(key, client, user, session, scopes, undefined, accessToken);
    }

    const refreshTokenPlain = await this.createRefreshToken(user, client, session, scopes);

    await this.refreshTokens.revoke(existing.id, new Date());

    return {
      token_type: 'Bearer',
      expires_in: this.accessTtlSeconds,
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshTokenPlain,
      scope: scopes.join(' '),
    };
  }

  private async ensureKey(): Promise<PrismaJsonWebKey> {
    const now = new Date();
    if (!this.signingKey || (this.signingKey.notAfter && this.signingKey.notAfter <= now)) {
      this.signingKey = await this.signingKeys.currentKey();
      this.keyLike = undefined;
    }
    return this.signingKey;
  }

  private async getKeyLike(key: PrismaJsonWebKey): Promise<ImportedKey> {
    if (!this.keyLike || this.signingKey?.id !== key.id) {
      this.keyLike = await importJWK(key.privateJwk as JWK, key.algorithm);
    }
    return this.keyLike;
  }

  private async ensureSession(
    authCode: AuthorizationCodeWithRelations,
    client: OidcClient,
    user: User,
  ): Promise<UserSession> {
    if (authCode.sessionId) {
      const session = await this.sessions.findById(authCode.sessionId);
      if (session) {
        return session;
      }
    }

    const expiresAt = addSeconds(new Date(), this.refreshTtlSeconds);
    return this.sessions.create({
      userId: user.id,
      clientId: client.id,
      scopes: authCode.scopes ?? ['openid'],
      expiresAt,
    });
  }

  private async createAccessToken(
    key: PrismaJsonWebKey,
    client: OidcClient,
    user: User,
    session: UserSession,
    scopes: string[],
  ): Promise<string> {
    const payload = {
      sub: user.id,
      aud: client.id,
      scope: scopes.join(' '),
      client_id: client.id,
      sid: session.id,
      jti: randomUUID(),
    };

    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setAudience(client.id)
      .setExpirationTime(`${this.accessTtlSeconds}s`)
      .sign(await this.getKeyLike(key));
  }

  private async createIdToken(
    key: PrismaJsonWebKey,
    client: OidcClient,
    user: User,
    session: UserSession,
    scopes: string[],
    nonce: string | undefined,
    accessToken: string,
  ): Promise<string> {
    const userClaims = this.claimsService.baseUserClaims(user);
    const dynamicClaims: SubjectClaim[] = await this.subjectClaims.listForUser(user.id);
    const mergedDynamic = this.claimsService.mergeDynamicClaims(dynamicClaims);

    const payload = {
      ...userClaims,
      ...mergedDynamic,
      aud: client.id,
      iss: this.issuer,
      sid: session.id,
      auth_time: Math.floor(session.createdAt.getTime() / 1000),
      nonce,
      at_hash: this.computeAtHash(accessToken),
      scope: scopes.join(' '),
    };

    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setAudience(client.id)
      .setExpirationTime(`${this.accessTtlSeconds}s`)
      .sign(await this.getKeyLike(key));
  }

  private computeAtHash(accessToken: string): string {
    const digest = createHash('sha256').update(accessToken).digest();
    const half = digest.slice(0, digest.length / 2);
    return Buffer.from(half).toString('base64url');
  }

  private async createRefreshToken(
    user: User,
    client: OidcClient,
    session: UserSession,
    scopes: string[],
  ): Promise<string> {
    const now = new Date();
    const refreshToken = this.hashService.randomToken(48);
    const tokenHash = this.hashService.hashToken(refreshToken);
    const expiresAt = addSeconds(now, this.refreshTtlSeconds);

    await this.refreshTokens.create({
      tokenHash,
      userId: user.id,
      clientId: client.id,
      sessionId: session.id,
      scopes,
      expiresAt,
    });

    return refreshToken;
  }
}
