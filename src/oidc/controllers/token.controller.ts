import { BadRequestException, Body, Controller, Headers, Post, UnauthorizedException } from '@nestjs/common';
import { CodeChallengeMethod } from '@prisma/client';
import { createHash } from 'node:crypto';
import { ClientsService } from '../../clients/clients.service';
import { HashService } from '../../crypto/hash.service';
import { AuthorizationCodeRepository, AuthorizationCodeWithRelations } from '../repositories/authorization-code.repository';
import { OidcTokenService } from '../services/oidc-token.service';
import { TokenRequestDto } from '../dto/token-request.dto';

type ClientWithRelations = NonNullable<Awaited<ReturnType<ClientsService['findByIdWithRelations']>>>;

@Controller('oauth2')
export class TokenController {
  constructor(
    private readonly clientsService: ClientsService,
    private readonly codes: AuthorizationCodeRepository,
    private readonly tokenService: OidcTokenService,
    private readonly hashService: HashService,
  ) {}

  @Post('token')
  async token(@Body() body: TokenRequestDto, @Headers('authorization') authHeader?: string) {
    const { client, clientSecret } = await this.authenticateClient(body, authHeader);

    switch (body.grant_type) {
      case 'authorization_code':
        return this.handleAuthorizationCodeGrant(body, client);
      case 'refresh_token':
        return this.handleRefreshTokenGrant(body, client);
      case 'client_credentials':
        if (!client.isConfidential) {
          throw new UnauthorizedException('unauthorized_client');
        }
        this.assertClientSecret(clientSecret);
        return this.handleClientCredentialsGrant(body, client);
      default:
        throw new BadRequestException('unsupported_grant_type');
    }
  }

  private async handleAuthorizationCodeGrant(body: TokenRequestDto, client: ClientWithRelations) {
    if (!body.code || !body.redirect_uri) {
      throw new BadRequestException('invalid_request');
    }

    const codeHash = this.hashService.hashToken(body.code);
    const authorizationCode = await this.codes.findByCodeHash(codeHash);
    if (!authorizationCode || authorizationCode.clientId !== client.id) {
      throw new BadRequestException('invalid_grant');
    }

    if (authorizationCode.consumedAt || authorizationCode.expiresAt < new Date()) {
      throw new BadRequestException('invalid_grant');
    }

    if (authorizationCode.redirectUri !== body.redirect_uri) {
      throw new BadRequestException('invalid_grant');
    }

    if (authorizationCode.codeChallenge) {
      if (!body.code_verifier) {
        throw new BadRequestException('invalid_grant');
      }

      if (!this.verifyPkce(authorizationCode.codeChallenge, authorizationCode.codeChallengeMethod, body.code_verifier)) {
        throw new BadRequestException('invalid_grant');
      }
    }

    await this.codes.consume(authorizationCode.id);

    return this.tokenService.issueForAuthorizationCode(authorizationCode);
  }

  private async handleRefreshTokenGrant(body: TokenRequestDto, client: ClientWithRelations) {
    if (!body.refresh_token) {
      throw new BadRequestException('invalid_request');
    }

    const tokens = await this.tokenService.issueFromRefreshToken(body.refresh_token, client);
    if (!tokens) {
      throw new BadRequestException('invalid_grant');
    }

    return tokens;
  }

  private async handleClientCredentialsGrant(body: TokenRequestDto, client: ClientWithRelations) {
    const scopes = body.scope
      ? body.scope
          .split(/[\s+]+/)
          .map((scope) => scope.trim())
          .filter(Boolean)
      : client.scopes ?? [];

    const invalidScope = scopes.find((scope) => !client.scopes.includes(scope));
    if (invalidScope) {
      throw new BadRequestException('invalid_scope');
    }

    return this.tokenService.issueForClientCredentials(client, scopes);
  }

  private async authenticateClient(body: TokenRequestDto, authHeader?: string): Promise<{ client: ClientWithRelations; clientSecret?: string }> {
    let clientId = body.client_id;
    let clientSecret = body.client_secret;

    if (authHeader?.startsWith('Basic ')) {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      const [id, secret] = decoded.split(':');
      clientId = id;
      clientSecret = secret;
    }

    if (!clientId) {
      throw new UnauthorizedException('invalid_client');
    }

    const client = await this.clientsService.findByIdWithRelations(clientId);
    if (!client) {
      throw new UnauthorizedException('invalid_client');
    }

    const authenticated = await this.clientsService.verifySecret(client, clientSecret);
    if (!authenticated) {
      throw new UnauthorizedException('invalid_client');
    }

    return { client, clientSecret };
  }

  private verifyPkce(challenge: string, method: CodeChallengeMethod | null, verifier: string): boolean {
    if (!method || method === CodeChallengeMethod.PLAIN) {
      return challenge === verifier;
    }

    const hashed = createHash('sha256').update(verifier).digest('base64url');
    return challenge === hashed;
  }

  private assertClientSecret(secret?: string) {
    if (!secret) {
      throw new UnauthorizedException('invalid_client');
    }
  }
}
