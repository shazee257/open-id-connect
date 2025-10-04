import { BadRequestException, Controller, Get, Query, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CodeChallengeMethod } from '@prisma/client';
import type { Response } from 'express';
import { addSeconds } from 'date-fns';
import { HashService } from '../../crypto/hash.service';
import { ClientsService } from '../../clients/clients.service';
import { UsersService } from '../../users/users.service';
import { AuthorizationCodeRepository } from '../repositories/authorization-code.repository';
import { SessionRepository } from '../repositories/session.repository';
import { AuthorizationRequestDto } from '../dto/authorization-request.dto';

@Controller('oauth2')
export class AuthorizationController {
  private readonly authCodeTtl: number;

  constructor(
    private readonly clientsService: ClientsService,
    private readonly usersService: UsersService,
    private readonly sessions: SessionRepository,
    private readonly codes: AuthorizationCodeRepository,
    private readonly hashService: HashService,
    configService: ConfigService,
  ) {
    this.authCodeTtl = Number(configService.get('AUTH_CODE_TTL') ?? 300);
  }

  @Get('authorize')
  async authorize(@Query() query: AuthorizationRequestDto, @Res() res: Response) {
    const client = await this.clientsService.findByIdWithRelations(query.client_id);
    if (!client) {
      throw new BadRequestException('invalid_client');
    }

    if (!query.redirect_uri) {
      throw new BadRequestException('invalid_request');
    }

    const isRedirectAllowed = client.redirectUris.some((entry) => entry.uri == query.redirect_uri);
    if (!isRedirectAllowed) {
      throw new BadRequestException('invalid_redirect_uri');
    }

    const scopes = query.scope.length ? query.scope : ['openid'];
    const unsupportedScope = scopes.find((scope) => !client.scopes.includes(scope));
    if (unsupportedScope) {
      throw new BadRequestException('invalid_scope');
    }

    if (client.requireProofKey && !query.code_challenge) {
      throw new BadRequestException('invalid_request');
    }

    if (!query.session_id) {
      throw new BadRequestException('login_required');
    }

    const session = await this.sessions.findById(query.session_id);
    if (!session || session.expiresAt < new Date() || session.userId === undefined) {
      throw new BadRequestException('login_required');
    }

    const user = await this.usersService.findById(session.userId);
    if (!user) {
      throw new BadRequestException('login_required');
    }

    if (client.requireProofKey && query.code_challenge_method && !['S256', 'plain', 's256'].includes(query.code_challenge_method)) {
      throw new BadRequestException('invalid_request');
    }

    const code = this.hashService.randomToken(32);
    const codeHash = this.hashService.hashToken(code);

    const expiresAt = addSeconds(new Date(), this.authCodeTtl);

    await this.codes.create({
      codeHash,
      clientId: client.id,
      userId: user.id,
      sessionId: session.id,
      redirectUri: query.redirect_uri,
      scopes,
      nonce: query.nonce,
      codeChallenge: query.code_challenge,
      codeChallengeMethod: query.code_challenge_method
        ? query.code_challenge_method.toUpperCase() === 'S256'
          ? CodeChallengeMethod.S256
          : CodeChallengeMethod.PLAIN
        : undefined,
      expiresAt,
    });

    const redirectUrl = new URL(query.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (query.state) {
      redirectUrl.searchParams.set('state', query.state);
    }

    return res.redirect(redirectUrl.toString());
  }
}
