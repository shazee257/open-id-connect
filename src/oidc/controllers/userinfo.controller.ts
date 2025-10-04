import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { ClaimsService } from '../services/claims.service';
import { SubjectClaimRepository } from '../repositories/subject-claim.repository';
import { UsersService } from '../../users/users.service';
import { AccessTokenGuard } from '../guards/access-token.guard';

type AuthenticatedRequest = Request & { user?: { sub: string; scope?: string } };

@Controller('oauth2')
export class UserInfoController {
  constructor(
    private readonly usersService: UsersService,
    private readonly claimsService: ClaimsService,
    private readonly subjectClaims: SubjectClaimRepository,
  ) {}

  @Get('userinfo')
  @UseGuards(AccessTokenGuard)
  async getUserInfo(@Req() req: AuthenticatedRequest) {
    const tokenPayload = req.user;
    if (!tokenPayload) {
      return {};
    }

    const user = await this.usersService.findById(tokenPayload.sub);
    if (!user) {
      return {};
    }

    const scopes = tokenPayload.scope?.split(' ') ?? ['openid'];
    const dynamicClaims = await this.subjectClaims.listForUser(user.id);
    const baseClaims = this.claimsService.baseUserClaims(user);
    const merged = { ...baseClaims, ...this.claimsService.mergeDynamicClaims(dynamicClaims) };

    const response: Record<string, unknown> = { sub: user.id };

    if (scopes.includes('email')) {
      response.email = merged.email;
      response.email_verified = merged.email_verified;
    }

    if (scopes.includes('profile')) {
      response.name = merged.name;
      response.preferred_username = merged.preferred_username;
      response.picture = merged.picture;
      response.locale = merged.locale;
    }

    if (scopes.includes('openid')) {
      response.sub = user.id;
    }

    return response;
  }
}
