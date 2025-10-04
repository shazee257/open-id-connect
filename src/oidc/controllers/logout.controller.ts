import { BadRequestException, Body, Controller, Post, Res } from '@nestjs/common';
import type { Response } from 'express';
import { ClientsService } from '../../clients/clients.service';
import { SessionRepository } from '../repositories/session.repository';
import { LogoutRequestDto } from '../dto/logout-request.dto';

@Controller('oauth2')
export class LogoutController {
  constructor(
    private readonly sessions: SessionRepository,
    private readonly clientsService: ClientsService,
  ) {}

  @Post('logout')
  async logout(@Body() body: LogoutRequestDto, @Res() res: Response) {
    if (!body.session_id) {
      throw new BadRequestException('session_id required');
    }

    const session = await this.sessions.findById(body.session_id);
    if (!session) {
      throw new BadRequestException('invalid_session');
    }

    await this.sessions.terminate(session.id);

    if (body.post_logout_redirect_uri) {
      if (!session.clientId) {
        throw new BadRequestException('invalid_request');
      }

      const client = await this.clientsService.findByIdWithRelations(session.clientId);
      if (!client) {
        throw new BadRequestException('invalid_client');
      }

      const isAllowed = client.postLogoutRedirectUris.some((entry) => entry.uri === body.post_logout_redirect_uri);
      if (!isAllowed) {
        throw new BadRequestException('invalid_request');
      }

      const redirectUrl = new URL(body.post_logout_redirect_uri);
      if (body.state) {
        redirectUrl.searchParams.set('state', body.state);
      }

      return res.redirect(redirectUrl.toString());
    }

    return res.json({ success: true });
  }
}
