import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { TokenValidatorService } from '../services/token-validator.service';

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly tokenValidator: TokenValidatorService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: unknown }>();
    const token = this.extractToken(request);
    if (!token) {
      throw new UnauthorizedException('invalid_token');
    }

    const payload = await this.tokenValidator.verifyAccessToken(token);
    request.user = payload;
    return true;
  }

  private extractToken(request: Request): string | null {
    const auth = request.headers['authorization'];
    if (!auth) {
      return null;
    }

    const [scheme, token] = auth.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) {
      return null;
    }

    return token;
  }
}
