import { Controller, Get } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Controller('.well-known')
export class DiscoveryController {
  constructor(private readonly configService: ConfigService) {}

  @Get('openid-configuration')
  openIdConfiguration() {
    const issuer = this.configService.get<string>('OIDC_ISSUER') ?? 'http://localhost:3000';

    return {
      issuer,
      authorization_endpoint: `${issuer}/oauth2/authorize`,
      token_endpoint: `${issuer}/oauth2/token`,
      userinfo_endpoint: `${issuer}/oauth2/userinfo`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      claims_supported: ['sub', 'email', 'email_verified', 'name', 'preferred_username', 'picture', 'locale'],
    };
  }
}
