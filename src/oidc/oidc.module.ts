import { Module } from '@nestjs/common';
import { ClientsModule } from '../clients/clients.module';
import { UsersModule } from '../users/users.module';
import { AuthorizationController } from './controllers/authorization.controller';
import { DiscoveryController } from './controllers/discovery.controller';
import { JwksController } from './controllers/jwks.controller';
import { LogoutController } from './controllers/logout.controller';
import { TokenController } from './controllers/token.controller';
import { UserInfoController } from './controllers/userinfo.controller';
import { ClaimsService } from './services/claims.service';
import { OidcTokenService } from './services/oidc-token.service';
import { SigningKeysService } from './services/signing-keys.service';
import { TokenValidatorService } from './services/token-validator.service';
import { AccessTokenGuard } from './guards/access-token.guard';
import { AuthorizationCodeRepository } from './repositories/authorization-code.repository';
import { JwkRepository } from './repositories/jwk.repository';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { SessionRepository } from './repositories/session.repository';
import { SubjectClaimRepository } from './repositories/subject-claim.repository';

@Module({
  imports: [ClientsModule, UsersModule],
  controllers: [
    AuthorizationController,
    TokenController,
    DiscoveryController,
    JwksController,
    UserInfoController,
    LogoutController,
  ],
  providers: [
    AuthorizationCodeRepository,
    RefreshTokenRepository,
    SessionRepository,
    JwkRepository,
    SubjectClaimRepository,
    SigningKeysService,
    ClaimsService,
    OidcTokenService,
    TokenValidatorService,
    AccessTokenGuard,
  ],
  exports: [
    AuthorizationCodeRepository,
    RefreshTokenRepository,
    SessionRepository,
    JwkRepository,
    SubjectClaimRepository,
    SigningKeysService,
    ClaimsService,
    OidcTokenService,
    TokenValidatorService,
    AccessTokenGuard,
  ],
})
export class OidcModule {}
