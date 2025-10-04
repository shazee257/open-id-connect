import { Controller, Get } from '@nestjs/common';
import { SigningKeysService } from '../services/signing-keys.service';

@Controller('.well-known')
export class JwksController {
  constructor(private readonly signingKeys: SigningKeysService) {}

  @Get('jwks.json')
  async jwks() {
    return this.signingKeys.jwks();
  }
}
