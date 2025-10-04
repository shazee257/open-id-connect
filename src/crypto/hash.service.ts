import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { createHash, randomBytes } from 'crypto';

@Injectable()
export class HashService {
  hashPassword(plain: string): Promise<string> {
    return argon2.hash(plain, {
      type: argon2.argon2id,
      memoryCost: 2 ** 12,
      timeCost: 3,
      hashLength: 32,
    });
  }

  verifyPassword(hash: string, plain: string): Promise<boolean> {
    return argon2.verify(hash, plain);
  }

  randomToken(byteLength = 32): string {
    return randomBytes(byteLength).toString('base64url');
  }

  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('base64url');
  }
}
