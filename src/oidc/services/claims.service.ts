import { Injectable } from '@nestjs/common';
import { SubjectClaim, User } from '@prisma/client';

@Injectable()
export class ClaimsService {
  baseUserClaims(user: User): Record<string, unknown> {
    return {
      sub: user.id,
      email: user.email,
      email_verified: user.emailVerified,
      name: user.displayName,
      preferred_username: user.email,
      picture: user.picture,
      locale: user.locale,
    };
  }

  mergeDynamicClaims(subjectClaims: SubjectClaim[]): Record<string, unknown> {
    return subjectClaims.reduce<Record<string, unknown>>((acc, claim) => {
      acc[claim.name] = claim.value;
      return acc;
    }, {});
  }
}
