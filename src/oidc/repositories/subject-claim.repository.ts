import { Injectable } from '@nestjs/common';
import { Prisma, SubjectClaim } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class SubjectClaimRepository {
  constructor(private readonly prisma: PrismaService) {}

  upsert(userId: string, name: string, value: string, source?: string): Promise<SubjectClaim> {
    return this.prisma.subjectClaim.upsert({
      where: {
        userId_name: { userId, name },
      },
      update: {
        value,
        source,
      },
      create: {
        value,
        source,
        name,
        user: { connect: { id: userId } },
      },
    });
  }

  listForUser(userId: string): Promise<SubjectClaim[]> {
    return this.prisma.subjectClaim.findMany({
      where: { userId },
    });
  }
}
