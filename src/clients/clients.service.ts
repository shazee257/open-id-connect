import { Injectable } from '@nestjs/common';
import { OidcClient, Prisma } from '@prisma/client';
import { HashService } from '../crypto/hash.service';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ClientsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly hashService: HashService,
  ) { }

  create(data: Prisma.OidcClientCreateInput): Promise<OidcClient> {
    return this.prisma.oidcClient.create({ data });
  }

  findById(id: string): Promise<OidcClient | null> {
    return this.prisma.oidcClient.findUnique({ where: { id } });
  }

  findByIdWithRelations(id: string) {
    return this.prisma.oidcClient.findUnique({
      where: { id },
      include: {
        redirectUris: true,
        postLogoutRedirectUris: true,
      },
    });
  }

  async verifySecret(client: OidcClient, clientSecret?: string): Promise<boolean> {
    if (!client.isConfidential) {
      return true;
    }

    if (!client.secretHash || !clientSecret) {
      return false;
    }

    return this.hashService.hashToken(clientSecret) === client.secretHash;
  }
}
