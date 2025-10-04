// prisma/seed.ts
import { PrismaClient, GrantType, ResponseType } from '@prisma/client';
import { randomBytes, createHash } from 'node:crypto';

const prisma = new PrismaClient();

function secretPair() {
    const secret = randomBytes(32).toString('base64url');
    const secretHash = createHash('sha256').update(secret).digest('base64url');
    return { secret, secretHash };
}

async function main() {
    const web = secretPair();
    const service = secretPair();

    await prisma.oidcClient.upsert({
        where: { id: 'app-web' },
        update: {},
        create: {
            id: 'app-web',
            name: 'Sample Web Client',
            secretHash: web.secretHash,
            redirectUris: { create: [{ uri: 'http://localhost:3001/callback' }] },
            postLogoutRedirectUris: { create: [{ uri: 'http://localhost:3001/logout-complete' }] },
            grantTypes: [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
            responseTypes: [ResponseType.CODE],
            scopes: ['openid', 'profile', 'email'],
            tokenEndpointAuthMethod: 'client_secret_basic',
            requireProofKey: true,
            requireConsent: false,
        },
    });

    await prisma.oidcClient.upsert({
        where: { id: 'service-api' },
        update: {},
        create: {
            id: 'service-api',
            name: 'Service-to-Service Client',
            secretHash: service.secretHash,
            grantTypes: [GrantType.CLIENT_CREDENTIALS],
            responseTypes: [ResponseType.CODE],
            scopes: ['openid', 'api:read'],
            tokenEndpointAuthMethod: 'client_secret_basic',
            requireProofKey: false,
            isConfidential: true,
        },
    });

    console.info('app-web secret:', web.secret);
    console.info('service-api secret:', service.secret);
}

main()
    .catch((err) => {
        console.error(err);
        process.exit(1);
    })
    .finally(async () => prisma.$disconnect());
