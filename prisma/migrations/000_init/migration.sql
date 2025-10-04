-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('ACTIVE', 'LOCKED', 'DISABLED');

-- CreateEnum
CREATE TYPE "GrantType" AS ENUM ('AUTHORIZATION_CODE', 'CLIENT_CREDENTIALS', 'REFRESH_TOKEN');

-- CreateEnum
CREATE TYPE "ResponseType" AS ENUM ('CODE', 'TOKEN', 'ID_TOKEN');

-- CreateEnum
CREATE TYPE "CodeChallengeMethod" AS ENUM ('PLAIN', 'S256');

-- CreateEnum
CREATE TYPE "TokenType" AS ENUM ('AUTHORIZATION_CODE', 'ACCESS_TOKEN', 'REFRESH_TOKEN');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "displayName" TEXT,
    "passwordHash" TEXT NOT NULL,
    "status" "UserStatus" NOT NULL DEFAULT 'ACTIVE',
    "picture" TEXT,
    "locale" VARCHAR(12),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OidcClient" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "secretHash" TEXT,
    "isConfidential" BOOLEAN NOT NULL DEFAULT true,
    "grantTypes" "GrantType"[] DEFAULT ARRAY['AUTHORIZATION_CODE', 'REFRESH_TOKEN']::"GrantType"[],
    "responseTypes" "ResponseType"[] DEFAULT ARRAY['CODE']::"ResponseType"[],
    "scopes" TEXT[] DEFAULT ARRAY['openid']::TEXT[],
    "tokenEndpointAuthMethod" TEXT NOT NULL DEFAULT 'client_secret_basic',
    "requireProofKey" BOOLEAN NOT NULL DEFAULT true,
    "requireConsent" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OidcClient_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClientRedirectUri" (
    "id" SERIAL NOT NULL,
    "uri" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,

    CONSTRAINT "ClientRedirectUri_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClientPostLogoutUri" (
    "id" SERIAL NOT NULL,
    "uri" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,

    CONSTRAINT "ClientPostLogoutUri_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthorizationCode" (
    "id" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "sessionId" TEXT,
    "redirectUri" TEXT NOT NULL,
    "scopes" TEXT[] DEFAULT ARRAY['openid']::TEXT[],
    "nonce" TEXT,
    "codeChallenge" TEXT,
    "codeChallengeMethod" "CodeChallengeMethod",
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthorizationCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RefreshToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scopes" TEXT[] DEFAULT ARRAY['openid']::TEXT[],
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "sessionId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "scopes" TEXT[] DEFAULT ARRAY['openid']::TEXT[],
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "terminatedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "JsonWebKey" (
    "id" TEXT NOT NULL,
    "kid" TEXT NOT NULL,
    "publicJwk" JSONB NOT NULL,
    "privateJwk" JSONB NOT NULL,
    "algorithm" TEXT NOT NULL,
    "use" TEXT NOT NULL DEFAULT 'sig',
    "isCurrent" BOOLEAN NOT NULL DEFAULT false,
    "notBefore" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "notAfter" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotatedAt" TIMESTAMP(3),

    CONSTRAINT "JsonWebKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SubjectClaim" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "source" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SubjectClaim_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "OidcClient_name_idx" ON "OidcClient"("name");

-- CreateIndex
CREATE UNIQUE INDEX "ClientRedirectUri_clientId_uri_key" ON "ClientRedirectUri"("clientId", "uri");

-- CreateIndex
CREATE UNIQUE INDEX "ClientPostLogoutUri_clientId_uri_key" ON "ClientPostLogoutUri"("clientId", "uri");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizationCode_codeHash_key" ON "AuthorizationCode"("codeHash");

-- CreateIndex
CREATE UNIQUE INDEX "RefreshToken_tokenHash_key" ON "RefreshToken"("tokenHash");

-- CreateIndex
CREATE INDEX "RefreshToken_userId_clientId_idx" ON "RefreshToken"("userId", "clientId");

-- CreateIndex
CREATE UNIQUE INDEX "JsonWebKey_kid_key" ON "JsonWebKey"("kid");

-- CreateIndex
CREATE UNIQUE INDEX "SubjectClaim_userId_name_key" ON "SubjectClaim"("userId", "name");

-- AddForeignKey
ALTER TABLE "ClientRedirectUri" ADD CONSTRAINT "ClientRedirectUri_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OidcClient"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClientPostLogoutUri" ADD CONSTRAINT "ClientPostLogoutUri_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OidcClient"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationCode" ADD CONSTRAINT "AuthorizationCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationCode" ADD CONSTRAINT "AuthorizationCode_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OidcClient"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationCode" ADD CONSTRAINT "AuthorizationCode_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "UserSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OidcClient"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "UserSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserSession" ADD CONSTRAINT "UserSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserSession" ADD CONSTRAINT "UserSession_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OidcClient"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SubjectClaim" ADD CONSTRAINT "SubjectClaim_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

